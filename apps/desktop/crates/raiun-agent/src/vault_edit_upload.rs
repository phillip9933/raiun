//! Historical upload-attempt ledger; network worker remains unwired. No network, crypto, live session,
//! native acknowledgement or clean-state authority is implemented here.
//! The Store must authenticate this logical subdomain and exact locator/full bytes.
use super::{
    vault_custody::{CaptureRef, Entry, Scope},
    vault_edit_capture::{self as capture, CaptureId},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use zeroize::Zeroizing;

const VERSION: u32 = 1;
pub(crate) const MAX_RECORD_BYTES: usize = 128 * 1024;
const DOMAIN: &[u8] = b"raiun-vault-existing-edit-upload-attempt-v1\0";
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Invalid,
    Foreign,
    Missing,
    Conflict,
    Persistence,
}
type Result<T> = std::result::Result<T, Error>;

/// Protected logical subrecord; serialize cross-process full-byte CAS and
/// acknowledge only durable exact readback. Errors may follow publication.
/// A strict versioned custody-child subrecord may reuse its existing protected
/// whole-child CAS; never put these mutable records in the immutable capture body.
/// Missing loads create nothing. The Windows custody adapter stores this logical
/// record inside the existing protected whole-child CAS domain.
pub(crate) trait Store {
    fn load(&self, locator: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn compare_exchange(&self, locator: &[u8], old: Option<&[u8]>, next: &[u8]) -> Result<()>;
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    scope: Scope,
    capture: CaptureRef,
    original: Entry,
    body_len: usize,
    body_sha256: [u8; 32],
}
impl Binding {
    fn validate(&self) -> Result<()> {
        self.scope
            .authenticated_store_binding()
            .map_err(|_| Error::Invalid)?;
        CaptureId::new(self.capture.id()).map_err(|_| Error::Invalid)?;
        self.capture
            .frame()
            .validate()
            .map_err(|_| Error::Invalid)?;
        let entry = &self.original;
        let validated = Entry::new(
            entry.opaque(),
            entry.remote_id(),
            entry.root_relative_path(),
            entry.etag(),
            entry.is_directory(),
            entry.length(),
        )
        .map_err(|_| Error::Invalid)?;
        if &validated != entry
            || self.capture.entry() != entry
            || entry.is_directory()
            || entry.root_relative_path() == "/"
            || !capture::strong_etag(entry.etag())
            || self.body_len > capture::MAX_BODY_BYTES
            || self.body_sha256 == [0; 32]
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn from_capture(
        body_store: &impl capture::Store,
        scope: &Scope,
        reference: &CaptureRef,
        original: &Entry,
    ) -> Result<Self> {
        let id = CaptureId::new(reference.id()).map_err(|_| Error::Invalid)?;
        let retained =
            capture::reopen_for_recovery(body_store, scope, &id).map_err(|error| match error {
                capture::Error::Missing => Error::Missing,
                capture::Error::Persistence => Error::Persistence,
                capture::Error::Foreign => Error::Foreign,
                _ => Error::Invalid,
            })?;
        if retained.encoded_frame_ref() != reference.frame() {
            return Err(Error::Foreign);
        }
        let binding = Self {
            scope: scope.clone(),
            capture: reference.clone(),
            original: original.clone(),
            body_len: retained.bytes_for_recovery().len(),
            body_sha256: Sha256::digest(retained.bytes_for_recovery()).into(),
        };
        binding.validate()?;
        Ok(binding)
    }
    fn locator(&self) -> Result<Vec<u8>> {
        locator(&self.scope, &self.capture)
    }
}
/// Fixed logical locator for a trusted immutable protected capture reference.
/// It is never account/root, live epoch or dispatch authority.
pub(crate) fn locator(scope: &Scope, reference: &CaptureRef) -> Result<Vec<u8>> {
    let scope = scope
        .authenticated_store_binding()
        .map_err(|_| Error::Invalid)?;
    CaptureId::new(reference.id()).map_err(|_| Error::Invalid)?;
    let mut hash = Sha256::new();
    hash.update((scope.len() as u64).to_le_bytes());
    hash.update(scope.as_slice());
    hash.update((reference.id().len() as u64).to_le_bytes());
    hash.update(reference.id().as_bytes());
    let mut key = DOMAIN.to_vec();
    key.extend_from_slice(&hash.finalize());
    Ok(key)
}

/// Historical assertion supplied by a future authenticated network adapter.
/// This model checks consistency, not TLS/server authentication or live leases.
/// It never turns this record into upload, native cleanup or acknowledgement authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HistoricalReadbackEvidence {
    resource_id: String,
    etag: String,
    body_len: usize,
    body_sha256: [u8; 32],
}
impl HistoricalReadbackEvidence {
    pub(crate) fn resource_id(&self) -> &str {
        &self.resource_id
    }
    pub(crate) fn etag(&self) -> &str {
        &self.etag
    }
    pub(crate) fn body_len(&self) -> usize {
        self.body_len
    }
    pub(crate) fn body_sha256(&self) -> [u8; 32] {
        self.body_sha256
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum State {
    NeverAttempted {},
    Attempting {},
    Uncertain {},
    Conflict {},
    ReadbackRecorded {
        evidence: HistoricalReadbackEvidence,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    revision: u64,
    binding: Binding,
    state: State,
}
impl Document {
    fn validate(&self, expected: &Binding) -> Result<()> {
        if self.version != VERSION || self.revision == 0 {
            return Err(Error::Invalid);
        }
        self.binding.validate()?;
        if &self.binding != expected {
            return Err(Error::Foreign);
        }
        if let State::ReadbackRecorded { evidence } = &self.state {
            validate_evidence(&self.binding, evidence)?;
        }
        Ok(())
    }
}
fn validate_evidence(binding: &Binding, evidence: &HistoricalReadbackEvidence) -> Result<()> {
    if evidence.resource_id != binding.original.remote_id()
        || !capture::strong_etag(&evidence.etag)
        || evidence.etag == binding.original.etag()
        || evidence.body_len != binding.body_len
        || evidence.body_sha256 != binding.body_sha256
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
struct Bounded(Zeroizing<Vec<u8>>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_RECORD_BYTES - self.0.len() {
            return Err(io::Error::other("upload attempt bounds"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode(document: &Document) -> Result<Zeroizing<Vec<u8>>> {
    let mut buffer = Bounded(Zeroizing::new(Vec::new()));
    serde_json::to_writer(&mut buffer, document).map_err(|_| Error::Invalid)?;
    Ok(buffer.0)
}
fn decode(raw: &[u8], expected: &Binding) -> Result<Document> {
    if raw.is_empty() || raw.len() > MAX_RECORD_BYTES {
        return Err(Error::Invalid);
    }
    let document: Document = serde_json::from_slice(raw).map_err(|_| Error::Invalid)?;
    document.validate(expected)?;
    Ok(document)
}
/// Validate only authenticated custody subrecord bytes against an existing
/// protected immutable reference. This checks format/binding, never network auth.
pub(crate) fn validate_bound_record(
    raw: &[u8],
    scope: &Scope,
    reference: &CaptureRef,
) -> Result<()> {
    let document = decode_bound_record(raw, scope, reference)?;
    document.validate(&document.binding)
}
fn decode_bound_record(raw: &[u8], scope: &Scope, reference: &CaptureRef) -> Result<Document> {
    if raw.is_empty() || raw.len() > MAX_RECORD_BYTES {
        return Err(Error::Invalid);
    }
    let document: Document = serde_json::from_slice(raw).map_err(|_| Error::Invalid)?;
    document.validate(&document.binding)?;
    if &document.binding.scope != scope
        || &document.binding.capture != reference
        || &document.binding.original != reference.entry()
    {
        return Err(Error::Foreign);
    }
    Ok(document)
}
/// Historical evidence through the existing exact bound parser; no authority.
pub(crate) fn bound_readback_evidence(
    raw: &[u8],
    scope: &Scope,
    reference: &CaptureRef,
) -> Result<Option<HistoricalReadbackEvidence>> {
    let document = decode_bound_record(raw, scope, reference)?;
    Ok(match document.state {
        State::ReadbackRecorded { evidence } => Some(evidence),
        _ => None,
    })
}
/// The protected adapter independently refuses reset/replay even if a future
/// caller supplies serialized bytes directly instead of using this model.
pub(crate) fn validate_transition(
    old: Option<&[u8]>,
    next: &[u8],
    scope: &Scope,
    reference: &CaptureRef,
) -> Result<()> {
    let next = decode_bound_record(next, scope, reference)?;
    match old {
        None if next.revision == 1 && next.state == (State::NeverAttempted {}) => Ok(()),
        Some(raw) => {
            let old = decode_bound_record(raw, scope, reference)?;
            if next.revision != old.revision.checked_add(1).ok_or(Error::Invalid)?
                || next.binding != old.binding
            {
                return Err(Error::Conflict);
            }
            match (&old.state, &next.state) {
                (State::NeverAttempted {}, State::Attempting {})
                | (
                    State::Attempting {},
                    State::Uncertain {} | State::Conflict {} | State::ReadbackRecorded { .. },
                ) => Ok(()),
                _ => Err(Error::Conflict),
            }
        }
        None => Err(Error::Conflict),
    }
}

/// Bounded historical reference listing under an existing trusted root member.
/// Missing/incomplete documents are errors, never an empty clean-history claim.
#[cfg(test)]
pub(crate) fn load_capture_references<
    S: super::root_manifest::Store + super::vault_custody::Store,
>(
    store: &S,
    root: &super::root_manifest::RootBinding,
    scope: &Scope,
) -> Result<Vec<CaptureRef>> {
    let (mut manifest, child) = reopen_member(store, root, scope)?;
    let references = child
        .capture_references_for_lookup()
        .map_err(|_| Error::Persistence)?;
    manifest
        .verify_current(store)
        .map_err(|_| Error::Persistence)?;
    Ok(references)
}
/// Read-only reference discovery under existing trusted root membership.
/// Missing manifests/children/references are refusals, never initialization.
pub(crate) fn load_capture_reference<
    S: super::root_manifest::Store + super::vault_custody::Store,
>(
    store: &S,
    root: &super::root_manifest::RootBinding,
    scope: &Scope,
    id: &str,
) -> Result<CaptureRef> {
    CaptureId::new(id).map_err(|_| Error::Invalid)?;
    let (mut manifest, child) = reopen_member(store, root, scope)?;
    let reference = child
        .capture_references_for_lookup()
        .map_err(|_| Error::Persistence)?
        .into_iter()
        .find(|reference| reference.id() == id)
        .ok_or(Error::Missing)?;
    // This also refuses a sticky/incomplete child, even with a valid row.
    child
        .load_upload_attempt(&reference)
        .map_err(|_| Error::Persistence)?;
    manifest
        .verify_current(store)
        .map_err(|_| Error::Persistence)?;
    Ok(reference)
}
fn reopen_member<S: super::root_manifest::Store + super::vault_custody::Store>(
    store: &S,
    root: &super::root_manifest::RootBinding,
    scope: &Scope,
) -> Result<(
    super::root_manifest::RootManifest,
    super::vault_custody::Custody,
)> {
    let mut manifest =
        super::root_manifest::RootManifest::reopen(store, root).map_err(|_| Error::Persistence)?;
    if !manifest
        .scopes_for_reconciliation()
        .map_err(|_| Error::Persistence)?
        .contains(scope)
    {
        return Err(Error::Foreign);
    }
    manifest
        .verify_current(store)
        .map_err(|_| Error::Persistence)?;
    let child =
        super::vault_custody::Custody::reopen(store, scope).map_err(|_| Error::Persistence)?;
    Ok((manifest, child))
}
/// Logical adapter over the already protected whole-child CAS. It owns no
/// locks, session permit, native handles or network capability. All reads/CAS
/// freshly authenticate root membership, child and the exact immutable ref.
pub(crate) struct CustodyLedger<'a, S> {
    store: &'a S,
    root: &'a super::root_manifest::RootBinding,
    scope: &'a Scope,
    reference: &'a CaptureRef,
}
impl<'a, S: super::root_manifest::Store + super::vault_custody::Store> CustodyLedger<'a, S> {
    pub(crate) fn admit(
        store: &'a S,
        root: &'a super::root_manifest::RootBinding,
        scope: &'a Scope,
        reference: &'a CaptureRef,
    ) -> Result<Self> {
        let ledger = Self {
            store,
            root,
            scope,
            reference,
        };
        ledger.load(&locator(scope, reference)?)?;
        Ok(ledger)
    }
    fn check_locator(&self, key: &[u8]) -> Result<()> {
        if key != locator(self.scope, self.reference)? {
            return Err(Error::Foreign);
        }
        Ok(())
    }
}
impl<S: super::root_manifest::Store + super::vault_custody::Store> Store for CustodyLedger<'_, S> {
    fn load(&self, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.check_locator(key)?;
        let (mut manifest, child) = reopen_member(self.store, self.root, self.scope)?;
        let record = child
            .load_upload_attempt(self.reference)
            .map_err(|_| Error::Persistence)?;
        manifest
            .verify_current(self.store)
            .map_err(|_| Error::Persistence)?;
        Ok(record)
    }
    fn compare_exchange(&self, key: &[u8], old: Option<&[u8]>, next: &[u8]) -> Result<()> {
        self.check_locator(key)?;
        let (mut manifest, mut child) = reopen_member(self.store, self.root, self.scope)?;
        child
            .compare_exchange_upload_attempt(self.store, self.reference, old, next)
            .map_err(|_| Error::Persistence)?;
        manifest
            .verify_current(self.store)
            .map_err(|_| Error::Persistence)
    }
}

/// One fresh durable transition acknowledgement. Private fields, no Clone,
/// deserialization or constructor; consumed even on refused outcome recording.
/// This is bookkeeping only: live dispatch authority must come from another adapter.
pub(crate) struct FreshAttempt {
    binding: Binding,
    revision: u64,
}
pub(crate) struct UploadAttempt {
    document: Document,
    raw: Zeroizing<Vec<u8>>,
    failed: bool,
}
impl UploadAttempt {
    pub(crate) fn initialize(
        store: &impl Store,
        body_store: &impl capture::Store,
        scope: &Scope,
        reference: &CaptureRef,
        original: &Entry,
    ) -> Result<Self> {
        let binding = Binding::from_capture(body_store, scope, reference, original)?;
        let document = Document {
            version: VERSION,
            revision: 1,
            binding,
            state: State::NeverAttempted {},
        };
        let raw = encode(&document)?;
        let key = document.binding.locator()?;
        store
            .compare_exchange(&key, None, &raw)
            .map_err(|_| Error::Persistence)?;
        if store
            .load(&key)
            .map_err(|_| Error::Persistence)?
            .as_deref()
            .map(Vec::as_slice)
            != Some(raw.as_slice())
        {
            return Err(Error::Persistence);
        }
        Ok(Self {
            document,
            raw,
            failed: false,
        })
    }
    /// An interrupted attempt is durably uncertain before returning; it can
    /// never mint a fresh attempt ticket or silently replay an HTTP mutation.
    pub(crate) fn reopen(
        store: &impl Store,
        body_store: &impl capture::Store,
        scope: &Scope,
        reference: &CaptureRef,
        original: &Entry,
    ) -> Result<Self> {
        let binding = Binding::from_capture(body_store, scope, reference, original)?;
        let raw = store
            .load(&binding.locator()?)
            .map_err(|_| Error::Persistence)?
            .ok_or(Error::Missing)?;
        let document = decode(&raw, &binding)?;
        let interrupted = document.state == (State::Attempting {});
        let mut value = Self {
            document,
            raw,
            failed: false,
        };
        if interrupted {
            value.commit(store, State::Uncertain {})?;
        }
        Ok(value)
    }
    fn commit(&mut self, store: &impl Store, state: State) -> Result<()> {
        if self.failed {
            return Err(Error::Persistence);
        }
        let mut next = self.document.clone();
        next.revision = next.revision.checked_add(1).ok_or(Error::Invalid)?;
        next.state = state;
        next.validate(&self.document.binding)?;
        let raw = encode(&next)?;
        let key = next.binding.locator()?;
        let result = (|| {
            store
                .compare_exchange(&key, Some(&self.raw), &raw)
                .map_err(|_| Error::Persistence)?;
            let readback = store
                .load(&key)
                .map_err(|_| Error::Persistence)?
                .ok_or(Error::Persistence)?;
            if readback.as_slice() != raw.as_slice() {
                return Err(Error::Persistence);
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
            return Err(Error::Persistence);
        }
        self.document = next;
        self.raw = raw;
        Ok(())
    }
    pub(crate) fn begin_attempt(&mut self, store: &impl Store) -> Result<FreshAttempt> {
        if self.failed {
            return Err(Error::Persistence);
        }
        if self.document.state != (State::NeverAttempted {}) {
            return Err(Error::Conflict);
        }
        self.commit(store, State::Attempting {})?;
        Ok(FreshAttempt {
            binding: self.document.binding.clone(),
            revision: self.document.revision,
        })
    }
    fn consume(&self, ticket: FreshAttempt) -> Result<()> {
        if self.failed {
            return Err(Error::Persistence);
        }
        if self.document.state != (State::Attempting {})
            || ticket.revision != self.document.revision
            || ticket.binding != self.document.binding
        {
            return Err(Error::Foreign);
        }
        Ok(())
    }
    pub(crate) fn record_uncertain(
        &mut self,
        store: &impl Store,
        ticket: FreshAttempt,
    ) -> Result<()> {
        self.consume(ticket)?;
        self.commit(store, State::Uncertain {})
    }
    pub(crate) fn record_conflict(
        &mut self,
        store: &impl Store,
        ticket: FreshAttempt,
    ) -> Result<()> {
        self.consume(ticket)?;
        self.commit(store, State::Conflict {})
    }
    /// The future adapter must independently authenticate PUT and GET, establish
    /// their exact current resource/scope/opaque epoch/token fences, and supply
    /// the readback of that PUT's strong ETag. Historical labels are never used
    /// here as live authority. Input bytes are borrowed and never copied/stored.
    pub(crate) fn record_readback_evidence(
        &mut self,
        store: &impl Store,
        ticket: FreshAttempt,
        resource_id: &str,
        put_etag: &str,
        readback_etag: &str,
        body: &[u8],
    ) -> Result<()> {
        self.consume(ticket)?;
        if resource_id != self.document.binding.original.remote_id()
            || put_etag != readback_etag
            || !capture::strong_etag(readback_etag)
            || readback_etag == self.document.binding.original.etag()
            || body.len() != self.document.binding.body_len
        {
            return Err(Error::Conflict);
        }
        let evidence = HistoricalReadbackEvidence {
            resource_id: resource_id.into(),
            etag: readback_etag.into(),
            body_len: body.len(),
            body_sha256: Sha256::digest(body).into(),
        };
        validate_evidence(&self.document.binding, &evidence)?;
        self.commit(store, State::ReadbackRecorded { evidence })
    }
    #[cfg(test)]
    pub(crate) fn readback_evidence(&self) -> Result<Option<&HistoricalReadbackEvidence>> {
        if self.failed {
            return Err(Error::Persistence);
        }
        Ok(match &self.document.state {
            State::ReadbackRecorded { evidence } => Some(evidence),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::vault_custody as custody;
    use super::*;
    use raiun_engine::folder_pairs::AccountScope;
    use raiun_vault::session::VaultSessionScope;
    use std::{
        cell::{Cell, RefCell},
        collections::BTreeMap,
    };
    type Bytes = Zeroizing<Vec<u8>>;
    #[derive(Default)]
    struct Memory {
        child: RefCell<Option<Bytes>>,
        roots: RefCell<BTreeMap<Vec<u8>, Bytes>>,
        uncertain_child: Cell<bool>,
        race_child_once: Cell<bool>,
        bodies: RefCell<BTreeMap<Vec<u8>, Bytes>>,
        records: RefCell<BTreeMap<Vec<u8>, Bytes>>,
        uncertain: Cell<bool>,
        corrupt_readback: Cell<bool>,
        writes: Cell<usize>,
    }
    impl custody::Store for Memory {
        fn load(&self, _: &Scope) -> std::result::Result<Option<Bytes>, custody::Error> {
            Ok(self.child.borrow().clone())
        }
        fn compare_exchange(
            &self,
            _: &Scope,
            old: Option<&[u8]>,
            next: &[u8],
        ) -> std::result::Result<(), custody::Error> {
            if self.child.borrow().as_ref().map(|v| v.as_slice()) != old {
                return Err(custody::Error::Conflict);
            }
            if self.race_child_once.replace(false) {
                let mut value: serde_json::Value =
                    serde_json::from_slice(self.child.borrow().as_ref().unwrap()).unwrap();
                value["revision"] = (value["revision"].as_u64().unwrap() + 1).into();
                *self.child.borrow_mut() =
                    Some(Zeroizing::new(serde_json::to_vec(&value).unwrap()));
                return Err(custody::Error::Conflict);
            }
            *self.child.borrow_mut() = Some(Zeroizing::new(next.to_vec()));
            if self.uncertain_child.get() {
                return Err(custody::Error::Persistence);
            }
            Ok(())
        }
    }
    impl super::super::root_manifest::Store for Memory {
        fn load(&self, key: &[u8]) -> std::result::Result<Option<Bytes>, custody::Error> {
            Ok(self.roots.borrow().get(key).cloned())
        }
        fn compare_exchange(
            &self,
            key: &[u8],
            old: Option<&[u8]>,
            next: &[u8],
        ) -> std::result::Result<(), custody::Error> {
            let mut map = self.roots.borrow_mut();
            if map.get(key).map(|raw| raw.as_slice()) != old {
                return Err(custody::Error::Conflict);
            }
            map.insert(key.to_vec(), Zeroizing::new(next.to_vec()));
            Ok(())
        }
    }
    impl capture::Store for Memory {
        fn load(&self, _: &[u8], key: &[u8]) -> std::result::Result<Option<Bytes>, capture::Error> {
            Ok(self.bodies.borrow().get(key).cloned())
        }
        fn put_new(
            &self,
            _: &[u8],
            key: &[u8],
            value: &[u8],
        ) -> std::result::Result<capture::PutNew, capture::Error> {
            let mut map = self.bodies.borrow_mut();
            if map.contains_key(key) {
                return Ok(capture::PutNew::AlreadyExists);
            }
            map.insert(key.to_vec(), Zeroizing::new(value.to_vec()));
            Ok(capture::PutNew::Created)
        }
    }
    impl Store for Memory {
        fn load(&self, key: &[u8]) -> Result<Option<Bytes>> {
            let mut value = self.records.borrow().get(key).cloned();
            if self.corrupt_readback.get()
                && let Some(raw) = &mut value
            {
                raw.push(b' ');
            }
            Ok(value)
        }
        fn compare_exchange(&self, key: &[u8], old: Option<&[u8]>, next: &[u8]) -> Result<()> {
            let mut map = self.records.borrow_mut();
            if map.get(key).map(|v| v.as_slice()) != old {
                return Err(Error::Conflict);
            }
            map.insert(key.to_vec(), Zeroizing::new(next.to_vec()));
            self.writes.set(self.writes.get() + 1);
            if self.uncertain.get() {
                return Err(Error::Persistence);
            }
            Ok(())
        }
    }
    fn scope(subject: &str) -> Scope {
        let account = AccountScope::new(
            "default".into(),
            "https://example.test/".into(),
            "client".into(),
            None,
            subject.into(),
        )
        .unwrap();
        let vault =
            VaultSessionScope::new("default", "https://example.test", "space", "root").unwrap();
        Scope::new(
            &serde_json::to_vec(&account).unwrap(),
            &vault,
            "/vault",
            7,
            42,
            "registration",
        )
        .unwrap()
    }
    fn fixture() -> (Memory, Scope, CaptureRef, Entry) {
        let store = Memory::default();
        let scope = scope("subject");
        let root_binding = super::super::root_manifest::RootBinding::from_scope(&scope).unwrap();
        let mut manifest = super::super::root_manifest::RootManifest::initialize_new_registration(
            &store,
            &root_binding,
        )
        .unwrap();
        manifest.register(&store, &scope).unwrap();
        let original = Entry::new([1; 16], "remote-file", "/1", "\"original\"", false, 4).unwrap();
        let mut child = custody::Custody::initialize_new_scope(&store, scope.clone()).unwrap();
        child.record_entry(&store, original.clone()).unwrap();
        let components = vec!["Personal".into(), "vault".into(), "1".into()];
        child
            .persist_hydration_intent(&store, [1; 16], 90, 4, components.clone())
            .unwrap();
        let prepared = capture::PreparedCapture::new(
            &scope,
            &CaptureId::new("capture-1").unwrap(),
            capture::Baseline::new([1; 16], "\"original\"", 3, 11, 7, 90).unwrap(),
            Zeroizing::new(b"edited bytes".to_vec()),
        )
        .unwrap();
        let custody::CaptureEnrollment::New(ticket) = child
            .enroll_capture(&store, &prepared, &components)
            .unwrap()
        else {
            panic!("fresh enrollment")
        };
        capture::persist_prepared_new(&store, prepared, ticket).unwrap();
        let reference = child.captures_for_reconciliation()[0].clone();
        (store, scope, reference, original)
    }
    fn initialize(
        s: &Memory,
        scope: &Scope,
        reference: &CaptureRef,
        original: &Entry,
    ) -> UploadAttempt {
        UploadAttempt::initialize(s, s, scope, reference, original).unwrap()
    }
    #[test]
    fn claim_is_durable_before_ticket_and_exact_readback_is_historical_only() {
        let (s, scope, reference, original) = fixture();
        let body_before = s.bodies.borrow().clone();
        let child_before = s.child.borrow().clone();
        let mut attempt = initialize(&s, &scope, &reference, &original);
        let ticket = attempt.begin_attempt(&s).unwrap();
        let stored = Store::load(&s, &attempt.document.binding.locator().unwrap())
            .unwrap()
            .unwrap();
        assert!(matches!(
            decode(&stored, &attempt.document.binding).unwrap().state,
            State::Attempting {}
        ));
        assert!(matches!(attempt.begin_attempt(&s), Err(Error::Conflict)));
        attempt
            .record_readback_evidence(
                &s,
                ticket,
                "remote-file",
                "\"new\"",
                "\"new\"",
                b"edited bytes",
            )
            .unwrap();
        let count = s.writes.get();
        let mut reopened = UploadAttempt::reopen(&s, &s, &scope, &reference, &original).unwrap();
        assert_eq!(s.writes.get(), count);
        assert!(reopened.readback_evidence().unwrap().is_some());
        assert!(matches!(reopened.begin_attempt(&s), Err(Error::Conflict)));
        assert!(s.bodies.borrow().eq(&body_before));
        assert!(s.child.borrow().eq(&child_before));
    }
    #[test]
    fn interrupted_attempt_becomes_uncertain_and_cannot_replay() {
        let (s, scope, reference, original) = fixture();
        let mut attempt = initialize(&s, &scope, &reference, &original);
        let ticket = attempt.begin_attempt(&s).unwrap();
        drop(ticket);
        drop(attempt);
        let count = s.writes.get();
        let mut reopened = UploadAttempt::reopen(&s, &s, &scope, &reference, &original).unwrap();
        assert_eq!(s.writes.get(), count + 1);
        assert!(matches!(reopened.document.state, State::Uncertain {}));
        assert!(matches!(reopened.begin_attempt(&s), Err(Error::Conflict)));
        assert!(reopened.readback_evidence().unwrap().is_none());
    }
    #[test]
    fn uncertain_claim_or_receipt_never_acknowledges_or_replays() {
        for during_receipt in [false, true] {
            let (s, scope, reference, original) = fixture();
            let mut attempt = initialize(&s, &scope, &reference, &original);
            if during_receipt {
                let ticket = attempt.begin_attempt(&s).unwrap();
                s.uncertain.set(true);
                assert!(matches!(
                    attempt.record_readback_evidence(
                        &s,
                        ticket,
                        "remote-file",
                        "\"new\"",
                        "\"new\"",
                        b"edited bytes"
                    ),
                    Err(Error::Persistence)
                ));
            } else {
                s.uncertain.set(true);
                assert!(matches!(attempt.begin_attempt(&s), Err(Error::Persistence)));
            }
            assert!(matches!(
                attempt.readback_evidence(),
                Err(Error::Persistence)
            ));
            assert!(matches!(attempt.begin_attempt(&s), Err(Error::Persistence)));
            s.uncertain.set(false);
            let mut reopened =
                UploadAttempt::reopen(&s, &s, &scope, &reference, &original).unwrap();
            assert!(matches!(reopened.begin_attempt(&s), Err(Error::Conflict)));
            // A published historical evidence row may be recovered after an
            // uncertain write, but it grants no live/native acknowledgement.
            assert_eq!(
                reopened.readback_evidence().unwrap().is_some(),
                during_receipt
            );
        }
        // CAS success with a non-exact subsequent load must not mint a ticket.
        let (s, scope, reference, original) = fixture();
        let mut attempt = initialize(&s, &scope, &reference, &original);
        s.corrupt_readback.set(true);
        assert!(matches!(attempt.begin_attempt(&s), Err(Error::Persistence)));
        assert!(matches!(
            attempt.readback_evidence(),
            Err(Error::Persistence)
        ));
        s.corrupt_readback.set(false);
        let recovered = UploadAttempt::reopen(&s, &s, &scope, &reference, &original).unwrap();
        assert!(matches!(recovered.document.state, State::Uncertain {}));

        // A fresh process makes the interrupted attempt uncertain. The older
        // holder's receipt CAS must then fail without replacing that evidence.
        let (s, scope, reference, original) = fixture();
        let mut stale = initialize(&s, &scope, &reference, &original);
        let ticket = stale.begin_attempt(&s).unwrap();
        let recovered = UploadAttempt::reopen(&s, &s, &scope, &reference, &original).unwrap();
        let before = recovered.raw.clone();
        assert!(matches!(
            stale.record_readback_evidence(
                &s,
                ticket,
                "remote-file",
                "\"new\"",
                "\"new\"",
                b"edited bytes"
            ),
            Err(Error::Persistence)
        ));
        assert!(matches!(stale.readback_evidence(), Err(Error::Persistence)));
        let recovered = UploadAttempt::reopen(&s, &s, &scope, &reference, &original).unwrap();
        assert!(recovered.raw.as_slice() == before.as_slice());
        assert!(recovered.readback_evidence().unwrap().is_none());
    }
    #[test]
    fn original_resource_strong_etag_and_exact_body_are_required() {
        for bad in 0..5 {
            let (s, scope, reference, original) = fixture();
            let mut attempt = initialize(&s, &scope, &reference, &original);
            let ticket = attempt.begin_attempt(&s).unwrap();
            let (resource, put, get, body) = match bad {
                0 => ("foreign", "\"new\"", "\"new\"", b"edited bytes".as_slice()),
                1 => (
                    "remote-file",
                    "W/\"weak\"",
                    "W/\"weak\"",
                    b"edited bytes".as_slice(),
                ),
                2 => (
                    "remote-file",
                    "\"original\"",
                    "\"original\"",
                    b"edited bytes".as_slice(),
                ),
                3 => (
                    "remote-file",
                    "\"new\"",
                    "\"other\"",
                    b"edited bytes".as_slice(),
                ),
                _ => (
                    "remote-file",
                    "\"new\"",
                    "\"new\"",
                    b"edited bytex".as_slice(),
                ),
            };
            assert!(
                attempt
                    .record_readback_evidence(&s, ticket, resource, put, get, body)
                    .is_err()
            );
            assert!(attempt.readback_evidence().unwrap().is_none());
            let reopened = UploadAttempt::reopen(&s, &s, &scope, &reference, &original).unwrap();
            assert!(matches!(reopened.document.state, State::Uncertain {}));
        }
    }
    #[test]
    fn conflict_and_uncertain_outcomes_preserve_capture_and_stale_cas_fails_closed() {
        for uncertain in [false, true] {
            let (s, scope, reference, original) = fixture();
            let before = s.bodies.borrow().clone();
            let mut attempt = initialize(&s, &scope, &reference, &original);
            let mut stale = UploadAttempt::reopen(&s, &s, &scope, &reference, &original).unwrap();
            let ticket = attempt.begin_attempt(&s).unwrap();
            assert!(matches!(stale.begin_attempt(&s), Err(Error::Persistence)));
            if uncertain {
                attempt.record_uncertain(&s, ticket).unwrap();
            } else {
                attempt.record_conflict(&s, ticket).unwrap();
            }
            let mut reopened =
                UploadAttempt::reopen(&s, &s, &scope, &reference, &original).unwrap();
            assert!(matches!(reopened.begin_attempt(&s), Err(Error::Conflict)));
            assert!(s.bodies.borrow().eq(&before));
        }
    }
    #[test]
    fn scope_frame_original_and_strict_record_parsing_refuse_without_healing() {
        let (s, scope, reference, original) = fixture();
        let attempt = initialize(&s, &scope, &reference, &original);
        assert!(UploadAttempt::initialize(&s, &s, &scope, &reference, &original).is_err());
        assert!(
            UploadAttempt::reopen(&s, &s, &self::scope("foreign"), &reference, &original).is_err()
        );
        let foreign_entry =
            Entry::new([1; 16], "other-resource", "/1", "\"original\"", false, 4).unwrap();
        assert!(UploadAttempt::reopen(&s, &s, &scope, &reference, &foreign_entry).is_err());
        let key = attempt.document.binding.locator().unwrap();
        let good = attempt.raw.clone();
        for bad in 0..5 {
            let mut value: serde_json::Value = serde_json::from_slice(&good).unwrap();
            match bad {
                0 => value["version"] = 2.into(),
                1 => value["unexpected"] = true.into(),
                2 => value["state"] = serde_json::json!({"kind":"Attempting","extra":true}),
                3 => value["binding"]["capture"]["frame"]["length"] = 0.into(),
                _ => value["state"] = serde_json::Value::Null,
            }
            let raw = Zeroizing::new(serde_json::to_vec(&value).unwrap());
            s.records.borrow_mut().insert(key.clone(), raw.clone());
            assert!(UploadAttempt::reopen(&s, &s, &scope, &reference, &original).is_err());
            assert!(s.records.borrow().get(&key).unwrap().as_slice() == raw.as_slice());
        }
        s.records.borrow_mut().insert(
            key.clone(),
            Zeroizing::new(vec![b' '; MAX_RECORD_BYTES + 1]),
        );
        assert!(UploadAttempt::reopen(&s, &s, &scope, &reference, &original).is_err());
        s.records.borrow_mut().insert(key.clone(), good);
        let body_key = s.bodies.borrow().keys().next().unwrap().clone();
        s.bodies.borrow_mut().get_mut(&body_key).unwrap().push(0);
        assert!(UploadAttempt::reopen(&s, &s, &scope, &reference, &original).is_err());
        assert_eq!(s.bodies.borrow().get(&body_key).unwrap().last(), Some(&0));
    }
    fn root(scope: &Scope) -> super::super::root_manifest::RootBinding {
        super::super::root_manifest::RootBinding::from_scope(scope).unwrap()
    }
    #[test]
    fn protected_ledger_preserves_v1_v2_raw_reads_and_only_explicit_init_creates_v3() {
        let (s, scope, reference, original) = fixture();
        let binding = root(&scope);
        let old: serde_json::Value =
            serde_json::from_slice(s.child.borrow().as_ref().unwrap()).unwrap();
        let mut v1 = old.clone();
        v1["version"] = 1.into();
        v1.as_object_mut().unwrap().remove("capture_refs");
        let mut spaced = b" \n".to_vec();
        spaced.extend_from_slice(&serde_json::to_vec(&v1).unwrap());
        spaced.extend_from_slice(b"\n ");
        *s.child.borrow_mut() = Some(Zeroizing::new(spaced.clone()));
        custody::Custody::reopen(&s, &scope).unwrap();
        assert!(load_capture_reference(&s, &binding, &scope, reference.id()).is_err());
        assert!(s.child.borrow().as_ref().unwrap().as_slice() == spaced);
        let mut spaced = b" \n".to_vec();
        spaced.extend_from_slice(&serde_json::to_vec(&old).unwrap());
        spaced.extend_from_slice(b"\n ");
        *s.child.borrow_mut() = Some(Zeroizing::new(spaced.clone()));
        let loaded = load_capture_reference(&s, &binding, &scope, reference.id()).unwrap();
        assert!(loaded == reference);
        assert!(load_capture_references(&s, &binding, &scope).unwrap() == vec![reference.clone()]);
        let ledger = CustodyLedger::admit(&s, &binding, &scope, &reference).unwrap();
        assert!(
            ledger
                .load(&locator(&scope, &reference).unwrap())
                .unwrap()
                .is_none()
        );
        assert!(s.child.borrow().as_ref().unwrap().as_slice() == spaced);
        let bodies = s.bodies.borrow().clone();
        let mut attempt =
            UploadAttempt::initialize(&ledger, &s, &scope, &reference, &original).unwrap();
        let document: serde_json::Value =
            serde_json::from_slice(s.child.borrow().as_ref().unwrap()).unwrap();
        assert_eq!(document["version"], 3);
        assert_eq!(document["upload_attempts"].as_array().unwrap().len(), 1);
        let fresh = custody::Custody::reopen(&s, &scope).unwrap();
        assert!(fresh.captures_for_reconciliation()[0] == reference);
        assert!(fresh.publication_history().is_err());
        let ticket = attempt.begin_attempt(&ledger).unwrap();
        attempt
            .record_readback_evidence(
                &ledger,
                ticket,
                "remote-file",
                "\"new\"",
                "\"new\"",
                b"edited bytes",
            )
            .unwrap();
        assert!(
            custody::Custody::reopen(&s, &scope)
                .unwrap()
                .publication_history()
                .is_err()
        );
        assert!(s.bodies.borrow().eq(&bodies));
    }
    #[test]
    fn protected_ledger_whole_child_race_and_uncertain_claim_never_adopt_or_replay() {
        let (s, scope, reference, original) = fixture();
        let binding = root(&scope);
        let ledger = CustodyLedger::admit(&s, &binding, &scope, &reference).unwrap();
        s.race_child_once.set(true);
        assert!(UploadAttempt::initialize(&ledger, &s, &scope, &reference, &original).is_err());
        let raced: serde_json::Value =
            serde_json::from_slice(s.child.borrow().as_ref().unwrap()).unwrap();
        assert_eq!(raced["version"], 2);
        assert!(raced.get("upload_attempts").is_none());
        let mut attempt =
            UploadAttempt::initialize(&ledger, &s, &scope, &reference, &original).unwrap();
        s.uncertain_child.set(true);
        assert!(matches!(
            attempt.begin_attempt(&ledger),
            Err(Error::Persistence)
        ));
        assert!(matches!(
            attempt.readback_evidence(),
            Err(Error::Persistence)
        ));
        s.uncertain_child.set(false);
        let mut recovered =
            UploadAttempt::reopen(&ledger, &s, &scope, &reference, &original).unwrap();
        assert!(matches!(recovered.document.state, State::Uncertain {}));
        assert!(matches!(
            recovered.begin_attempt(&ledger),
            Err(Error::Conflict)
        ));
        let key = locator(&scope, &reference).unwrap();
        let old = ledger.load(&key).unwrap().unwrap();
        let mut reset: serde_json::Value = serde_json::from_slice(&old).unwrap();
        reset["revision"] = (reset["revision"].as_u64().unwrap() + 1).into();
        reset["state"] = serde_json::json!({"kind":"NeverAttempted"});
        assert!(
            ledger
                .compare_exchange(&key, Some(&old), &serde_json::to_vec(&reset).unwrap())
                .is_err()
        );
        let mut nonexact = old.to_vec();
        nonexact.push(b' ');
        assert!(
            ledger
                .compare_exchange(&key, Some(&nonexact), &old)
                .is_err()
        );
        assert!(ledger.load(&key).unwrap().unwrap().as_slice() == old.as_slice());
    }
    #[test]
    fn protected_ledger_refuses_foreign_reference_missing_member_child_or_body_without_healing() {
        let (s, scope, reference, original) = fixture();
        let binding = root(&scope);
        let before = s.child.borrow().clone().unwrap();
        let mut wrong: serde_json::Value = serde_json::to_value(&reference).unwrap();
        wrong["frame"]["length"] = (wrong["frame"]["length"].as_u64().unwrap() + 1).into();
        let wrong: CaptureRef = serde_json::from_value(wrong).unwrap();
        assert!(CustodyLedger::admit(&s, &binding, &scope, &wrong).is_err());
        let ledger = CustodyLedger::admit(&s, &binding, &scope, &reference).unwrap();
        assert!(ledger.load(b"foreign-locator").is_err());
        s.bodies.borrow_mut().clear();
        assert!(UploadAttempt::initialize(&ledger, &s, &scope, &reference, &original).is_err());
        assert!(s.child.borrow().as_ref().unwrap().as_slice() == before.as_slice());
        *s.child.borrow_mut() = None;
        assert!(ledger.load(&locator(&scope, &reference).unwrap()).is_err());
        assert!(s.child.borrow().is_none());
        *s.child.borrow_mut() = Some(before.clone());
        s.roots.borrow_mut().clear();
        assert!(ledger.load(&locator(&scope, &reference).unwrap()).is_err());
        assert!(s.roots.borrow().is_empty());
        assert!(s.child.borrow().as_ref().unwrap().as_slice() == before.as_slice());
    }
    #[test]
    fn protected_v3_strict_null_empty_unknown_duplicate_and_oversize_records_preserve_evidence() {
        let (s, scope, reference, original) = fixture();
        let binding = root(&scope);
        let ledger = CustodyLedger::admit(&s, &binding, &scope, &reference).unwrap();
        UploadAttempt::initialize(&ledger, &s, &scope, &reference, &original).unwrap();
        let good: serde_json::Value =
            serde_json::from_slice(s.child.borrow().as_ref().unwrap()).unwrap();
        for bad in 0..9 {
            let mut value = good.clone();
            match bad {
                0 => value["upload_attempts"] = serde_json::Value::Null,
                1 => value["upload_attempts"] = serde_json::json!([]),
                2 => value["upload_attempts"][0]["record"] = serde_json::json!([]),
                3 => value["upload_attempts"][0]["record"] = serde_json::Value::Null,
                4 => value["upload_attempts"][0]["unknown"] = true.into(),
                5 => {
                    let row = value["upload_attempts"][0].clone();
                    value["upload_attempts"].as_array_mut().unwrap().push(row);
                }
                6 => value["version"] = 2.into(),
                7 => {
                    value["upload_attempts"][0]["record"] =
                        serde_json::to_value(vec![0u8; MAX_RECORD_BYTES + 1]).unwrap()
                }
                _ => value["upload_attempts"][0]["capture_id"] = "foreign-capture".into(),
            }
            let raw = Zeroizing::new(serde_json::to_vec(&value).unwrap());
            *s.child.borrow_mut() = Some(raw.clone());
            assert!(ledger.load(&locator(&scope, &reference).unwrap()).is_err());
            assert!(s.child.borrow().as_ref().unwrap().as_slice() == raw.as_slice());
        }
        let mut incomplete = good;
        incomplete["incomplete"] = true.into();
        *s.child.borrow_mut() = Some(Zeroizing::new(serde_json::to_vec(&incomplete).unwrap()));
        assert!(ledger.load(&locator(&scope, &reference).unwrap()).is_err());
        assert!(load_capture_references(&s, &binding, &scope).is_err());
    }
}

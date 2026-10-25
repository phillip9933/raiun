//! Inert immutable retained vault edits. No native capture, upload, cleanup or
//! session authority is provided. Store authentication is mandatory: framing,
//! digests and JSON validation alone do not authenticate a record.
use super::vault_custody::Scope;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Matches the existing protected vault-document plaintext ceiling. A future
/// adapter needs its OWN domain; the custody/credential stores are not adapters.
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;
/// Deliberately bounded prerequisite, not general large-file save support.
/// Binary framing avoids JSON byte-array expansion. Metadata has its own cap,
/// and the final exact encoded size is checked before persistence.
#[cfg(windows)]
pub const MAX_BODY_BYTES: usize = raiun_cloudfiles_windows::MAX_VAULT_EDIT_CAPTURE_BYTES;
#[cfg(not(windows))]
pub const MAX_BODY_BYTES: usize = 512 * 1024;
const MAX_METADATA_BYTES: usize = 128 * 1024;
pub(crate) const DOMAIN: &[u8] = b"raiun-vault-existing-edit-capture-v1";
const MAGIC: &[u8] = b"RAIUN-VAULT-EXISTING-EDIT-CAPTURE\0\x01";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Capacity,
    Missing,
    Foreign,
    Conflict,
    Persistence,
}
type Result<T> = std::result::Result<T, Error>;

/// No Debug/serialization: this is only a bounded storage locator, not authority.
#[derive(Clone, PartialEq, Eq)]
pub struct CaptureId(String);
impl CaptureId {
    pub fn new(value: &str) -> Result<Self> {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(Error::Invalid);
        }
        Ok(Self(value.into()))
    }
}

/// Trusted caller supplies an existing-file opaque identity and strong ETag,
/// captured under current account/root/session leases, plus the pinned native
/// volume/file identity. Nonzero counters are historical labels, not leases.
/// No Debug or live-operation methods; decoded fields are revalidated before use.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    opaque_file: [u8; 16],
    strong_etag: String,
    unlock_epoch: u64,
    token_generation: u64,
    native_volume: u32,
    native_file: u64,
}
impl Baseline {
    pub fn new(
        opaque_file: [u8; 16],
        strong_etag: &str,
        unlock_epoch: u64,
        token_generation: u64,
        native_volume: u32,
        native_file: u64,
    ) -> Result<Self> {
        let baseline = Self {
            opaque_file,
            strong_etag: strong_etag.into(),
            unlock_epoch,
            token_generation,
            native_volume,
            native_file,
        };
        baseline.validate()?;
        Ok(baseline)
    }
    fn validate(&self) -> Result<()> {
        if self.opaque_file == [0; 16]
            || !strong_etag(&self.strong_etag)
            || self.unlock_epoch == 0
            || self.token_generation == 0
            || self.native_volume == 0
            || self.native_file == 0
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
pub(crate) fn strong_etag(value: &str) -> bool {
    let etag = value.as_bytes();
    etag.len() >= 2
        && etag.len() <= 4096
        && etag.first() == Some(&b'"')
        && etag.last() == Some(&b'"')
        && etag[1..etag.len() - 1]
            .iter()
            .all(|b| *b == 0x21 || (0x23..=0x7e).contains(b))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    domain: String,
    scope: Scope,
    capture_id: String,
    baseline: Baseline,
    body_len: usize,
    body_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PutNew {
    Created,
    AlreadyExists,
}
/// Separate domain-bound protected persistence contract. Implementations MUST:
/// authenticate the WHOLE domain, binding and record; use private storage;
/// atomically put only if absent across processes; never overwrite old bytes;
/// and acknowledge Created only after durable publication and exact readback.
/// AlreadyExists must leave existing bytes unchanged. load must authenticate
/// before returning plaintext; None must not create storage. Errors may follow
/// publication and confer no rollback guarantee. The Windows adapter uses its own protected document domain.
pub trait Store {
    fn load(&self, domain: &[u8], binding: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn put_new(&self, domain: &[u8], binding: &[u8], record: &[u8]) -> Result<PutNew>;
}

/// Adapter over an already-admitted private Windows profile store. Construction
/// performs no account/session lookup or directory initialization. It is not
/// wired to native editing or ordinary upload recovery.
#[cfg(windows)]
pub struct DpapiCaptureStore<'a> {
    store: &'a raiun_control_windows::DpapiSessionStore,
}
#[cfg(windows)]
impl<'a> DpapiCaptureStore<'a> {
    pub fn new(store: &'a raiun_control_windows::DpapiSessionStore) -> Self {
        Self { store }
    }
}
#[cfg(windows)]
impl Store for DpapiCaptureStore<'_> {
    fn load(&self, domain: &[u8], binding: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        if domain != DOMAIN {
            return Err(Error::Foreign);
        }
        self.store
            .load_vault_existing_edit_capture(binding)
            .map_err(|_| Error::Persistence)
    }
    fn put_new(&self, domain: &[u8], binding: &[u8], record: &[u8]) -> Result<PutNew> {
        if domain != DOMAIN {
            return Err(Error::Foreign);
        }
        if self.load(domain, binding)?.is_some() {
            return Ok(PutNew::AlreadyExists);
        }
        // A race or uncertain publication remains an error. In particular,
        // never turn a failed write into success merely because bytes appeared.
        self.store
            .put_new_vault_existing_edit_capture(binding, record)
            .map_err(|_| Error::Persistence)?;
        Ok(PutNew::Created)
    }
}

fn binding(scope: &Scope, id: &CaptureId) -> Result<Zeroizing<Vec<u8>>> {
    let scope = scope
        .authenticated_store_binding()
        .map_err(|_| Error::Invalid)?;
    // Length framing prevents concatenation ambiguities. The store must also
    // authenticate DOMAIN independently of this locator.
    let mut binding = Zeroizing::new(Vec::new());
    binding.extend_from_slice(&(scope.len() as u32).to_le_bytes());
    binding.extend_from_slice(&scope);
    binding.extend_from_slice(id.0.as_bytes());
    Ok(binding)
}
fn encode(
    scope: &Scope,
    id: &CaptureId,
    baseline: Baseline,
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    baseline.validate()?;
    if body.len() > MAX_BODY_BYTES {
        return Err(Error::Capacity);
    }
    let metadata = Metadata {
        domain: String::from_utf8(DOMAIN.to_vec()).map_err(|_| Error::Invalid)?,
        scope: scope.clone(),
        capture_id: id.0.clone(),
        baseline,
        body_len: body.len(),
        body_sha256: Sha256::digest(body).into(),
    };
    let header = Zeroizing::new(serde_json::to_vec(&metadata).map_err(|_| Error::Invalid)?);
    if header.len() > MAX_METADATA_BYTES {
        return Err(Error::Capacity);
    }
    let length = MAGIC.len() + 4 + header.len() + body.len();
    if length > MAX_RECORD_BYTES {
        return Err(Error::Capacity);
    }
    let mut raw = Zeroizing::new(Vec::with_capacity(length));
    raw.extend_from_slice(MAGIC);
    raw.extend_from_slice(&(header.len() as u32).to_le_bytes());
    raw.extend_from_slice(&header);
    raw.extend_from_slice(body);
    Ok(raw)
}

/// Historical recovery bytes ONLY. Reopening deliberately does not require a
/// current epoch: dirty bytes from an older unlock must never be discarded.
/// The type has no conversion into a session, route, dispatch or upload permit.
/// Any future upload requires independent current unlock/root/remote validation.
pub struct RetainedEdit {
    metadata: Metadata,
    raw: Zeroizing<Vec<u8>>,
    body_offset: usize,
}
impl RetainedEdit {
    pub fn bytes_for_recovery(&self) -> &[u8] {
        &self.raw[self.body_offset..]
    }
    pub fn historical_baseline(&self) -> &Baseline {
        &self.metadata.baseline
    }
}
fn decode(raw: Zeroizing<Vec<u8>>, scope: &Scope, id: &CaptureId) -> Result<RetainedEdit> {
    if raw.len() > MAX_RECORD_BYTES || raw.len() < MAGIC.len() + 4 || !raw.starts_with(MAGIC) {
        return Err(Error::Invalid);
    }
    let size = u32::from_le_bytes(
        raw[MAGIC.len()..MAGIC.len() + 4]
            .try_into()
            .map_err(|_| Error::Invalid)?,
    ) as usize;
    let offset = (MAGIC.len() + 4).checked_add(size).ok_or(Error::Capacity)?;
    if size > MAX_METADATA_BYTES || offset > raw.len() || raw.len() - offset > MAX_BODY_BYTES {
        return Err(Error::Capacity);
    }
    let metadata: Metadata =
        serde_json::from_slice(&raw[MAGIC.len() + 4..offset]).map_err(|_| Error::Invalid)?;
    metadata.baseline.validate()?;
    let parsed = metadata
        .scope
        .authenticated_store_binding()
        .map_err(|_| Error::Invalid)?;
    let expected = scope
        .authenticated_store_binding()
        .map_err(|_| Error::Invalid)?;
    if parsed != expected || metadata.domain.as_bytes() != DOMAIN || metadata.capture_id != id.0 {
        return Err(Error::Foreign);
    }
    if metadata.body_len != raw.len() - offset
        || metadata.body_sha256 != <[u8; 32]>::from(Sha256::digest(&raw[offset..]))
    {
        return Err(Error::Invalid);
    }
    Ok(RetainedEdit {
        metadata,
        raw,
        body_offset: offset,
    })
}

/// Trusted caller must already hold all live capture leases; this inert model
/// cannot establish them. Success acknowledges retained bytes only. Plaintext
/// ownership is moved in and zeroized on every success/error path.
#[cfg(test)]
pub fn retain(
    store: &impl Store,
    scope: &Scope,
    id: &CaptureId,
    baseline: Baseline,
    body: Zeroizing<Vec<u8>>,
) -> Result<RetainedEdit> {
    let key = binding(scope, id)?;
    let raw = encode(scope, id, baseline, &body)?;
    store
        .put_new(DOMAIN, &key, &raw)
        .map_err(|_| Error::Persistence)?;
    // Even Created is checked through the same fresh authenticated load path.
    // Conflicting duplicate IDs never overwrite, including concurrent callers.
    let retained = reopen_for_recovery(store, scope, id)?;
    if retained.raw.as_slice() != raw.as_slice() {
        return Err(Error::Conflict);
    }
    Ok(retained)
}
pub fn reopen_for_recovery(
    store: &impl Store,
    scope: &Scope,
    id: &CaptureId,
) -> Result<RetainedEdit> {
    let key = binding(scope, id)?;
    let raw = store
        .load(DOMAIN, &key)
        .map_err(|_| Error::Persistence)?
        .ok_or(Error::Missing)?;
    decode(raw, scope, id)
}

/// Digest/length of the complete immutable encoded frame, including scope,
/// baseline, native identity, epoch labels and body. Not an upload permit.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EncodedFrameRef {
    length: usize,
    sha256: [u8; 32],
}
impl EncodedFrameRef {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.length <= MAGIC.len() + 4
            || self.length > MAX_RECORD_BYTES
            || self.sha256 == [0; 32]
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
impl RetainedEdit {
    pub(crate) fn encoded_frame_ref(&self) -> EncodedFrameRef {
        EncodedFrameRef {
            length: self.raw.len(),
            sha256: Sha256::digest(self.raw.as_slice()).into(),
        }
    }
}
/// Encode once before index enrollment. No mutable frame, Debug, Clone or
/// deserialization API; dropping this object zeroizes its owned plaintext frame.
pub(crate) struct PreparedCapture {
    edit: RetainedEdit,
}
impl PreparedCapture {
    pub(crate) fn new(
        scope: &Scope,
        id: &CaptureId,
        baseline: Baseline,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Self> {
        let _validated_scope_binding = binding(scope, id)?;
        let raw = encode(scope, id, baseline, &body)?;
        Ok(Self {
            edit: decode(raw, scope, id)?,
        })
    }
    pub(crate) fn scope(&self) -> &Scope {
        &self.edit.metadata.scope
    }
    pub(crate) fn id(&self) -> &str {
        &self.edit.metadata.capture_id
    }
    pub(crate) fn existing_file_binding(&self) -> ([u8; 16], &str, u32, u64) {
        let b = &self.edit.metadata.baseline;
        (
            b.opaque_file,
            &b.strong_etag,
            b.native_volume,
            b.native_file,
        )
    }
    pub(crate) fn encoded_frame_ref(&self) -> EncodedFrameRef {
        self.edit.encoded_frame_ref()
    }
}
/// Persistence requires an acknowledged, newly enrolled index ticket. A
/// recovered/existing reference cannot mint this consumed, non-cloneable ticket.
/// AlreadyExists is a collision here, never adoption of a previous body.
pub(crate) fn persist_prepared_new(
    store: &impl Store,
    prepared: PreparedCapture,
    ticket: super::vault_custody::FreshEnrollmentTicket,
) -> Result<RetainedEdit> {
    ticket.consume(&prepared).map_err(|_| Error::Foreign)?;
    let scope = prepared.scope();
    let id = CaptureId::new(prepared.id())?;
    let key = binding(scope, &id)?;
    match store
        .put_new(DOMAIN, &key, &prepared.edit.raw)
        .map_err(|_| Error::Persistence)?
    {
        PutNew::Created => {}
        PutNew::AlreadyExists => return Err(Error::Conflict),
    }
    let retained = reopen_for_recovery(store, scope, &id)?;
    if retained.raw.as_slice() != prepared.edit.raw.as_slice() {
        return Err(Error::Conflict);
    }
    Ok(retained)
}

#[cfg(test)]
mod tests {
    use super::*;
    use raiun_engine::folder_pairs::AccountScope;
    use raiun_vault::session::VaultSessionScope;
    use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

    // Synthetic authenticated-store contract simulator, NOT cryptography for
    // production. A fresh wrapper shares durable bytes but no live authority.
    type Rows = BTreeMap<Vec<u8>, (Vec<u8>, [u8; 32])>;
    #[derive(Clone, Default)]
    struct Memory(Rc<RefCell<Rows>>);
    fn tag(domain: &[u8], binding: &[u8], raw: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        for part in [b"synthetic-contract-key".as_slice(), domain, binding, raw] {
            h.update((part.len() as u64).to_le_bytes());
            h.update(part);
        }
        h.finalize().into()
    }
    impl Store for Memory {
        fn load(&self, domain: &[u8], binding: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
            self.0
                .borrow()
                .get(binding)
                .map(|(raw, mac)| {
                    if tag(domain, binding, raw) != *mac {
                        return Err(Error::Persistence);
                    }
                    Ok(Zeroizing::new(raw.clone()))
                })
                .transpose()
        }
        fn put_new(&self, domain: &[u8], binding: &[u8], record: &[u8]) -> Result<PutNew> {
            let mut rows = self.0.borrow_mut();
            if rows.contains_key(binding) {
                return Ok(PutNew::AlreadyExists);
            }
            rows.insert(
                binding.to_vec(),
                (record.to_vec(), tag(domain, binding, record)),
            );
            Ok(PutNew::Created)
        }
    }
    fn scope(subject: &str) -> Scope {
        let account = AccountScope::new(
            "default".into(),
            "https://example.test/".into(),
            "client".into(),
            Some("https://issuer.test/".into()),
            subject.into(),
        )
        .unwrap();
        let vault =
            VaultSessionScope::new("default", "https://example.test", "space", "vault-root")
                .unwrap();
        Scope::new(
            &serde_json::to_vec(&account).unwrap(),
            &vault,
            "/Travel.vault",
            7,
            42,
            "registered-root-id",
        )
        .unwrap()
    }
    fn baseline(epoch: u64) -> Baseline {
        Baseline::new([1; 16], "\"strong\"", epoch, 11, 7, 90).unwrap()
    }
    fn id() -> CaptureId {
        CaptureId::new("capture-1").unwrap()
    }
    fn capture(store: &impl Store, body: Vec<u8>) -> Result<RetainedEdit> {
        retain(
            store,
            &scope("subject"),
            &id(),
            baseline(3),
            Zeroizing::new(body),
        )
    }
    #[test]
    fn immutable_duplicate_conflict_and_fresh_store_reopen_exact_binary_bytes() {
        let store = Memory::default();
        let bytes = (0..=255).cycle().take(65537).collect::<Vec<u8>>();
        assert!(capture(&store, bytes.clone()).is_ok());
        let original = store.0.borrow().clone();
        assert!(capture(&store, bytes.clone()).is_ok());
        assert!(matches!(
            capture(&store, b"different".to_vec()),
            Err(Error::Conflict)
        ));
        assert!(*store.0.borrow() == original);
        let fresh = Memory(store.0.clone());
        let recovered = reopen_for_recovery(&fresh, &scope("subject"), &id()).unwrap();
        assert_eq!(recovered.bytes_for_recovery(), bytes);
        assert_eq!(recovered.historical_baseline().unlock_epoch, 3);
        assert_eq!(recovered.historical_baseline().token_generation, 11);
        // A changed live epoch is intentionally not an input to recovery.
        // Recovered Baseline is metadata; no Session/Permit/dispatch API exists.
        assert!(matches!(
            retain(
                &fresh,
                &scope("subject"),
                &id(),
                baseline(4),
                Zeroizing::new(bytes)
            ),
            Err(Error::Conflict)
        ));
        assert!(reopen_for_recovery(&fresh, &scope("subject"), &id()).is_ok());
    }
    #[test]
    fn scope_domain_and_tamper_are_refused_without_overwriting_retained_bytes() {
        let store = Memory::default();
        capture(&store, b"dirty body".to_vec()).unwrap();
        assert!(matches!(
            reopen_for_recovery(&store, &scope("foreign"), &id()),
            Err(Error::Missing)
        ));
        let key = binding(&scope("subject"), &id()).unwrap();
        assert!(store.load(b"foreign-domain", &key).is_err());
        let original = store.0.borrow().clone();
        *store
            .0
            .borrow_mut()
            .get_mut(key.as_slice())
            .unwrap()
            .0
            .last_mut()
            .unwrap() ^= 1;
        assert!(matches!(
            reopen_for_recovery(&store, &scope("subject"), &id()),
            Err(Error::Persistence)
        ));
        assert!(store.0.borrow().contains_key(key.as_slice()));
        *store.0.borrow_mut() = original;
        // A structurally valid record authenticated under the WRONG locator
        // remains refused by embedded exact-scope verification too.
        let foreign_key = binding(&scope("foreign"), &id()).unwrap();
        let raw = store.0.borrow().get(key.as_slice()).unwrap().0.clone();
        store.0.borrow_mut().insert(
            foreign_key.to_vec(),
            (raw.clone(), tag(DOMAIN, &foreign_key, &raw)),
        );
        assert!(matches!(
            reopen_for_recovery(&store, &scope("foreign"), &id()),
            Err(Error::Foreign)
        ));
    }
    #[test]
    fn authenticated_malformed_or_cross_domain_records_do_not_confer_authority() {
        let scope = scope("subject");
        let good = encode(&scope, &id(), baseline(3), b"body").unwrap();
        for mode in 0..5 {
            let mut raw = Zeroizing::new(good.to_vec());
            match mode {
                0 => raw[0] ^= 1,
                1 => {
                    *raw.last_mut().unwrap() ^= 1;
                }
                2 => {
                    raw.extend_from_slice(b"extra");
                }
                3 => {
                    let header_len =
                        u32::from_le_bytes(raw[MAGIC.len()..MAGIC.len() + 4].try_into().unwrap())
                            as usize;
                    let mut header: serde_json::Value =
                        serde_json::from_slice(&raw[MAGIC.len() + 4..MAGIC.len() + 4 + header_len])
                            .unwrap();
                    header["domain"] = "foreign".into();
                    let encoded = serde_json::to_vec(&header).unwrap();
                    raw = Zeroizing::new(
                        [
                            MAGIC,
                            &(encoded.len() as u32).to_le_bytes(),
                            &encoded,
                            b"body",
                        ]
                        .concat(),
                    );
                }
                _ => {
                    raw[MAGIC.len()..MAGIC.len() + 4].copy_from_slice(&u32::MAX.to_le_bytes());
                }
            }
            assert!(decode(raw, &scope, &id()).is_err());
        }
    }
    #[test]
    fn size_limit_is_exact_binary_preservation_and_never_truncates_or_writes_overflow() {
        let store = Memory::default();
        let bytes = vec![255; MAX_BODY_BYTES];
        assert_eq!(
            capture(&store, bytes.clone()).unwrap().bytes_for_recovery(),
            bytes
        );
        assert!(
            store
                .0
                .borrow()
                .values()
                .all(|(raw, _)| raw.len() <= MAX_RECORD_BYTES)
        );
        let before = store.0.borrow().clone();
        assert!(matches!(
            capture(&store, vec![0; MAX_BODY_BYTES + 1]),
            Err(Error::Capacity)
        ));
        assert!(*store.0.borrow() == before);
        let empty = Memory::default();
        assert!(
            capture(&empty, vec![])
                .unwrap()
                .bytes_for_recovery()
                .is_empty()
        );
    }
    #[test]
    fn invalid_etags_counters_and_capture_ids_never_reach_storage() {
        for etag in [
            "weak",
            "W/\"weak\"",
            "\"bad quote\"",
            "\"bad\n\"",
            "\"bad\"quote\"",
        ] {
            assert!(Baseline::new([1; 16], etag, 1, 1, 7, 90).is_err());
        }
        assert!(Baseline::new([0; 16], "\"strong\"", 1, 1, 7, 90).is_err());
        assert!(Baseline::new([1; 16], "\"strong\"", 0, 1, 7, 90).is_err());
        assert!(Baseline::new([1; 16], "\"strong\"", 1, 0, 7, 90).is_err());
        assert!(Baseline::new([1; 16], "\"strong\"", 1, 1, 0, 90).is_err());
        assert!(Baseline::new([1; 16], "\"strong\"", 1, 1, 7, 0).is_err());
        for bad in ["", "../escape", "line\n", "a/b", "a b", &"x".repeat(129)] {
            assert!(CaptureId::new(bad).is_err());
        }
    }
    #[test]
    fn uncertain_publication_retains_dirty_bytes_but_returns_no_success() {
        struct Uncertain(Memory);
        impl Store for Uncertain {
            fn load(&self, domain: &[u8], binding: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
                self.0.load(domain, binding)
            }
            fn put_new(&self, domain: &[u8], binding: &[u8], record: &[u8]) -> Result<PutNew> {
                self.0.put_new(domain, binding, record)?;
                Err(Error::Persistence)
            }
        }
        let store = Uncertain(Memory::default());
        assert!(matches!(
            capture(&store, b"dirty bytes".to_vec()),
            Err(Error::Persistence)
        ));
        let recovered = reopen_for_recovery(&store.0, &scope("subject"), &id()).unwrap();
        assert_eq!(recovered.bytes_for_recovery(), b"dirty bytes");
        assert_eq!(recovered.historical_baseline().unlock_epoch, 3);
    }
}

//! Protected local-disposition metadata. Descriptors/status are historical data;
//! only opaque native proofs plus a fresh preparation ticket change disposition.
pub(crate) type PreparedDisposition = super::vault_custody::PreparedDisposition;
use super::{
    vault_custody::{CaptureRef, Entry, Hydration, Scope},
    vault_edit_capture::{self as capture, RetainedEdit},
    vault_edit_upload::HistoricalReadbackEvidence,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Invalid,
    Foreign,
    Conflict,
    Persistence,
}
pub(crate) type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DispositionDescriptor {
    scope: Scope,
    reference: CaptureRef,
    hydration: Hydration,
    body_len: u64,
    body_sha256: [u8; 32],
}
impl DispositionDescriptor {
    pub(crate) fn from_capture(
        scope: &Scope,
        reference: &CaptureRef,
        hydration: &Hydration,
        retained: &RetainedEdit,
    ) -> Result<Self> {
        validate_retained_capture(scope, reference, retained)?;
        let baseline = retained.historical_baseline();
        if baseline.native_volume() != scope.native_root().0
            || baseline.native_file() != hydration.file_index()
        {
            return Err(Error::Foreign);
        }
        let value = Self {
            scope: scope.clone(),
            reference: reference.clone(),
            hydration: hydration.clone(),
            body_len: retained.bytes_for_recovery().len() as u64,
            body_sha256: Sha256::digest(retained.bytes_for_recovery()).into(),
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.scope
            .authenticated_store_binding()
            .map_err(|_| Error::Invalid)?;
        self.reference
            .frame()
            .validate()
            .map_err(|_| Error::Invalid)?;
        self.hydration
            .validate_for_entry(self.reference.entry())
            .map_err(|_| Error::Invalid)?;
        if self.body_len > capture::MAX_BODY_BYTES as u64
            || self.body_sha256 == [0; 32]
            || !capture::strong_etag(self.reference.entry().etag())
            || self.reference.entry().is_directory()
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub(crate) fn scope(&self) -> &Scope {
        &self.scope
    }
    pub(crate) fn scope_binding(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.scope
            .authenticated_store_binding()
            .map_err(|_| Error::Invalid)
    }
    pub(crate) fn reference(&self) -> &CaptureRef {
        &self.reference
    }
    pub(crate) fn original_entry(&self) -> &Entry {
        self.reference.entry()
    }
    pub(crate) fn hydration(&self) -> &Hydration {
        &self.hydration
    }
    pub(crate) fn body_len(&self) -> u64 {
        self.body_len
    }
    pub(crate) fn body_sha256(&self) -> [u8; 32] {
        self.body_sha256
    }
}
/// Semantic check after the store has authenticated and decoded the full body.
/// Used during promoted history reconstruction; never creates native authority.
pub(crate) fn validate_retained_capture(
    scope: &Scope,
    reference: &CaptureRef,
    retained: &RetainedEdit,
) -> Result<()> {
    let baseline = retained.historical_baseline();
    if retained.scope() != scope
        || retained.capture_id() != reference.id()
        || retained.encoded_frame_ref() != reference.frame()
        || baseline.opaque_file() != reference.entry().opaque()
        || baseline.strong_etag() != reference.entry().etag()
    {
        return Err(Error::Foreign);
    }
    Ok(())
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Phase {
    Prepared {},
    NativeCompleted {},
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DispositionRow {
    descriptor: DispositionDescriptor,
    verified: Entry,
    promoted_hydration: Hydration,
    phase: Phase,
}
impl DispositionRow {
    pub(crate) fn prepared(descriptor: DispositionDescriptor, verified: Entry) -> Result<Self> {
        let promoted_hydration = descriptor.hydration.with_verified_length(verified.length());
        let row = Self {
            descriptor,
            verified,
            promoted_hydration,
            phase: Phase::Prepared {},
        };
        row.validate()?;
        Ok(row)
    }
    fn validate(&self) -> Result<()> {
        self.descriptor.validate()?;
        let old = self.descriptor.original_entry();
        let new = &self.verified;
        Entry::new(
            new.opaque(),
            new.remote_id(),
            new.root_relative_path(),
            new.etag(),
            new.is_directory(),
            new.length(),
        )
        .map_err(|_| Error::Invalid)?;
        self.promoted_hydration
            .validate_for_entry(new)
            .map_err(|_| Error::Invalid)?;
        if old.opaque() != new.opaque()
            || old.remote_id() != new.remote_id()
            || old.root_relative_path() != new.root_relative_path()
            || new.is_directory()
            || !capture::strong_etag(new.etag())
            || new.etag() == old.etag()
            || new.length() != self.descriptor.body_len
            || self.promoted_hydration.file_index() != self.descriptor.hydration.file_index()
            || self.promoted_hydration.components() != self.descriptor.hydration.components()
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub(crate) fn validate_bound(
        &self,
        scope: &Scope,
        reference: &CaptureRef,
        evidence: &HistoricalReadbackEvidence,
    ) -> Result<()> {
        self.validate()?;
        if self.descriptor.scope() != scope
            || self.reference() != reference
            || evidence.resource_id() != self.verified.remote_id()
            || evidence.etag() != self.verified.etag()
            || evidence.body_len() as u64 != self.descriptor.body_len
            || evidence.body_sha256() != self.descriptor.body_sha256
        {
            return Err(Error::Foreign);
        }
        Ok(())
    }
    pub(crate) fn descriptor(&self) -> &DispositionDescriptor {
        &self.descriptor
    }
    pub(crate) fn reference(&self) -> &CaptureRef {
        self.descriptor.reference()
    }
    pub(crate) fn verified_entry(&self) -> &Entry {
        &self.verified
    }
    pub(crate) fn promoted_hydration(&self) -> &Hydration {
        &self.promoted_hydration
    }
    pub(crate) fn is_native_completed(&self) -> bool {
        matches!(self.phase, Phase::NativeCompleted {})
    }
    pub(crate) fn completed(&self) -> Self {
        let mut next = self.clone();
        next.phase = Phase::NativeCompleted {};
        next
    }
}
/// Read-only persisted evidence, not a native or preparation capability.
#[cfg(test)]
pub(crate) type DispositionStatus = DispositionRow;

#[cfg(windows)]
macro_rules! native_matches {
    ($d:expr,$p:expr) => {{
        let d = $d;
        let p = $p;
        p.scope_binding() == d.scope_binding()?.as_slice()
            && p.capture_id() == d.reference().id()
            && p.frame_sha256() == d.reference().frame().sha256()
            && p.frame_len() == d.reference().frame().length() as u64
            && (p.root().volume_serial, p.root().file_index) == d.scope().native_root()
            && p.identity() == d.original_entry().opaque()
            && p.local_file().volume_serial == d.scope().native_root().0
            && p.local_file().file_index == d.hydration().file_index()
            && p.components() == d.hydration().components()
            && p.body_len() == d.body_len()
            && p.body_sha256() == d.body_sha256()
            && p.original().id == d.original_entry().remote_id()
            && p.original().path == d.original_entry().root_relative_path()
            && p.original().etag == d.original_entry().etag()
            && p.original().size == d.original_entry().length()
            && !p.original().directory
    }};
}
#[cfg(windows)]
pub(crate) fn preparation_entry(
    descriptor: &DispositionDescriptor,
    proof: &raiun_cloudfiles_windows::VaultNativePreparation,
) -> Result<Entry> {
    if !native_matches!(descriptor, proof) {
        return Err(Error::Foreign);
    }
    let new = proof.verified();
    let entry = Entry::new(
        proof.identity(),
        &new.id,
        &new.path,
        &new.etag,
        new.directory,
        new.size,
    )
    .map_err(|_| Error::Invalid)?;
    DispositionRow::prepared(descriptor.clone(), entry.clone())?;
    Ok(entry)
}
#[cfg(windows)]
pub(crate) fn completion_matches(
    row: &DispositionRow,
    proof: &raiun_cloudfiles_windows::VaultNativeCompletionProof,
) -> Result<()> {
    let new = proof.verified();
    let expected = row.verified_entry();
    if !native_matches!(row.descriptor(), proof)
        || new.id != expected.remote_id()
        || new.path != expected.root_relative_path()
        || new.etag != expected.etag()
        || new.size != expected.length()
        || new.directory
    {
        return Err(Error::Foreign);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{
        root_manifest::{self, RootBinding, RootManifest},
        vault_custody::{self as custody, Custody},
        vault_edit_capture::{Baseline, CaptureId, PreparedCapture},
        vault_edit_upload::{self as upload, UploadAttempt},
    };
    use super::*;
    use raiun_engine::folder_pairs::AccountScope;
    use raiun_vault::session::VaultSessionScope;
    use std::{
        cell::{Cell, RefCell},
        collections::BTreeMap,
    };
    #[derive(Default)]
    struct Memory {
        child: RefCell<Option<Zeroizing<Vec<u8>>>>,
        roots: RefCell<BTreeMap<Vec<u8>, Zeroizing<Vec<u8>>>>,
        bodies: RefCell<BTreeMap<Vec<u8>, Zeroizing<Vec<u8>>>>,
        uncertain: Cell<bool>,
    }
    impl custody::Store for Memory {
        fn load(
            &self,
            _: &Scope,
        ) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, custody::Error> {
            Ok(self.child.borrow().clone())
        }
        fn compare_exchange(
            &self,
            _: &Scope,
            old: Option<&[u8]>,
            new: &[u8],
        ) -> std::result::Result<(), custody::Error> {
            if self.child.borrow().as_ref().map(|v| v.as_slice()) != old {
                return Err(custody::Error::Conflict);
            }
            *self.child.borrow_mut() = Some(Zeroizing::new(new.to_vec()));
            if self.uncertain.get() {
                return Err(custody::Error::Persistence);
            }
            Ok(())
        }
    }
    impl root_manifest::Store for Memory {
        fn load(
            &self,
            key: &[u8],
        ) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, custody::Error> {
            Ok(self.roots.borrow().get(key).cloned())
        }
        fn compare_exchange(
            &self,
            key: &[u8],
            old: Option<&[u8]>,
            new: &[u8],
        ) -> std::result::Result<(), custody::Error> {
            if self.roots.borrow().get(key).map(|v| v.as_slice()) != old {
                return Err(custody::Error::Conflict);
            }
            self.roots
                .borrow_mut()
                .insert(key.to_vec(), Zeroizing::new(new.to_vec()));
            Ok(())
        }
    }
    impl capture::Store for Memory {
        fn load(
            &self,
            _: &[u8],
            key: &[u8],
        ) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, capture::Error> {
            Ok(self.bodies.borrow().get(key).cloned())
        }
        fn put_new(
            &self,
            _: &[u8],
            key: &[u8],
            record: &[u8],
        ) -> std::result::Result<capture::PutNew, capture::Error> {
            if self.bodies.borrow().contains_key(key) {
                return Ok(capture::PutNew::AlreadyExists);
            }
            self.bodies
                .borrow_mut()
                .insert(key.to_vec(), Zeroizing::new(record.to_vec()));
            Ok(capture::PutNew::Created)
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
            VaultSessionScope::new("default", "https://example.test", "space", "vault-root")
                .unwrap();
        Scope::new(
            &serde_json::to_vec(&account).unwrap(),
            &vault,
            "/Travel.vault",
            7,
            42,
            "registration",
        )
        .unwrap()
    }
    fn entry(etag: &str, len: u64) -> Entry {
        Entry::new([1; 16], "remote-file", "/1", etag, false, len).unwrap()
    }
    fn fixture() -> (Memory, Scope, Custody) {
        let store = Memory::default();
        let scope = scope("subject");
        let root = RootBinding::from_scope(&scope).unwrap();
        let mut manifest = RootManifest::initialize_new_registration(&store, &root).unwrap();
        manifest.register(&store, &scope).unwrap();
        let child = Custody::initialize_new_scope(&store, scope.clone()).unwrap();
        (store, scope, child)
    }
    fn captured(
        store: &Memory,
        scope: &Scope,
        child: &mut Custody,
        id: &str,
        old: &Entry,
        body: &[u8],
        etag: &str,
    ) -> (DispositionDescriptor, Entry) {
        child.record_entry(store, old.clone()).unwrap();
        child
            .persist_hydration_intent(
                store,
                [1; 16],
                90,
                old.length(),
                vec!["Personal".into(), "Travel.vault".into(), "1".into()],
            )
            .unwrap();
        let prepared = PreparedCapture::new(
            scope,
            &CaptureId::new(id).unwrap(),
            Baseline::new([1; 16], old.etag(), 3, 11, 7, 90).unwrap(),
            Zeroizing::new(body.to_vec()),
        )
        .unwrap();
        let custody::CaptureEnrollment::New(ticket) = child
            .enroll_capture(
                store,
                &prepared,
                &["Personal".into(), "Travel.vault".into(), "1".into()],
            )
            .unwrap()
        else {
            panic!("fresh capture")
        };
        let retained = capture::persist_prepared_new(store, prepared, ticket).unwrap();
        let reference = child
            .captures_for_reconciliation()
            .iter()
            .find(|reference| reference.id() == id)
            .unwrap()
            .clone();
        let root = RootBinding::from_scope(scope).unwrap();
        let ledger = upload::CustodyLedger::admit(store, &root, scope, &reference).unwrap();
        let mut attempt =
            UploadAttempt::initialize(&ledger, store, scope, &reference, old).unwrap();
        let ticket = attempt.begin_attempt(&ledger).unwrap();
        attempt
            .record_readback_evidence(&ledger, ticket, old.remote_id(), etag, etag, body)
            .unwrap();
        *child = Custody::reopen(store, scope).unwrap();
        (
            child.disposition_descriptor(&reference, &retained).unwrap(),
            entry(etag, body.len() as u64),
        )
    }
    #[test]
    fn preparation_promotes_atomically_and_only_fresh_ticket_completes_exact_native_result() {
        let (s, scope, mut child) = fixture();
        let (descriptor, new) = captured(
            &s,
            &scope,
            &mut child,
            "capture-1",
            &entry("\"old\"", 4),
            b"edited bytes",
            "\"new\"",
        );
        let bodies = s.bodies.borrow().clone();
        let reference = descriptor.reference().clone();
        let ticket = child
            .prepare_disposition_for_test(&s, &descriptor, new.clone())
            .unwrap();
        let reopened = Custody::reopen(&s, &scope).unwrap();
        assert!(reopened.entries_for_reconciliation().contains(&new));
        let status = reopened.local_disposition(&reference).unwrap().unwrap();
        assert!(!status.is_native_completed());
        assert_eq!(status.promoted_hydration().length(), 12);
        assert!(status.reference() == &reference);
        assert!(reopened.publication_history().is_err());
        let mut reopened = Custody::reopen(&s, &scope).unwrap();
        assert!(
            reopened
                .prepare_disposition_for_test(&s, &descriptor, new)
                .is_err(),
            "stored Prepared cannot mint another ticket"
        );
        reopened.complete_disposition_for_test(&s, ticket).unwrap();
        let history = reopened.publication_history().unwrap();
        assert_eq!(history[0].length(), 12);
        assert!(
            reopened
                .local_disposition(&reference)
                .unwrap()
                .unwrap()
                .is_native_completed()
        );
        assert!(s.bodies.borrow().eq(&bodies));
    }
    #[test]
    fn old_versions_reopen_byte_exact_and_failed_or_stale_preparation_keeps_new_validator_pending()
    {
        let (s, scope, mut child) = fixture();
        let (descriptor, new) = captured(
            &s,
            &scope,
            &mut child,
            "capture-1",
            &entry("\"old\"", 4),
            b"edited bytes",
            "\"new\"",
        );
        let value: serde_json::Value =
            serde_json::from_slice(s.child.borrow().as_ref().unwrap()).unwrap();
        for version in [1, 2, 3] {
            let mut old = value.clone();
            old["version"] = version.into();
            if version < 3 {
                old.as_object_mut().unwrap().remove("upload_attempts");
            }
            if version < 2 {
                old.as_object_mut().unwrap().remove("capture_refs");
            }
            let mut raw = b" \n".to_vec();
            raw.extend_from_slice(&serde_json::to_vec(&old).unwrap());
            raw.extend_from_slice(b"\n ");
            *s.child.borrow_mut() = Some(Zeroizing::new(raw.clone()));
            Custody::reopen(&s, &scope).unwrap();
            assert!(s.child.borrow().as_ref().unwrap().as_slice() == raw);
        }
        *s.child.borrow_mut() = Some(Zeroizing::new(serde_json::to_vec(&value).unwrap()));
        child = Custody::reopen(&s, &scope).unwrap();
        s.uncertain.set(true);
        assert!(
            child
                .prepare_disposition_for_test(&s, &descriptor, new.clone())
                .is_err()
        );
        s.uncertain.set(false);
        let mut fresh = Custody::reopen(&s, &scope).unwrap();
        assert!(fresh.entries_for_reconciliation().contains(&new));
        assert!(fresh.publication_history().is_err());
        assert!(
            fresh
                .prepare_disposition_for_test(&s, &descriptor, new)
                .is_err()
        );
        let (s, scope, mut child) = fixture();
        let (descriptor, new) = captured(
            &s,
            &scope,
            &mut child,
            "capture-1",
            &entry("\"old\"", 4),
            b"edited bytes",
            "\"new\"",
        );
        let ticket = child
            .prepare_disposition_for_test(&s, &descriptor, new)
            .unwrap();
        child.record_entries(&s, &[]).unwrap();
        assert!(child.complete_disposition_for_test(&s, ticket).is_err());
        assert!(child.publication_history().is_err());
    }
    #[test]
    fn sequential_completed_chains_preserve_old_refs_and_other_prepared_or_unrecorded_capture_blocks_history()
     {
        let (s, scope, mut child) = fixture();
        let (first, b) = captured(
            &s,
            &scope,
            &mut child,
            "capture-1",
            &entry("\"a\"", 4),
            b"edited bytes",
            "\"b\"",
        );
        let first_ref = first.reference().clone();
        let ticket = child
            .prepare_disposition_for_test(&s, &first, b.clone())
            .unwrap();
        child.complete_disposition_for_test(&s, ticket).unwrap();
        let (second, c) = captured(
            &s,
            &scope,
            &mut child,
            "capture-2",
            &b,
            b"second edit has another length",
            "\"c\"",
        );
        assert!(child.publication_history().is_err());
        let ticket = child
            .prepare_disposition_for_test(&s, &second, c.clone())
            .unwrap();
        assert!(child.publication_history().is_err());
        child.complete_disposition_for_test(&s, ticket).unwrap();
        assert_eq!(child.publication_history().unwrap()[0].length(), c.length());
        assert!(child.captures_for_reconciliation().contains(&first_ref));
        let prepared = PreparedCapture::new(
            &scope,
            &CaptureId::new("index-only").unwrap(),
            Baseline::new([1; 16], c.etag(), 3, 11, 7, 90).unwrap(),
            Zeroizing::new(b"not yet recorded".to_vec()),
        )
        .unwrap();
        child
            .enroll_capture(
                &s,
                &prepared,
                &["Personal".into(), "Travel.vault".into(), "1".into()],
            )
            .unwrap();
        assert!(
            Custody::reopen(&s, &scope)
                .unwrap()
                .publication_history()
                .is_err()
        );
    }
    #[test]
    fn foreign_scope_frame_and_unverified_versions_cannot_prepare() {
        let (s, scope, mut child) = fixture();
        let (descriptor, new) = captured(
            &s,
            &scope,
            &mut child,
            "capture-1",
            &entry("\"old\"", 4),
            b"edited bytes",
            "\"new\"",
        );
        let old = s.child.borrow().clone().unwrap();
        let retained = capture::reopen_for_recovery(
            &s,
            &scope,
            &CaptureId::new(descriptor.reference().id()).unwrap(),
        )
        .unwrap();
        let mut wrong_hydration = serde_json::to_value(descriptor.hydration()).unwrap();
        wrong_hydration["file_index"] = 91.into();
        let wrong_hydration: Hydration = serde_json::from_value(wrong_hydration).unwrap();
        assert!(
            DispositionDescriptor::from_capture(
                &scope,
                descriptor.reference(),
                &wrong_hydration,
                &retained
            )
            .is_err()
        );
        let mut value = serde_json::to_value(&descriptor).unwrap();
        value["scope"] = serde_json::to_value(self::scope("foreign")).unwrap();
        let foreign: DispositionDescriptor = serde_json::from_value(value).unwrap();
        assert!(
            child
                .prepare_disposition_for_test(&s, &foreign, new.clone())
                .is_err()
        );
        let mut value = serde_json::to_value(&descriptor).unwrap();
        value["reference"]["frame"]["length"] = 1.into();
        let foreign: DispositionDescriptor = serde_json::from_value(value).unwrap();
        assert!(
            child
                .prepare_disposition_for_test(&s, &foreign, new)
                .is_err()
        );
        assert!(
            child
                .prepare_disposition_for_test(&s, &descriptor, entry("\"not-the-readback\"", 12))
                .is_err()
        );
        assert!(s.child.borrow().as_ref().unwrap().as_slice() == old.as_slice());
        let mut wrong_ref = serde_json::to_value(descriptor.reference()).unwrap();
        wrong_ref["frame"]["length"] = 1.into();
        let wrong_ref: CaptureRef = serde_json::from_value(wrong_ref).unwrap();
        assert!(validate_retained_capture(&scope, &wrong_ref, &retained).is_err());
        s.bodies.borrow_mut().clear();
        assert!(
            capture::reopen_for_recovery(
                &s,
                &scope,
                &CaptureId::new(descriptor.reference().id()).unwrap()
            )
            .is_err()
        );
        assert!(s.child.borrow().as_ref().unwrap().as_slice() == old.as_slice());
    }
    #[test]
    fn strict_v4_null_empty_duplicate_unknown_and_broken_chain_refuse_without_repair() {
        let (s, scope, mut child) = fixture();
        let (descriptor, new) = captured(
            &s,
            &scope,
            &mut child,
            "capture-1",
            &entry("\"old\"", 4),
            b"edited bytes",
            "\"new\"",
        );
        child
            .prepare_disposition_for_test(&s, &descriptor, new)
            .unwrap();
        let good: serde_json::Value =
            serde_json::from_slice(s.child.borrow().as_ref().unwrap()).unwrap();
        for bad in 0..7 {
            let mut value = good.clone();
            match bad {
                0 => value["dispositions"] = serde_json::Value::Null,
                1 => value["dispositions"] = serde_json::json!([]),
                2 => {
                    let row = value["dispositions"][0].clone();
                    value["dispositions"].as_array_mut().unwrap().push(row);
                }
                3 => value["dispositions"][0]["phase"]["extra"] = true.into(),
                4 => {
                    value["dispositions"][0]["descriptor"]["body_sha256"] =
                        serde_json::to_value([0u8; 32]).unwrap()
                }
                5 => value["catalogue"][0]["etag"] = "\"other\"".into(),
                _ => value["version"] = 3.into(),
            }
            let raw = Zeroizing::new(serde_json::to_vec(&value).unwrap());
            *s.child.borrow_mut() = Some(raw.clone());
            assert!(Custody::reopen(&s, &scope).is_err());
            assert!(s.child.borrow().as_ref().unwrap().as_slice() == raw.as_slice());
        }
    }
    #[test]
    fn reconstructed_body_rejects_native_or_digest_tuple_internally_consistent_on_wire() {
        let (s, scope, mut child) = fixture();
        let (descriptor, new) = captured(
            &s,
            &scope,
            &mut child,
            "capture-1",
            &entry("\"old\"", 4),
            b"edited bytes",
            "\"new\"",
        );
        let ticket = child
            .prepare_disposition_for_test(&s, &descriptor, new)
            .unwrap();
        child.complete_disposition_for_test(&s, ticket).unwrap();
        let retained = capture::reopen_for_recovery(
            &s,
            &scope,
            &CaptureId::new(descriptor.reference().id()).unwrap(),
        )
        .unwrap();
        child
            .validate_reconstructed_disposition(descriptor.reference(), &retained)
            .unwrap();
        let good: serde_json::Value =
            serde_json::from_slice(s.child.borrow().as_ref().unwrap()).unwrap();
        let mut wrong_native = good.clone();
        wrong_native["dispositions"][0]["descriptor"]["hydration"]["file_index"] = 91.into();
        wrong_native["dispositions"][0]["promoted_hydration"]["file_index"] = 91.into();
        wrong_native["pending"][0]["file_index"] = 91.into();
        *s.child.borrow_mut() = Some(Zeroizing::new(serde_json::to_vec(&wrong_native).unwrap()));
        let fresh = Custody::reopen(&s, &scope).unwrap();
        assert!(
            fresh
                .validate_reconstructed_disposition(descriptor.reference(), &retained)
                .is_err()
        );
        let mut wrong_digest = good;
        wrong_digest["dispositions"][0]["descriptor"]["body_sha256"] =
            serde_json::to_value([1u8; 32]).unwrap();
        let bytes: Vec<u8> =
            serde_json::from_value(wrong_digest["upload_attempts"][0]["record"].clone()).unwrap();
        let mut attempt: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        attempt["binding"]["body_sha256"] = serde_json::to_value([1u8; 32]).unwrap();
        attempt["state"]["evidence"]["body_sha256"] = serde_json::to_value([1u8; 32]).unwrap();
        wrong_digest["upload_attempts"][0]["record"] =
            serde_json::to_value(serde_json::to_vec(&attempt).unwrap()).unwrap();
        *s.child.borrow_mut() = Some(Zeroizing::new(serde_json::to_vec(&wrong_digest).unwrap()));
        let fresh = Custody::reopen(&s, &scope).unwrap();
        assert!(
            fresh
                .validate_reconstructed_disposition(descriptor.reference(), &retained)
                .is_err()
        );
    }
}

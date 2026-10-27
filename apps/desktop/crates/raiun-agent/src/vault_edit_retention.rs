//! Index-first historical retention only. Callers still need independent live
//! account/root/session/native leases; this service never creates that authority.
use super::{vault_custody as custody, vault_edit_capture as capture};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Custody(custody::Error),
    Capture(capture::Error),
}
/// A fresh notification is eligible only for this invocation's acknowledged
/// new index and immutable-body publication. Reopened history is never fresh.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RetentionOutcome {
    New,
    Existing,
}
/// Only acknowledged new enrollment permits a body put. Existing/recovered
/// references can reopen and compare; missing bodies are never healed here.
pub(crate) fn retain_indexed(
    custody_store: &impl custody::Store,
    child: &mut custody::Custody,
    body_store: &impl capture::Store,
    prepared: capture::PreparedCapture,
    native_components: &[String],
) -> Result<RetentionOutcome, Error> {
    match child
        .enroll_capture(custody_store, &prepared, native_components)
        .map_err(Error::Custody)?
    {
        custody::CaptureEnrollment::New(ticket) => {
            // This includes exact full-frame/body readback; publication errors,
            // collisions and uncertain persistence never produce New.
            capture::persist_prepared_new(body_store, prepared, ticket).map_err(Error::Capture)?;
            Ok(RetentionOutcome::New)
        }
        custody::CaptureEnrollment::Existing(reference) => {
            let id = capture::CaptureId::new(reference.id()).map_err(Error::Capture)?;
            let retained = capture::reopen_for_recovery(body_store, prepared.scope(), &id)
                .map_err(Error::Capture)?;
            if retained.encoded_frame_ref() != reference.frame() {
                return Err(Error::Capture(capture::Error::Conflict));
            }
            Ok(RetentionOutcome::Existing)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use capture::{Baseline, CaptureId, PreparedCapture};
    use raiun_engine::folder_pairs::AccountScope;
    use raiun_vault::session::VaultSessionScope;
    use serde::Deserialize;
    use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
    use zeroize::Zeroizing;

    /// Trusted-store semantic simulator only; the unchanged native protected
    /// store's authentication/domain behavior has separate OS evidence.
    #[derive(Default)]
    struct State {
        child: Option<Zeroizing<Vec<u8>>>,
        bodies: BTreeMap<Vec<u8>, Zeroizing<Vec<u8>>>,
        writes: Vec<&'static str>,
        uncertain_index: bool,
        fail_body: bool,
        uncertain_body_after_publication: bool,
        corrupt_body_after_publication: bool,
    }
    #[derive(Clone, Default)]
    struct Memory(Rc<RefCell<State>>);
    impl custody::Store for Memory {
        fn load(&self, _: &custody::Scope) -> Result<Option<Zeroizing<Vec<u8>>>, custody::Error> {
            Ok(self.0.borrow().child.clone())
        }
        fn compare_exchange(
            &self,
            _: &custody::Scope,
            old: Option<&[u8]>,
            next: &[u8],
        ) -> Result<(), custody::Error> {
            let mut s = self.0.borrow_mut();
            if s.child.as_ref().map(|v| v.as_slice()) != old {
                return Err(custody::Error::Conflict);
            }
            s.writes.push("index");
            s.child = Some(Zeroizing::new(next.to_vec()));
            if s.uncertain_index {
                return Err(custody::Error::Persistence);
            }
            Ok(())
        }
    }
    impl capture::Store for Memory {
        fn load(
            &self,
            _: &[u8],
            binding: &[u8],
        ) -> Result<Option<Zeroizing<Vec<u8>>>, capture::Error> {
            Ok(self.0.borrow().bodies.get(binding).cloned())
        }
        fn put_new(
            &self,
            _: &[u8],
            binding: &[u8],
            body: &[u8],
        ) -> Result<capture::PutNew, capture::Error> {
            let mut s = self.0.borrow_mut();
            if s.fail_body {
                return Err(capture::Error::Persistence);
            }
            if s.bodies.contains_key(binding) {
                return Ok(capture::PutNew::AlreadyExists);
            }
            s.writes.push("body");
            let mut published = body.to_vec();
            if s.corrupt_body_after_publication {
                *published.last_mut().unwrap() ^= 1;
            }
            s.bodies.insert(binding.to_vec(), Zeroizing::new(published));
            if s.uncertain_body_after_publication {
                return Err(capture::Error::Persistence);
            }
            Ok(capture::PutNew::Created)
        }
    }
    fn scope(subject: &str) -> custody::Scope {
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
        custody::Scope::new(
            &serde_json::to_vec(&account).unwrap(),
            &vault,
            "/Travel.vault",
            7,
            42,
            "registration",
        )
        .unwrap()
    }
    fn components() -> Vec<String> {
        vec!["Personal".into(), "Travel.vault".into(), "1".into()]
    }
    fn prepared(scope: &custody::Scope, id: &str, body: &[u8]) -> PreparedCapture {
        PreparedCapture::new(
            scope,
            &CaptureId::new(id).unwrap(),
            Baseline::new([1; 16], "\"base\"", 3, 11, 7, 90).unwrap(),
            Zeroizing::new(body.to_vec()),
        )
        .unwrap()
    }
    fn fixture() -> (Memory, custody::Scope, custody::Custody) {
        let s = Memory::default();
        let scope = scope("subject");
        let mut child = custody::Custody::initialize_new_scope(&s, scope.clone()).unwrap();
        child
            .record_entry(
                &s,
                custody::Entry::new([1; 16], "remote-file", "/1", "\"base\"", false, 4).unwrap(),
            )
            .unwrap();
        child
            .persist_hydration_intent(&s, [1; 16], 90, 4, components())
            .unwrap();
        s.0.borrow_mut().writes.clear();
        (s, scope, child)
    }
    #[test]
    fn enrollment_precedes_body_and_exact_existing_frame_is_read_only_and_still_pending() {
        let (s, scope, mut child) = fixture();
        let bytes = b"edited length differs from baseline";
        let retained = retain_indexed(
            &s,
            &mut child,
            &s,
            prepared(&scope, "capture-1", bytes),
            &components(),
        )
        .unwrap();
        assert_eq!(retained, RetentionOutcome::New);
        assert_eq!(
            capture::reopen_for_recovery(&s, &scope, &CaptureId::new("capture-1").unwrap())
                .unwrap()
                .bytes_for_recovery(),
            bytes
        );
        assert_eq!(s.0.borrow().writes, ["index", "body"]);
        assert!(matches!(
            child.publication_history(),
            Err(custody::Error::Incomplete)
        ));
        let mut fresh = custody::Custody::reopen(&s, &scope).unwrap();
        assert_eq!(fresh.captures_for_reconciliation().len(), 1);
        s.0.borrow_mut().writes.clear();
        let recovered = retain_indexed(
            &s,
            &mut fresh,
            &s,
            prepared(&scope, "capture-1", bytes),
            &components(),
        )
        .unwrap();
        assert_eq!(recovered, RetentionOutcome::Existing);
        assert_eq!(
            capture::reopen_for_recovery(&s, &scope, &CaptureId::new("capture-1").unwrap())
                .unwrap()
                .bytes_for_recovery(),
            bytes
        );
        assert!(s.0.borrow().writes.is_empty());
        assert!(matches!(
            fresh.publication_history(),
            Err(custody::Error::Incomplete)
        ));
    }
    #[test]
    fn published_but_uncertain_or_wrong_readback_never_becomes_a_new_close() {
        for corrupt in [false, true] {
            let (s, scope, mut child) = fixture();
            s.0.borrow_mut().uncertain_body_after_publication = !corrupt;
            s.0.borrow_mut().corrupt_body_after_publication = corrupt;
            assert!(
                retain_indexed(
                    &s,
                    &mut child,
                    &s,
                    prepared(&scope, "capture-1", b"retained bytes"),
                    &components(),
                )
                .is_err()
            );
            assert_eq!(child.captures_for_reconciliation().len(), 1);
            assert_eq!(s.0.borrow().bodies.len(), 1);
            let body_before = s.0.borrow().bodies.clone();
            s.0.borrow_mut().uncertain_body_after_publication = false;
            s.0.borrow_mut().corrupt_body_after_publication = false;
            s.0.borrow_mut().writes.clear();
            let mut reopened = custody::Custody::reopen(&s, &scope).unwrap();
            let result = retain_indexed(
                &s,
                &mut reopened,
                &s,
                prepared(&scope, "capture-1", b"retained bytes"),
                &components(),
            );
            if corrupt {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap(), RetentionOutcome::Existing);
            }
            assert!(s.0.borrow().writes.is_empty());
            assert!(s.0.borrow().bodies == body_before);
            assert!(reopened.publication_history().is_err());
        }
    }
    #[test]
    fn crash_after_enrollment_and_uncertain_cas_never_fill_a_recovered_missing_body() {
        for uncertain in [false, true] {
            let (s, scope, mut child) = fixture();
            s.0.borrow_mut().uncertain_index = uncertain;
            let result =
                child.enroll_capture(&s, &prepared(&scope, "capture-1", b"dirty"), &components());
            if uncertain {
                assert!(matches!(result, Err(custody::Error::Persistence)));
            } else {
                assert!(matches!(result, Ok(custody::CaptureEnrollment::New(_))));
            }
            // Dropping a fresh ticket simulates a crash before body publication.
            // Uncertain CAS cannot return any ticket in the first place.
            assert!(s.0.borrow().bodies.is_empty());
            s.0.borrow_mut().uncertain_index = false;
            let mut recovered = custody::Custody::reopen(&s, &scope).unwrap();
            assert_eq!(recovered.captures_for_reconciliation().len(), 1);
            s.0.borrow_mut().writes.clear();
            assert!(matches!(
                retain_indexed(
                    &s,
                    &mut recovered,
                    &s,
                    prepared(&scope, "capture-1", b"dirty"),
                    &components()
                ),
                Err(Error::Capture(capture::Error::Missing))
            ));
            assert!(s.0.borrow().writes.is_empty());
            assert!(matches!(
                recovered.publication_history(),
                Err(custody::Error::Incomplete)
            ));
        }
    }
    #[test]
    fn failed_body_and_conflicting_or_foreign_context_preserve_the_index_and_original_bytes() {
        let (s, scope, mut child) = fixture();
        s.0.borrow_mut().fail_body = true;
        assert!(matches!(
            retain_indexed(
                &s,
                &mut child,
                &s,
                prepared(&scope, "capture-1", b"dirty"),
                &components()
            ),
            Err(Error::Capture(capture::Error::Persistence))
        ));
        assert_eq!(child.captures_for_reconciliation().len(), 1);
        let before = s.0.borrow().child.clone().unwrap();
        s.0.borrow_mut().fail_body = false;
        let mut recovered = custody::Custody::reopen(&s, &scope).unwrap();
        assert_eq!(recovered.captures_for_reconciliation().len(), 1);
        assert!(matches!(
            recovered.publication_history(),
            Err(custody::Error::Incomplete)
        ));
        s.0.borrow_mut().writes.clear();
        assert!(matches!(
            retain_indexed(
                &s,
                &mut recovered,
                &s,
                prepared(&scope, "capture-1", b"dirty"),
                &components()
            ),
            Err(Error::Capture(capture::Error::Missing))
        ));
        assert!(s.0.borrow().writes.is_empty());
        for (target_scope, id, bytes, path) in [
            (
                self::scope("foreign"),
                "capture-2",
                b"dirty".as_slice(),
                components(),
            ),
            (
                scope.clone(),
                "capture-1",
                b"different".as_slice(),
                components(),
            ),
            (
                scope.clone(),
                "capture-2",
                b"dirty".as_slice(),
                vec!["renamed".into()],
            ),
        ] {
            assert!(
                retain_indexed(
                    &s,
                    &mut child,
                    &s,
                    prepared(&target_scope, id, bytes),
                    &path
                )
                .is_err()
            );
        }
        let wrong_file = PreparedCapture::new(
            &scope,
            &CaptureId::new("capture-2").unwrap(),
            Baseline::new([1; 16], "\"base\"", 3, 11, 7, 91).unwrap(),
            Zeroizing::new(b"dirty".to_vec()),
        )
        .unwrap();
        assert!(retain_indexed(&s, &mut child, &s, wrong_file, &components()).is_err());
        let wrong_etag = PreparedCapture::new(
            &scope,
            &CaptureId::new("capture-2").unwrap(),
            Baseline::new([1; 16], "\"changed\"", 3, 11, 7, 90).unwrap(),
            Zeroizing::new(b"dirty".to_vec()),
        )
        .unwrap();
        assert!(retain_indexed(&s, &mut child, &s, wrong_etag, &components()).is_err());
        assert!(s.0.borrow().child.as_ref().unwrap().as_slice() == before.as_slice());
        assert!(s.0.borrow().bodies.is_empty());
    }
    #[test]
    fn fresh_ticket_is_bound_to_the_whole_encoded_frame_and_cannot_adopt_a_preexisting_body() {
        let (s, scope, mut child) = fixture();
        let custody::CaptureEnrollment::New(ticket) = child
            .enroll_capture(&s, &prepared(&scope, "capture-1", b"dirty"), &components())
            .unwrap()
        else {
            panic!("expected fresh ticket")
        };
        assert!(matches!(
            capture::persist_prepared_new(
                &s,
                prepared(&scope, "capture-1", b"substitution"),
                ticket
            ),
            Err(capture::Error::Foreign)
        ));
        assert!(s.0.borrow().bodies.is_empty());
        // A preexisting exact frame must not be adopted as the fresh put result.
        let other = Memory::default();
        capture::retain(
            &other,
            &scope,
            &CaptureId::new("capture-2").unwrap(),
            Baseline::new([1; 16], "\"base\"", 3, 11, 7, 90).unwrap(),
            Zeroizing::new(b"dirty".to_vec()),
        )
        .unwrap();
        assert!(matches!(
            retain_indexed(
                &s,
                &mut child,
                &other,
                prepared(&scope, "capture-2", b"dirty"),
                &components()
            ),
            Err(Error::Capture(capture::Error::Conflict))
        ));
        assert_eq!(child.captures_for_reconciliation().len(), 2);
    }
    #[test]
    fn v1_readonly_reopen_preserves_raw_bytes_and_v2_is_strict_and_rejected_by_old_reader() {
        let (s, scope, _) = fixture();
        let old = s.0.borrow().child.clone().unwrap();
        let mut spaced = b" \n".to_vec();
        spaced.extend_from_slice(&old);
        spaced.extend_from_slice(b"\n ");
        s.0.borrow_mut().child = Some(Zeroizing::new(spaced.clone()));
        let mut child = custody::Custody::reopen(&s, &scope).unwrap();
        assert!(s.0.borrow().writes.is_empty());
        assert_eq!(s.0.borrow().child.as_ref().unwrap().as_slice(), spaced);
        let v1: serde_json::Value = serde_json::from_slice(&spaced).unwrap();
        assert_eq!(v1["version"], 1);
        assert!(v1.get("capture_refs").is_none());
        let mut null_v1 = v1;
        null_v1["capture_refs"] = serde_json::Value::Null;
        s.0.borrow_mut().child = Some(Zeroizing::new(serde_json::to_vec(&null_v1).unwrap()));
        assert!(custody::Custody::reopen(&s, &scope).is_err());
        s.0.borrow_mut().child = Some(Zeroizing::new(spaced));
        retain_indexed(
            &s,
            &mut child,
            &s,
            prepared(&scope, "capture-1", b"dirty"),
            &components(),
        )
        .unwrap();
        let good = s.0.borrow().child.clone().unwrap();
        let v2: serde_json::Value = serde_json::from_slice(&good).unwrap();
        assert_eq!(v2["version"], 2);
        #[allow(dead_code)]
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct OldDocument {
            version: u32,
            scope: custody::Scope,
            revision: u64,
            incomplete: bool,
            catalogue: Vec<custody::Entry>,
            pending: Vec<custody::Hydration>,
        }
        assert!(serde_json::from_slice::<OldDocument>(&good).is_err());
        for bad in 0..6 {
            let mut value = v2.clone();
            match bad {
                0 => value["capture_refs"] = serde_json::Value::Null,
                1 => value["capture_refs"] = serde_json::json!([]),
                2 => {
                    value.as_object_mut().unwrap().remove("capture_refs");
                }
                3 => value["capture_refs"][0]["unknown"] = true.into(),
                4 => value["capture_refs"][0]["frame"]["length"] = 0.into(),
                _ => {
                    value["capture_refs"][0]["entry"]["etag"] = "W/\"weak\"".into();
                    value["catalogue"][0]["etag"] = "W/\"weak\"".into();
                }
            }
            let bytes = serde_json::to_vec(&value).unwrap();
            s.0.borrow_mut().child = Some(Zeroizing::new(bytes.clone()));
            assert!(custody::Custody::reopen(&s, &scope).is_err());
            assert_eq!(s.0.borrow().child.as_ref().unwrap().as_slice(), bytes);
        }
    }
    #[test]
    fn bounded_index_capacity_preserves_all_pending_refs_and_blocks_history() {
        let (s, scope, mut child) = fixture();
        for n in 0..custody::MAX_CAPTURE_REFS {
            child
                .enroll_capture(
                    &s,
                    &prepared(&scope, &format!("capture-{n}"), b"dirty"),
                    &components(),
                )
                .unwrap();
        }
        assert!(matches!(
            child.enroll_capture(&s, &prepared(&scope, "overflow", b"dirty"), &components()),
            Err(custody::Error::Capacity)
        ));
        let recovered = custody::Custody::reopen(&s, &scope).unwrap();
        assert_eq!(
            recovered.captures_for_reconciliation().len(),
            custody::MAX_CAPTURE_REFS
        );
        assert!(matches!(
            recovered.publication_history(),
            Err(custody::Error::Incomplete)
        ));
        assert!(s.0.borrow().bodies.is_empty());
    }
}

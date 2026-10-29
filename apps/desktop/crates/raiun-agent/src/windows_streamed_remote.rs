//! Agent-generation fence around the existing authorized v2 recovery chain.
//! No HTTP context, source ownership, token generation or deadline is replaced.
use raiun_cloudfiles_windows::{
    EditJournalScope, RecoveryRemote, RecoveryRemoteVersion, RemoteEditBaseline,
    streamed_reconcile::{StreamedRecoveryRemote, StreamedRemoteDigest},
};
use raiun_core::backend::{CloudError, ErrorKind};
use std::{
    io::Read,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

pub(super) fn companion<'a>(
    owner: &'a super::AgentGenerationRecoveryRemote<'_>,
) -> Option<Box<dyn StreamedRecoveryRemote + 'a>> {
    let expected = owner.expected_generation;
    if expected == 0 || owner.authorized_generation.load(Ordering::Acquire) != expected {
        return None;
    }
    let legacy = owner.inner.remote();
    let inner = legacy.streamed_remote()?;
    if owner.authorized_generation.load(Ordering::Acquire) != expected {
        return None;
    }
    Some(Box::new(GenerationStreamedRemote {
        legacy,
        inner,
        generation: Arc::clone(&owner.authorized_generation),
        expected,
    }))
}

struct GenerationStreamedRemote<'a> {
    legacy: &'a dyn RecoveryRemote,
    inner: Box<dyn StreamedRecoveryRemote + 'a>,
    generation: Arc<AtomicU64>,
    expected: u64,
}
impl GenerationStreamedRemote<'_> {
    fn current(&self) -> bool {
        self.expected != 0 && self.generation.load(Ordering::Acquire) == self.expected
    }
    fn check(&self, scope: &EditJournalScope) -> Result<(), CloudError> {
        if !self.current() {
            return Err(revoked());
        }
        let result = self.legacy.ensure_authorized(scope);
        if !self.current() {
            return Err(revoked());
        }
        result
    }
}
fn revoked() -> CloudError {
    CloudError::new(
        ErrorKind::Unauthorized,
        "the connected account generation changed",
    )
}
impl StreamedRecoveryRemote for GenerationStreamedRemote<'_> {
    fn server_origin(&self) -> &str {
        if !self.current() {
            return "";
        }
        let origin = self.inner.server_origin();
        if self.current() { origin } else { "" }
    }
    fn ensure_authorized(
        &self,
        scope: &EditJournalScope,
        record_generation: u64,
    ) -> Result<(), CloudError> {
        self.check(scope)?;
        let result = self.inner.ensure_authorized(scope, record_generation);
        self.check(scope)?;
        result
    }
    fn stat(
        &self,
        scope: &EditJournalScope,
        path: &str,
    ) -> Result<RecoveryRemoteVersion, CloudError> {
        self.check(scope)?;
        let result = self.inner.stat(scope, path);
        self.check(scope)?;
        result
    }
    fn conditional_upload(
        &self,
        scope: &EditJournalScope,
        path: &str,
        source: Box<dyn Read + Send>,
        baseline: &RemoteEditBaseline,
        length: u64,
        sha256: [u8; 32],
    ) -> Result<StreamedRemoteDigest, CloudError> {
        self.check(scope)?;
        let result = self
            .inner
            .conditional_upload(scope, path, source, baseline, length, sha256);
        self.check(scope)?;
        result
    }
    fn read_digest(
        &self,
        scope: &EditJournalScope,
        path: &str,
        id: &str,
        etag: &str,
        length: u64,
        sha256: [u8; 32],
    ) -> Result<StreamedRemoteDigest, CloudError> {
        self.check(scope)?;
        let result = self
            .inner
            .read_digest(scope, path, id, etag, length, sha256);
        self.check(scope)?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raiun_cloudfiles_windows::RecoveryRemoteBody;
    use raiun_core::backend::WriteCondition;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    struct Probe {
        generation: Arc<AtomicU64>,
        companions: AtomicUsize,
        calls: AtomicUsize,
        legacy_checks: AtomicUsize,
        token_checks: AtomicUsize,
        flip: AtomicBool,
        flip_authorization: AtomicBool,
        deny_legacy: AtomicBool,
        supported: bool,
    }
    impl Probe {
        fn new() -> Self {
            Self {
                generation: Arc::new(AtomicU64::new(7)),
                companions: AtomicUsize::new(0),
                calls: AtomicUsize::new(0),
                legacy_checks: AtomicUsize::new(0),
                token_checks: AtomicUsize::new(0),
                flip: AtomicBool::new(false),
                flip_authorization: AtomicBool::new(false),
                deny_legacy: AtomicBool::new(false),
                supported: true,
            }
        }
        fn version(&self) -> RecoveryRemoteVersion {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.flip.load(Ordering::Acquire) {
                self.generation.store(8, Ordering::Release);
            }
            RecoveryRemoteVersion {
                resource_id: "file".into(),
                etag: "\"v2\"".into(),
                size: 0,
                is_directory: false,
                encrypted: false,
                writable: true,
            }
        }
    }
    fn scope() -> EditJournalScope {
        EditJournalScope {
            profile_id: "synthetic".into(),
            server_origin: "https://fixture.invalid".into(),
            account_subject: "private-subject".into(),
            space_id: "space".into(),
            root_resource_id: "root".into(),
            root_volume_serial: 1,
            root_file_index: 2,
        }
    }
    fn unsupported<T>() -> Result<T, CloudError> {
        Err(CloudError::new(
            ErrorKind::Unsupported,
            "synthetic legacy mutation refused",
        ))
    }
    impl RecoveryRemote for Probe {
        fn server_origin(&self) -> Option<&str> {
            Some("https://fixture.invalid")
        }
        fn ensure_authorized(&self, _: &EditJournalScope) -> Result<(), CloudError> {
            self.legacy_checks.fetch_add(1, Ordering::Relaxed);
            if self.deny_legacy.load(Ordering::Acquire) {
                Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "synthetic scope refused",
                ))
            } else {
                Ok(())
            }
        }
        fn streamed_remote(&self) -> Option<Box<dyn StreamedRecoveryRemote + '_>> {
            self.companions.fetch_add(1, Ordering::Relaxed);
            self.supported
                .then(|| Box::new(StreamedProbe(self)) as Box<dyn StreamedRecoveryRemote>)
        }
        fn stat(&self, _: &EditJournalScope, _: &str) -> Result<RecoveryRemoteVersion, CloudError> {
            unsupported()
        }
        fn conditional_upload(
            &self,
            _: &EditJournalScope,
            _: &str,
            _: &[u8],
            _: &str,
            _: WriteCondition,
            _: u64,
        ) -> Result<RecoveryRemoteVersion, CloudError> {
            unsupported()
        }
        fn readback(
            &self,
            _: &EditJournalScope,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: usize,
        ) -> Result<RecoveryRemoteBody, CloudError> {
            unsupported()
        }
    }
    struct StreamedProbe<'a>(&'a Probe);
    impl StreamedRecoveryRemote for StreamedProbe<'_> {
        fn server_origin(&self) -> &str {
            "https://fixture.invalid"
        }
        fn ensure_authorized(
            &self,
            _: &EditJournalScope,
            record_generation: u64,
        ) -> Result<(), CloudError> {
            self.0.token_checks.fetch_add(1, Ordering::Relaxed);
            if record_generation == 11 {
                if self.0.flip_authorization.load(Ordering::Acquire) {
                    self.0.generation.store(8, Ordering::Release);
                }
                Ok(())
            } else {
                Err(revoked())
            }
        }
        fn stat(
            &self,
            scope: &EditJournalScope,
            _: &str,
        ) -> Result<RecoveryRemoteVersion, CloudError> {
            self.ensure_authorized(scope, 11)?;
            Ok(self.0.version())
        }
        fn conditional_upload(
            &self,
            scope: &EditJournalScope,
            _: &str,
            mut source: Box<dyn Read + Send>,
            _: &RemoteEditBaseline,
            length: u64,
            sha256: [u8; 32],
        ) -> Result<StreamedRemoteDigest, CloudError> {
            self.ensure_authorized(scope, 11)?;
            let mut bytes = [0; 64];
            while source.read(&mut bytes).unwrap() != 0 {}
            Ok(StreamedRemoteDigest {
                version: self.0.version(),
                bytes: length,
                sha256,
            })
        }
        fn read_digest(
            &self,
            scope: &EditJournalScope,
            _: &str,
            _: &str,
            _: &str,
            length: u64,
            sha256: [u8; 32],
        ) -> Result<StreamedRemoteDigest, CloudError> {
            self.ensure_authorized(scope, 11)?;
            Ok(StreamedRemoteDigest {
                version: self.0.version(),
                bytes: length,
                sha256,
            })
        }
    }
    fn owner(probe: &Probe, expected: u64) -> super::super::AgentGenerationRecoveryRemote<'_> {
        super::super::AgentGenerationRecoveryRemote {
            inner: super::super::RecoveryRemoteHandle::Borrowed(probe),
            authorized_generation: probe.generation.clone(),
            expected_generation: expected,
        }
    }
    #[test]
    fn stale_zero_or_unsupported_companion_refuses_without_calls() {
        let mut probe = Probe::new();
        assert!(companion(&owner(&probe, 0)).is_none());
        assert!(companion(&owner(&probe, 6)).is_none());
        assert_eq!(probe.companions.load(Ordering::Relaxed), 0);
        struct LegacyOnly;
        impl RecoveryRemote for LegacyOnly {
            fn server_origin(&self) -> Option<&str> {
                None
            }
            fn stat(
                &self,
                _: &EditJournalScope,
                _: &str,
            ) -> Result<RecoveryRemoteVersion, CloudError> {
                unsupported()
            }
            fn conditional_upload(
                &self,
                _: &EditJournalScope,
                _: &str,
                _: &[u8],
                _: &str,
                _: WriteCondition,
                _: u64,
            ) -> Result<RecoveryRemoteVersion, CloudError> {
                unsupported()
            }
            fn readback(
                &self,
                _: &EditJournalScope,
                _: &str,
                _: &str,
                _: Option<&str>,
                _: usize,
            ) -> Result<RecoveryRemoteBody, CloudError> {
                unsupported()
            }
        }
        let legacy = LegacyOnly;
        let legacy_owner = super::super::AgentGenerationRecoveryRemote {
            inner: super::super::RecoveryRemoteHandle::Borrowed(&legacy),
            authorized_generation: Arc::new(AtomicU64::new(7)),
            expected_generation: 7,
        };
        assert!(companion(&legacy_owner).is_none());
        probe.supported = false;
        assert!(companion(&owner(&probe, 7)).is_none());
        assert_eq!(probe.calls.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn generation_flip_after_each_delegate_refuses_proof_and_future_calls() {
        for operation in 0..3 {
            let probe = Probe::new();
            let owner = owner(&probe, 7);
            let remote = companion(&owner).unwrap();
            remote.ensure_authorized(&scope(), 11).unwrap();
            probe.flip.store(true, Ordering::Release);
            let error = match operation {
                0 => remote.stat(&scope(), "file").err().unwrap(),
                1 => remote
                    .conditional_upload(
                        &scope(),
                        "file",
                        Box::new(std::io::empty()),
                        &RemoteEditBaseline {
                            resource_id: "file".into(),
                            etag: "\"v1\"".into(),
                            byte_len: 1,
                        },
                        0,
                        [0; 32],
                    )
                    .err()
                    .unwrap(),
                _ => remote
                    .read_digest(&scope(), "file", "file", "\"v2\"", 0, [0; 32])
                    .err()
                    .unwrap(),
            };
            assert_eq!(error.kind, ErrorKind::Unauthorized);
            assert!(!error.to_string().contains("private-subject"));
            assert_eq!(remote.server_origin(), "");
            assert!(remote.stat(&scope(), "file").is_err());
            assert_eq!(probe.calls.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn inner_scope_and_record_generation_authorization_are_not_bypassed() {
        let probe = Probe::new();
        let owner = owner(&probe, 7);
        let remote = companion(&owner).unwrap();
        assert!(remote.ensure_authorized(&scope(), 10).is_err());
        assert_eq!(probe.token_checks.load(Ordering::Relaxed), 1);
        probe.deny_legacy.store(true, Ordering::Release);
        assert_eq!(
            remote.stat(&scope(), "file").err().unwrap().kind,
            ErrorKind::Forbidden
        );
        assert_eq!(probe.calls.load(Ordering::Relaxed), 0);
        assert!(probe.legacy_checks.load(Ordering::Relaxed) >= 2);
        let probe = Probe::new();
        let flipped_owner = super::super::AgentGenerationRecoveryRemote {
            inner: super::super::RecoveryRemoteHandle::Borrowed(&probe),
            authorized_generation: probe.generation.clone(),
            expected_generation: 7,
        };
        let remote = companion(&flipped_owner).unwrap();
        probe.flip_authorization.store(true, Ordering::Release);
        assert_eq!(
            remote.ensure_authorized(&scope(), 11).unwrap_err().kind,
            ErrorKind::Unauthorized
        );
        assert_eq!(probe.calls.load(Ordering::Relaxed), 0);
    }
}

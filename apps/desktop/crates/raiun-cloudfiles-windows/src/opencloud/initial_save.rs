//! Exact live-backend route for a fresh close receipt. The closure cannot retain
//! the borrowed remote beyond the backend revocation lease.
use super::*;
use crate::{
    EditJournalScope, OpenCloudRecoveryRemote, RecoveryRemote, RecoveryRemoteBody,
    RecoveryRemoteVersion,
};
use raiun_core::backend::{CloudError, WriteCondition};

impl OpenCloudPlaceholderBackend {
    /// Revalidate the namespace and ordinary Space root under the current
    /// backend lease. This does not discover pending records or initiate a
    /// write; the caller supplies one fresh receipt and its agent-generation
    /// guard in `run`.
    pub fn with_initial_edit_remote<T>(
        &self,
        scope: &EditJournalScope,
        run: impl FnOnce(&dyn RecoveryRemote) -> T,
    ) -> Result<T, BackendError> {
        self.with_initial_edit_session(scope, |session| run(session.remote()))
    }

    /// Retain the same revocation lease through remote verification and local
    /// completion. Publication capabilities cannot outlive this session.
    pub fn with_initial_edit_session<T>(
        &self,
        scope: &EditJournalScope,
        run: impl FnOnce(&InitialEditSession<'_>) -> T,
    ) -> Result<T, BackendError> {
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        self.ensure_active()?;
        let catalog = self
            .catalog_scope
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .clone()
            .ok_or(BackendError::Unavailable)?;
        if scope.profile_id != self.scope.profile_id()
            || scope.account_subject != self.scope.account_id()
            || scope.server_origin != self.scope.server_origin()
            || scope.root_volume_serial != catalog.local_root().volume_serial
            || scope.root_file_index != catalog.local_root().file_index
        {
            return Err(BackendError::Unavailable);
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let spaces = self.validate_namespace_scope(
            self.scope.account_id(),
            catalog.personal_space_id(),
            catalog.personal_root_resource_id(),
            deadline,
        )?;
        let space = spaces
            .iter()
            .find(|space| space.id == scope.space_id)
            .filter(|space| space.writable && !space.encrypted)
            .ok_or(BackendError::Unavailable)?;
        let root = self
            .client
            .stat_discovered_space_root_with_context(
                space,
                RangeReadContext {
                    deadline,
                    token_generation: self.token_generation,
                },
            )
            .map_err(|error| self.reject_cached_cloud_error(error))?;
        if !root.directory || root.encrypted || !root.writable || root.id != scope.root_resource_id
        {
            return Err(BackendError::Unavailable);
        }
        self.ensure_active()?;
        let inner = OpenCloudRecoveryRemote::new(
            Arc::clone(&self.client),
            scope.clone(),
            root.path,
            self.token_generation,
        )
        .map_err(|error| self.reject_cached_cloud_error(error))?
        .with_dispatch_deadline(deadline);
        let remote = LiveInitialRemote {
            backend: self,
            inner,
        };
        Ok(run(&InitialEditSession {
            remote,
            scope: scope.clone(),
        }))
    }
}

pub struct InitialEditSession<'backend> {
    pub(super) remote: LiveInitialRemote<'backend>,
    pub(super) scope: EditJournalScope,
}

impl InitialEditSession<'_> {
    pub fn remote(&self) -> &dyn RecoveryRemote {
        &self.remote
    }
}

pub(super) struct LiveInitialRemote<'a> {
    pub(super) backend: &'a OpenCloudPlaceholderBackend,
    inner: OpenCloudRecoveryRemote,
}

impl LiveInitialRemote<'_> {
    fn authorize_path(&self, scope: &EditJournalScope, path: &str) -> Result<(), CloudError> {
        self.authorize(scope)?;
        let absolute = format!("/{}", path.trim_start_matches('/'));
        self.backend
            .ensure_ordinary_location(&scope.space_id, &absolute)
            .map_err(|_| {
                CloudError::new(
                    ErrorKind::Forbidden,
                    "Ordinary writes cannot address a known vault",
                )
            })
    }

    pub(super) fn authorize(&self, scope: &EditJournalScope) -> Result<(), CloudError> {
        self.backend.ensure_active().map_err(|_| {
            CloudError::new(ErrorKind::Unauthorized, "the connected backend changed")
        })?;
        self.inner.ensure_authorized(scope)
    }
}

impl RecoveryRemote for LiveInitialRemote<'_> {
    #[cfg(any(windows, test))]
    fn streamed_remote(
        &self,
    ) -> Option<Box<dyn crate::streamed_reconcile::StreamedRecoveryRemote + '_>> {
        self.backend.ensure_active().ok()?;
        let inner = RecoveryRemote::streamed_remote(&self.inner)?;
        Some(Box::new(LiveStreamedRemote {
            backend: self.backend,
            inner,
        }))
    }

    fn server_origin(&self) -> Option<&str> {
        self.backend.ensure_active().ok()?;
        self.inner.server_origin()
    }
    fn ensure_authorized(&self, scope: &EditJournalScope) -> Result<(), CloudError> {
        self.authorize(scope)
    }
    fn stat(
        &self,
        scope: &EditJournalScope,
        path: &str,
    ) -> Result<RecoveryRemoteVersion, CloudError> {
        self.authorize_path(scope, path)?;
        self.inner.stat(scope, path)
    }
    fn conditional_upload(
        &self,
        scope: &EditJournalScope,
        path: &str,
        content: &[u8],
        id: &str,
        condition: WriteCondition,
        size: u64,
    ) -> Result<RecoveryRemoteVersion, CloudError> {
        self.authorize_path(scope, path)?;
        self.inner
            .conditional_upload(scope, path, content, id, condition, size)
    }
    fn readback(
        &self,
        scope: &EditJournalScope,
        path: &str,
        id: &str,
        etag: Option<&str>,
        max_bytes: usize,
    ) -> Result<RecoveryRemoteBody, CloudError> {
        self.authorize_path(scope, path)?;
        self.inner.readback(scope, path, id, etag, max_bytes)
    }
}

/// The companion borrows the same live backend/session; it cannot extend the
/// enclosing revocation lease or the inner route's existing dispatch deadline.
#[cfg(any(windows, test))]
struct LiveStreamedRemote<'a> {
    backend: &'a OpenCloudPlaceholderBackend,
    inner: Box<dyn crate::streamed_reconcile::StreamedRecoveryRemote + 'a>,
}

#[cfg(any(windows, test))]
impl LiveStreamedRemote<'_> {
    fn authorize_path(&self, scope: &EditJournalScope, path: &str) -> Result<(), CloudError> {
        crate::streamed_reconcile::StreamedRecoveryRemote::ensure_authorized(
            self,
            scope,
            self.backend.token_generation,
        )?;
        let absolute = format!("/{}", path.trim_start_matches('/'));
        self.backend
            .ensure_ordinary_location(&scope.space_id, &absolute)
            .map_err(|_| {
                CloudError::new(
                    ErrorKind::Forbidden,
                    "Ordinary writes cannot address a known vault",
                )
            })
    }
}

#[cfg(any(windows, test))]
impl crate::streamed_reconcile::StreamedRecoveryRemote for LiveStreamedRemote<'_> {
    fn server_origin(&self) -> &str {
        // Informational only. Every operational method separately requires
        // live authorization; this string never conveys permission.
        crate::streamed_reconcile::StreamedRecoveryRemote::server_origin(self.inner.as_ref())
    }

    fn ensure_authorized(
        &self,
        scope: &EditJournalScope,
        generation: u64,
    ) -> Result<(), CloudError> {
        self.backend.ensure_active().map_err(|_| {
            CloudError::new(ErrorKind::Unauthorized, "the connected backend changed")
        })?;
        if generation != self.backend.token_generation {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "the provider generation changed",
            ));
        }
        crate::streamed_reconcile::StreamedRecoveryRemote::ensure_authorized(
            self.inner.as_ref(),
            scope,
            generation,
        )
    }

    fn stat(
        &self,
        scope: &EditJournalScope,
        path: &str,
    ) -> Result<RecoveryRemoteVersion, CloudError> {
        self.authorize_path(scope, path)?;
        let result = crate::streamed_reconcile::StreamedRecoveryRemote::stat(
            self.inner.as_ref(),
            scope,
            path,
        );
        self.authorize_path(scope, path)?;
        result
    }

    fn conditional_upload(
        &self,
        scope: &EditJournalScope,
        path: &str,
        source: Box<dyn std::io::Read + Send>,
        baseline: &crate::RemoteEditBaseline,
        content_len: u64,
        sha256: [u8; 32],
    ) -> Result<crate::streamed_reconcile::StreamedRemoteDigest, CloudError> {
        self.authorize_path(scope, path)?;
        let result = crate::streamed_reconcile::StreamedRecoveryRemote::conditional_upload(
            self.inner.as_ref(),
            scope,
            path,
            source,
            baseline,
            content_len,
            sha256,
        );
        self.authorize_path(scope, path)?;
        result
    }

    fn read_digest(
        &self,
        scope: &EditJournalScope,
        path: &str,
        resource_id: &str,
        etag: &str,
        content_len: u64,
        sha256: [u8; 32],
    ) -> Result<crate::streamed_reconcile::StreamedRemoteDigest, CloudError> {
        self.authorize_path(scope, path)?;
        let result = crate::streamed_reconcile::StreamedRecoveryRemote::read_digest(
            self.inner.as_ref(),
            scope,
            path,
            resource_id,
            etag,
            content_len,
            sha256,
        );
        self.authorize_path(scope, path)?;
        result
    }
}

#[cfg(test)]
mod streamed_route_tests {
    use super::*;
    use crate::streamed_reconcile::{StreamedRecoveryRemote, StreamedRemoteDigest};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixture() -> (OpenCloudPlaceholderBackend, EditJournalScope) {
        // Constructors only; no server is listening and these tests issue no HTTP.
        let client =
            Arc::new(OpenCloudClient::new("http://127.0.0.1:9", "synthetic".into()).unwrap());
        let origin = client.server_origin().unwrap();
        let provider = ProviderScope::new(
            client.as_ref(),
            "synthetic".into(),
            derive_account_id(&origin, "personal"),
            origin.clone(),
        )
        .unwrap();
        let scope = EditJournalScope {
            profile_id: provider.profile_id().into(),
            server_origin: origin,
            account_subject: provider.account_id().into(),
            space_id: "personal".into(),
            root_resource_id: "root".into(),
            root_volume_serial: 17,
            root_file_index: 29,
        };
        (
            OpenCloudPlaceholderBackend::new(client, provider).unwrap(),
            scope,
        )
    }
    struct Mock {
        scope: EditJournalScope,
        generation: u64,
        calls: Arc<AtomicUsize>,
        rotate: Option<Arc<OpenCloudClient>>,
    }
    fn version() -> RecoveryRemoteVersion {
        RecoveryRemoteVersion {
            resource_id: "file".into(),
            etag: "\"version\"".into(),
            size: 3,
            is_directory: false,
            encrypted: false,
            writable: true,
        }
    }
    impl Mock {
        fn called(&self) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(client) = &self.rotate {
                client.set_bearer_token("rotated".into()).unwrap();
            }
        }
        fn digest(&self) -> StreamedRemoteDigest {
            StreamedRemoteDigest {
                version: version(),
                bytes: 3,
                sha256: [7; 32],
            }
        }
    }
    impl StreamedRecoveryRemote for Mock {
        fn server_origin(&self) -> &str {
            &self.scope.server_origin
        }
        fn ensure_authorized(
            &self,
            scope: &EditJournalScope,
            generation: u64,
        ) -> Result<(), CloudError> {
            if scope != &self.scope || generation != self.generation {
                return Err(CloudError::new(
                    ErrorKind::Unauthorized,
                    "mock scope changed",
                ));
            }
            Ok(())
        }
        fn stat(
            &self,
            _: &EditJournalScope,
            path: &str,
        ) -> Result<RecoveryRemoteVersion, CloudError> {
            assert_eq!(path, "notes.txt");
            self.called();
            Ok(version())
        }
        fn conditional_upload(
            &self,
            _: &EditJournalScope,
            path: &str,
            mut source: Box<dyn std::io::Read + Send>,
            baseline: &crate::RemoteEditBaseline,
            length: u64,
            sha: [u8; 32],
        ) -> Result<StreamedRemoteDigest, CloudError> {
            assert_eq!(path, "notes.txt");
            assert_eq!(baseline.resource_id, "file");
            assert_eq!(baseline.etag, "\"base\"");
            assert_eq!(length, 3);
            assert_eq!(sha, [7; 32]);
            let mut bytes = [0; 3];
            source.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"abc");
            self.called();
            Ok(self.digest())
        }
        fn read_digest(
            &self,
            _: &EditJournalScope,
            path: &str,
            id: &str,
            etag: &str,
            length: u64,
            sha: [u8; 32],
        ) -> Result<StreamedRemoteDigest, CloudError> {
            assert_eq!(
                (path, id, etag, length, sha),
                ("notes.txt", "file", "\"version\"", 3, [7; 32])
            );
            self.called();
            Ok(self.digest())
        }
    }
    fn run(
        remote: &dyn StreamedRecoveryRemote,
        scope: &EditJournalScope,
        operation: usize,
    ) -> Result<(), CloudError> {
        match operation {
            0 => remote.stat(scope, "notes.txt").map(|_| ()),
            1 => remote
                .conditional_upload(
                    scope,
                    "notes.txt",
                    Box::new(std::io::Cursor::new(b"abc")),
                    &crate::RemoteEditBaseline {
                        resource_id: "file".into(),
                        etag: "\"base\"".into(),
                        byte_len: 3,
                    },
                    3,
                    [7; 32],
                )
                .map(|_| ()),
            _ => remote
                .read_digest(scope, "notes.txt", "file", "\"version\"", 3, [7; 32])
                .map(|_| ()),
        }
    }
    #[test]
    fn live_streamed_wrapper_preserves_arguments_and_refuses_wrong_scope_generation_and_revocation()
    {
        let (backend, scope) = fixture();
        let calls = Arc::new(AtomicUsize::new(0));
        let remote = LiveStreamedRemote {
            backend: &backend,
            inner: Box::new(Mock {
                scope: scope.clone(),
                generation: backend.token_generation,
                calls: calls.clone(),
                rotate: None,
            }),
        };
        assert!(
            remote
                .ensure_authorized(&scope, backend.token_generation + 1)
                .is_err()
        );
        let mut wrong = scope.clone();
        wrong.account_subject.push_str("-other");
        for operation in 0..3 {
            assert!(run(&remote, &wrong, operation).is_err());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        for operation in 0..3 {
            run(&remote, &scope, operation).unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        backend.revoke();
        for operation in 0..3 {
            assert!(run(&remote, &scope, operation).is_err());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
    #[test]
    fn live_streamed_wrapper_discards_every_success_after_token_rotation() {
        for operation in 0..3 {
            let (backend, scope) = fixture();
            let calls = Arc::new(AtomicUsize::new(0));
            let remote = LiveStreamedRemote {
                backend: &backend,
                inner: Box::new(Mock {
                    scope: scope.clone(),
                    generation: backend.token_generation,
                    calls: calls.clone(),
                    rotate: Some(backend.client.clone()),
                }),
            };
            assert_eq!(
                run(&remote, &scope, operation).unwrap_err().kind,
                ErrorKind::Unauthorized
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }
    #[test]
    fn v2_companion_constructor_does_not_extend_expired_v1_dispatch_deadline() {
        let (backend, scope) = fixture();
        let inner = OpenCloudRecoveryRemote::new(
            backend.client.clone(),
            scope.clone(),
            "/dav/personal".into(),
            backend.token_generation,
        )
        .unwrap();
        let live = LiveInitialRemote {
            backend: &backend,
            inner,
        };
        let companion = RecoveryRemote::streamed_remote(&live).unwrap();
        assert!(
            companion
                .ensure_authorized(&scope, backend.token_generation)
                .is_ok()
        );
        drop(companion);
        let expired = LiveInitialRemote {
            backend: &backend,
            inner: OpenCloudRecoveryRemote::new(
                backend.client.clone(),
                scope,
                "/dav/personal".into(),
                backend.token_generation,
            )
            .unwrap()
            .with_dispatch_deadline(std::time::Instant::now() - std::time::Duration::from_secs(1)),
        };
        assert!(RecoveryRemote::streamed_remote(&expired).is_none());
    }
}

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
        Ok(run(&remote))
    }
}

struct LiveInitialRemote<'a> {
    backend: &'a OpenCloudPlaceholderBackend,
    inner: OpenCloudRecoveryRemote,
}

impl LiveInitialRemote<'_> {
    fn authorize(&self, scope: &EditJournalScope) -> Result<(), CloudError> {
        self.backend.ensure_active().map_err(|_| {
            CloudError::new(ErrorKind::Unauthorized, "the connected backend changed")
        })?;
        self.inner.ensure_authorized(scope)
    }
}

impl RecoveryRemote for LiveInitialRemote<'_> {
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
        self.authorize(scope)?;
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
        self.authorize(scope)?;
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
        self.authorize(scope)?;
        self.inner.readback(scope, path, id, etag, max_bytes)
    }
}

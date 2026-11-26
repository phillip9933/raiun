//! Trusted OpenCloud binding for ordinary v2 recovery. No record/event can
//! choose its URL, root, account or token generation. Caller holds provider lease.
use super::*;
use raiun_core::backend::{CloudBackend, RemoteEntry};
use raiun_opencloud::{OpenCloudClient, RangeReadContext, RecoveryStreamReadback};
use std::time::Instant;

pub struct OpenCloudStreamedRecoveryRemote {
    client: Arc<OpenCloudClient>,
    scope: EditJournalScope,
    root_path: String,
    context: RangeReadContext,
    job: Option<crate::StreamedRecoveryJob>,
}
impl OpenCloudStreamedRecoveryRemote {
    /// Construct only from current prepared provider state, never journal or
    /// IPC-provided server/root credentials. The owner retains its live lease.
    pub fn new(
        client: Arc<OpenCloudClient>,
        scope: EditJournalScope,
        root_path: String,
        context: RangeReadContext,
    ) -> Result<Self, CloudError> {
        if context.token_generation == 0
            || !client.provider_generation_is_current(context.token_generation)
            || !client.provider_credentials_match(&scope.account_subject, None, None)
            || context.deadline <= Instant::now()
            || client.server_origin().as_deref() != Some(scope.server_origin.as_str())
            || root_path.is_empty()
            || !root_path.starts_with('/')
            || root_path.len() > 32 * 1024
            || root_path.contains(['\\', '?', '#'])
            || root_path.chars().any(char::is_control)
            || root_path.split('/').any(|part| matches!(part, "." | ".."))
        {
            return Err(unavailable());
        }
        Ok(Self {
            client,
            scope,
            root_path,
            context,
            job: None,
        })
    }
    pub(crate) fn with_recovery_job(mut self, job: crate::StreamedRecoveryJob) -> Self {
        self.context.deadline = self.context.deadline.min(job.deadline());
        self.job = Some(job);
        self
    }
    fn job_cancelled(&self) -> Arc<dyn Fn() -> bool + Send + Sync> {
        let job = self.job.clone();
        Arc::new(move || job.as_ref().is_some_and(|job| job.is_stopped()))
    }
    fn check(&self, scope: &EditJournalScope) -> Result<(), CloudError> {
        self.ensure_authorized(scope, self.context.token_generation)
    }
}
fn unavailable() -> CloudError {
    CloudError::new(
        ErrorKind::Unauthorized,
        "streamed recovery scope or generation is unavailable",
    )
}
fn version(entry: RemoteEntry) -> RecoveryRemoteVersion {
    RecoveryRemoteVersion {
        resource_id: entry.id,
        etag: entry.etag,
        size: entry.size,
        is_directory: entry.directory,
        encrypted: entry.encrypted,
        writable: entry.writable,
    }
}
fn evidence(proof: RecoveryStreamReadback) -> StreamedRemoteDigest {
    StreamedRemoteDigest {
        version: version(proof.entry),
        bytes: proof.bytes,
        sha256: proof.sha256,
    }
}
impl StreamedRecoveryRemote for OpenCloudStreamedRecoveryRemote {
    fn server_origin(&self) -> &str {
        &self.scope.server_origin
    }
    fn ensure_authorized(
        &self,
        scope: &EditJournalScope,
        generation: u64,
    ) -> Result<(), CloudError> {
        if self.job.as_ref().is_some_and(|job| job.is_stopped())
            || scope != &self.scope
            || generation != self.context.token_generation
            || !self.client.provider_generation_is_current(generation)
            || !self
                .client
                .provider_credentials_match(&self.scope.account_subject, None, None)
            || self.context.deadline <= Instant::now()
            || self.client.server_origin().as_deref() != Some(self.scope.server_origin.as_str())
        {
            Err(unavailable())
        } else {
            Ok(())
        }
    }
    fn stat(
        &self,
        scope: &EditJournalScope,
        path: &str,
    ) -> Result<RecoveryRemoteVersion, CloudError> {
        self.check(scope)?;
        let entry = self.client.recovery_stat_with_context(
            &scope.space_id,
            &self.root_path,
            &scope.root_resource_id,
            path,
            RangeReadContext {
                deadline: self
                    .context
                    .deadline
                    .min(Instant::now() + std::time::Duration::from_secs(30)),
                token_generation: self.context.token_generation,
            },
        )?;
        self.check(scope)?;
        Ok(version(entry))
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
        let proof = self
            .client
            .recovery_upload_blocking_reader_cancellable_with_context(
                &scope.space_id,
                &self.root_path,
                &scope.root_resource_id,
                path,
                &baseline.resource_id,
                &baseline.etag,
                baseline.byte_len,
                source,
                length,
                sha256,
                self.context,
                self.job_cancelled(),
            )?;
        self.check(scope)?;
        Ok(evidence(proof))
    }
    fn read_digest(
        &self,
        scope: &EditJournalScope,
        path: &str,
        resource_id: &str,
        etag: &str,
        length: u64,
        sha256: [u8; 32],
    ) -> Result<StreamedRemoteDigest, CloudError> {
        self.check(scope)?;
        let proof = self.client.recovery_read_digest_cancellable_with_context(
            &scope.space_id,
            &self.root_path,
            &scope.root_resource_id,
            path,
            resource_id,
            etag,
            length,
            sha256,
            self.context,
            self.job_cancelled(),
        )?;
        self.check(scope)?;
        Ok(evidence(proof))
    }
}

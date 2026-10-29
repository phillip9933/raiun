//! Streaming recovery of an existing ordinary file, with independent full-body
//! readback. These checks do not establish namespace atomicity on the server.
//! Errors after dispatch leave delivery uncertain: callers must retain their
//! immutable snapshot and original condition, and must not automatically retry.

use super::*;
use bytes::Bytes;
use futures_util::{Stream, StreamExt, stream};
use sha2::{Digest, Sha256};
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use tokio::io::{AsyncRead, AsyncReadExt};

const CHUNK: usize = 64 * 1024;

/// A complete, revision-conditioned readback; not authority to discard local
/// recovery data or acknowledge a native file without its separate guards.
pub struct RecoveryStreamReadback {
    pub entry: RemoteEntry,
    pub bytes: u64,
    pub sha256: [u8; 32],
}

fn source_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "recovery source validation failed",
    )
}

struct StrictReader<R, C> {
    reader: R,
    remaining: u64,
    hash: Sha256,
    digest: [u8; 32],
    budget: TransferBudget,
    cancelled: C,
    progress: async_body::BodyProgress,
    verified: Arc<AtomicBool>,
}

impl<R, C> StrictReader<R, C>
where
    R: AsyncRead + Unpin,
    C: Fn() -> bool,
{
    async fn next(&mut self) -> io::Result<Option<Bytes>> {
        if (self.cancelled)() {
            return Err(source_error());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        if self.remaining != 0 {
            self.progress.budget_wait_started();
            let reservation = self
                .budget
                .acquire_cancellable_async(
                    TransferDirection::Upload,
                    self.remaining.min(CHUNK as u64) as usize,
                    &self.cancelled,
                )
                .await;
            self.progress.budget_wait_finished();
            let reservation = reservation?;
            bytes.resize(reservation.granted(), 0);
            // Do not expose source errors: their messages may contain local paths.
            let count = self
                .reader
                .read(&mut bytes)
                .await
                .map_err(|_| source_error())?;
            reservation.settle(count);
            if count == 0 || (self.cancelled)() {
                return Err(source_error());
            }
            bytes.truncate(count);
            self.remaining -= count as u64;
            self.hash.update(bytes.as_slice());
        }
        if self.remaining == 0 && !self.verified.load(Ordering::Acquire) {
            // Hyper need not poll again after Content-Length bytes. Validate
            // digest AND EOF before yielding that last chunk (also for empty files).
            let mut extra = Zeroizing::new([0u8; 1]);
            let count = self
                .reader
                .read(extra.as_mut())
                .await
                .map_err(|_| source_error())?;
            if count != 0
                || (self.cancelled)()
                || self.hash.clone().finalize().as_slice() != self.digest
            {
                return Err(source_error());
            }
            self.verified.store(true, Ordering::Release);
        }
        if bytes.is_empty() {
            Ok(None)
        } else {
            self.progress.bytes_progressed();
            // Only one bounded plaintext chunk enters the HTTP body at a time;
            // the local source buffer is zeroized when it leaves this scope.
            Ok(Some(Bytes::copy_from_slice(&bytes)))
        }
    }
}

type UploadStream = Pin<Box<dyn Stream<Item = io::Result<Bytes>> + Send>>;

async fn strict_upload<R, C>(mut source: StrictReader<R, C>) -> io::Result<UploadStream>
where
    R: AsyncRead + Unpin + Send + 'static,
    C: Fn() -> bool + Send + Sync + 'static,
{
    // Empty bodies may never be polled by the HTTP stack. Preflight the first
    // chunk, which proves EOF for empty sources before dispatching any request.
    let first = source.next().await?;
    let initial = stream::iter(first.map(Ok));
    let rest = stream::try_unfold(source, |mut source| async move {
        if source.verified.load(Ordering::Acquire) {
            return Ok(None);
        }
        Ok(source.next().await?.map(|bytes| (bytes, source)))
    });
    Ok(Box::pin(initial.chain(rest)))
}

fn stream_metadata_context(context: RangeReadContext) -> RangeReadContext {
    RangeReadContext {
        deadline: context
            .deadline
            .min(Instant::now() + Duration::from_secs(30)),
        token_generation: context.token_generation,
    }
}

fn stream_metadata_step<T>(
    client: &OpenCloudClient,
    context: RangeReadContext,
    operation: impl FnOnce() -> Result<T, CloudError>,
) -> Result<T, CloudError> {
    let child = stream_metadata_context(context);
    client.ensure_context_current(child)?;
    let _guard = RangeContextGuard::enter(child);
    let result = operation()?;
    client.ensure_context_current(child)?;
    Ok(result)
}

impl OpenCloudClient {
    fn stream_context_current(&self, context: RangeReadContext) -> Result<(), CloudError> {
        self.ensure_context_current(context)?;
        if self.transfer_budget.is_paused() {
            return Err(CloudError::new(
                ErrorKind::Offline,
                "recovery transfer was cancelled or paused",
            ));
        }
        Ok(())
    }

    fn stream_entry(
        &self,
        space: &str,
        path: &str,
        id: &str,
        etag: &str,
        size: u64,
    ) -> Result<RemoteEntry, CloudError> {
        let entry = CloudBackend::stat(self, space, path)?;
        validate_recovery_entry(&entry, path)?;
        if entry.id != id
            || entry.etag != etag
            || entry.size != size
            || !entry.writable
            || entry.directory
            || entry.encrypted
        {
            return Err(conflict(
                "recovery target identity, revision or role changed",
            ));
        }
        Ok(entry)
    }

    /// Upload a protected blocking reader on a dedicated, demand-driven worker.
    /// Call on a synchronous engine worker: shutdown joins the source worker and
    /// can block if its underlying synchronous read never returns. The same
    /// source/pin remains owned through independent remote GET and final metadata
    /// checks. A verified transport result is accepted only after actual EOF and
    /// successful joined source destruction; failures retain caller recovery data.
    #[allow(clippy::too_many_arguments)]
    pub fn recovery_upload_blocking_reader_with_context<R>(
        &self,
        space: &str,
        remote_root_path: &str,
        expected_root_id: &str,
        relative_path: &str,
        expected_resource_id: &str,
        expected_etag: &str,
        expected_size: u64,
        reader: R,
        content_length: u64,
        expected_sha256: [u8; 32],
        context: RangeReadContext,
    ) -> Result<RecoveryStreamReadback, CloudError>
    where
        R: std::io::Read + Send + 'static,
    {
        self.recovery_upload_blocking_reader_cancellable_with_context(
            space,
            remote_root_path,
            expected_root_id,
            relative_path,
            expected_resource_id,
            expected_etag,
            expected_size,
            reader,
            content_length,
            expected_sha256,
            context,
            Arc::new(|| false),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn recovery_upload_blocking_reader_cancellable_with_context<R>(
        &self,
        space: &str,
        remote_root_path: &str,
        expected_root_id: &str,
        relative_path: &str,
        expected_resource_id: &str,
        expected_etag: &str,
        expected_size: u64,
        reader: R,
        content_length: u64,
        expected_sha256: [u8; 32],
        context: RangeReadContext,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<RecoveryStreamReadback, CloudError>
    where
        R: std::io::Read + Send + 'static,
    {
        let cancellation = self.transfer_budget.cancellation();
        let (mut worker, reader) = crate::blocking_reader::start(reader)
            .map_err(|_| invalid("recovery source worker could not start"))?;
        let result = self.recovery_upload_reader_cancellable_with_context(
            space,
            remote_root_path,
            expected_root_id,
            relative_path,
            expected_resource_id,
            expected_etag,
            expected_size,
            reader,
            content_length,
            expected_sha256,
            context,
            Arc::clone(&cancelled),
        );
        // Always join, including admission/transport/readback failures. Never
        // replace an existing transport error with a later shutdown diagnosis.
        let completion = worker.cancel_and_join();
        match result {
            Err(error) => Err(error),
            Ok(proof) if completion == crate::blocking_reader::WorkerCompletion::Eof => {
                self.stream_context_current(context)?;
                ensure_not_cancelled(&|| cancelled())?;
                ensure_not_cancelled(&|| cancellation.is_cancelled())?;
                Ok(proof)
            }
            Ok(_) => Err(invalid("recovery source worker did not complete safely")),
        }
    }

    /// Upload an immutable source to an existing file using its original strong
    /// ETag, then independently GET/hash the complete resulting revision.
    /// A successful PUT alone is never returned as verified delivery.
    #[allow(clippy::too_many_arguments)]
    pub fn recovery_upload_reader_with_context<R>(
        &self,
        space: &str,
        remote_root_path: &str,
        expected_root_id: &str,
        relative_path: &str,
        expected_resource_id: &str,
        expected_etag: &str,
        expected_size: u64,
        reader: R,
        content_length: u64,
        expected_sha256: [u8; 32],
        context: RangeReadContext,
    ) -> Result<RecoveryStreamReadback, CloudError>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        self.recovery_upload_reader_cancellable_with_context(
            space,
            remote_root_path,
            expected_root_id,
            relative_path,
            expected_resource_id,
            expected_etag,
            expected_size,
            reader,
            content_length,
            expected_sha256,
            context,
            Arc::new(|| false),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn recovery_upload_reader_cancellable_with_context<R>(
        &self,
        space: &str,
        remote_root_path: &str,
        expected_root_id: &str,
        relative_path: &str,
        expected_resource_id: &str,
        expected_etag: &str,
        expected_size: u64,
        reader: R,
        content_length: u64,
        expected_sha256: [u8; 32],
        context: RangeReadContext,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<RecoveryStreamReadback, CloudError>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        stream_metadata(expected_resource_id, expected_etag)?;
        self.stream_context_current(context)?;
        ensure_not_cancelled(&|| cancelled())?;
        let _guard = RangeContextGuard::enter(context);
        let path = recovery_target_path(remote_root_path, relative_path)?;
        stream_metadata_step(self, context, || {
            self.validate_recovery_root(space, remote_root_path, expected_root_id)
        })?;
        stream_metadata_step(self, context, || {
            self.stream_entry(
                space,
                &path,
                expected_resource_id,
                expected_etag,
                expected_size,
            )
        })?;
        let (selected, url) =
            stream_metadata_step(self, context, || self.transfer_url(space, &path))?;
        stream_metadata_step(self, context, || {
            self.ensure_writable_target(&selected, &url, &path)
        })?;
        self.stream_context_current(context)?;
        ensure_not_cancelled(&|| cancelled())?;
        let (request, token) = self.request_async(Method::PUT, &url)?;
        let budget = self.transfer_budget.clone();
        let cancel = budget.cancellation();
        let pause_budget = budget.clone();
        let body_cancel = cancel.clone();
        let generation = Arc::clone(&self.token_generation);
        let body_generation = Arc::clone(&generation);
        let body_job_cancelled = Arc::clone(&cancelled);
        let timeout = transfer_timeout_for_context(
            context,
            &budget,
            TransferDirection::Upload,
            content_length,
        )?;
        let verified = Arc::new(AtomicBool::new(false));
        let witness = Arc::clone(&verified);
        let result = async_body::run_body_operation_cancellable(
            self.body_idle_timeout,
            timeout,
            || {
                cancelled()
                    || pause_budget.is_paused()
                    || cancel.is_cancelled()
                    || generation.load(Ordering::Acquire) != context.token_generation
            },
            move |progress| async move {
                let body = strict_upload(StrictReader {
                    reader,
                    remaining: content_length,
                    hash: Sha256::new(),
                    digest: expected_sha256,
                    budget,
                    cancelled: move || {
                        body_job_cancelled()
                            || body_cancel.is_cancelled()
                            || body_generation.load(Ordering::Acquire) != context.token_generation
                    },
                    progress,
                    verified: witness,
                })
                .await
                .map_err(|_| invalid("recovery source validation failed"))?;
                let response = request
                    .header(CONTENT_LENGTH, content_length)
                    .header(CONTENT_TYPE, "application/octet-stream")
                    .header(IF_MATCH, expected_etag)
                    .timeout(timeout)
                    .body(reqwest::Body::wrap_stream(body))
                    .send()
                    .await
                    .map_err(network)?;
                checked_async(
                    response,
                    &[StatusCode::CREATED, StatusCode::NO_CONTENT],
                    &token,
                )?;
                Ok(())
            },
        );
        self.stream_context_current(context)?;
        ensure_not_cancelled(&|| cancelled())?;
        ensure_not_cancelled(&|| cancel.is_cancelled())?;
        result?;
        if !verified.load(Ordering::Acquire) {
            return Err(invalid("recovery source was not completely consumed"));
        }
        stream_metadata_step(self, context, || {
            self.validate_recovery_root(space, remote_root_path, expected_root_id)
        })?;
        let after = stream_metadata_step(self, context, || CloudBackend::stat(self, space, &path))?;
        validate_recovery_entry(&after, &path)?;
        stream_metadata(expected_resource_id, &after.etag)?;
        if after.id != expected_resource_id
            || after.size != content_length
            || !after.writable
            || after.directory
            || after.encrypted
        {
            return Err(conflict("recovery upload could not be verified"));
        }
        let readback = self.recovery_read_digest_cancellable_with_context(
            space,
            remote_root_path,
            expected_root_id,
            relative_path,
            expected_resource_id,
            &after.etag,
            content_length,
            expected_sha256,
            context,
            Arc::clone(&cancelled),
        )?;
        self.stream_context_current(context)?;
        ensure_not_cancelled(&|| cancelled())?;
        ensure_not_cancelled(&|| cancel.is_cancelled())?;
        Ok(readback)
    }

    /// Verify the entire decoded HTTP entity without returning its plaintext.
    /// Requires a full 200 response, exact length, strong ETag and SHA-256, plus
    /// unchanged root/resource/revision/role before and after the body.
    #[allow(clippy::too_many_arguments)]
    pub fn recovery_read_digest_with_context(
        &self,
        space: &str,
        remote_root_path: &str,
        expected_root_id: &str,
        relative_path: &str,
        expected_resource_id: &str,
        expected_etag: &str,
        expected_size: u64,
        expected_sha256: [u8; 32],
        context: RangeReadContext,
    ) -> Result<RecoveryStreamReadback, CloudError> {
        self.recovery_read_digest_cancellable_with_context(
            space,
            remote_root_path,
            expected_root_id,
            relative_path,
            expected_resource_id,
            expected_etag,
            expected_size,
            expected_sha256,
            context,
            Arc::new(|| false),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn recovery_read_digest_cancellable_with_context(
        &self,
        space: &str,
        remote_root_path: &str,
        expected_root_id: &str,
        relative_path: &str,
        expected_resource_id: &str,
        expected_etag: &str,
        expected_size: u64,
        expected_sha256: [u8; 32],
        context: RangeReadContext,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<RecoveryStreamReadback, CloudError> {
        stream_metadata(expected_resource_id, expected_etag)?;
        self.stream_context_current(context)?;
        ensure_not_cancelled(&|| cancelled())?;
        let _guard = RangeContextGuard::enter(context);
        let path = recovery_target_path(remote_root_path, relative_path)?;
        stream_metadata_step(self, context, || {
            self.validate_recovery_root(space, remote_root_path, expected_root_id)
        })?;
        stream_metadata_step(self, context, || {
            self.stream_entry(
                space,
                &path,
                expected_resource_id,
                expected_etag,
                expected_size,
            )
        })?;
        let (selected, url) =
            stream_metadata_step(self, context, || self.transfer_url(space, &path))?;
        stream_metadata_step(self, context, || {
            self.ensure_writable_target(&selected, &url, &path)
        })?;
        self.stream_context_current(context)?;
        ensure_not_cancelled(&|| cancelled())?;
        let (request, token) = self.request_async(Method::GET, &url)?;
        let budget = self.transfer_budget.clone();
        let cancel = budget.cancellation();
        let pause_budget = budget.clone();
        let body_cancel = cancel.clone();
        let generation = Arc::clone(&self.token_generation);
        let body_generation = Arc::clone(&generation);
        let body_job_cancelled = Arc::clone(&cancelled);
        let timeout = transfer_timeout_for_context(
            context,
            &budget,
            TransferDirection::Download,
            expected_size,
        )?;
        let result = async_body::run_body_operation_cancellable(
            self.body_idle_timeout,
            timeout,
            || {
                cancelled()
                    || pause_budget.is_paused()
                    || cancel.is_cancelled()
                    || generation.load(Ordering::Acquire) != context.token_generation
            },
            move |progress| async move {
                let response = request
                    .header(IF_MATCH, expected_etag)
                    .timeout(timeout)
                    .send()
                    .await
                    .map_err(network)?;
                let mut response = checked_async(response, &[StatusCode::OK], &token)?;
                if response.content_length() != Some(expected_size)
                    || response
                        .headers()
                        .contains_key(reqwest::header::CONTENT_RANGE)
                    || response.headers().get(ETAG).and_then(|v| v.to_str().ok())
                        != Some(expected_etag)
                {
                    return Err(conflict("recovery readback length or revision changed"));
                }
                let mut count = 0u64;
                let mut hash = Sha256::new();
                // Await EOF even for empty bodies. No file-sized accumulation.
                while let Some(chunk) = response.chunk().await.map_err(network)? {
                    count = count
                        .checked_add(chunk.len() as u64)
                        .ok_or_else(|| invalid("recovery readback length overflow"))?;
                    if count > expected_size {
                        return Err(invalid("recovery readback body exceeded its length"));
                    }
                    let mut offset = 0;
                    while offset < chunk.len() {
                        let cancelled = || {
                            body_job_cancelled()
                                || body_cancel.is_cancelled()
                                || body_generation.load(Ordering::Acquire)
                                    != context.token_generation
                        };
                        if cancelled() {
                            return Err(invalid("recovery readback cancelled"));
                        }
                        progress.budget_wait_started();
                        let reservation = budget
                            .acquire_cancellable_async(
                                TransferDirection::Download,
                                (chunk.len() - offset).min(CHUNK),
                                cancelled,
                            )
                            .await;
                        progress.budget_wait_finished();
                        let reservation =
                            reservation.map_err(|_| invalid("recovery readback cancelled"))?;
                        let end = offset + reservation.granted();
                        hash.update(&chunk[offset..end]);
                        reservation.settle(end - offset);
                        offset = end;
                        progress.bytes_progressed();
                    }
                }
                if count != expected_size || hash.finalize().as_slice() != expected_sha256 {
                    return Err(conflict("recovery readback content did not match"));
                }
                Ok(())
            },
        );
        self.stream_context_current(context)?;
        ensure_not_cancelled(&|| cancelled())?;
        ensure_not_cancelled(&|| cancel.is_cancelled())?;
        result?;
        stream_metadata_step(self, context, || {
            self.validate_recovery_root(space, remote_root_path, expected_root_id)
        })?;
        let entry = stream_metadata_step(self, context, || {
            self.stream_entry(
                space,
                &path,
                expected_resource_id,
                expected_etag,
                expected_size,
            )
        })?;
        self.stream_context_current(context)?;
        ensure_not_cancelled(&|| cancelled())?;
        ensure_not_cancelled(&|| cancel.is_cancelled())?;
        Ok(RecoveryStreamReadback {
            entry,
            bytes: expected_size,
            sha256: expected_sha256,
        })
    }
}

fn stream_metadata(id: &str, etag: &str) -> Result<(), CloudError> {
    if id.is_empty()
        || id.len() > MAX_DAV_ENTRY
        || id.chars().any(char::is_control)
        || !is_strong_etag(etag)
        || HeaderValue::from_str(etag).is_err()
    {
        return Err(invalid("recovery stream metadata is invalid"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "recovery_stream_tests.rs"]
mod tests;

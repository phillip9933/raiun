//! Explicit ordinary-file offline jobs; never called by implicit OS hydration.

use super::*;
use raiun_cache::{CachedPlaintextVerification, PlaintextDownloadStage};

/// A retained reservation is a local recovery condition, not cancellation
/// success. Callers must surface it without exposing private stage paths.
#[derive(Debug)]
pub enum OfflineDownloadError {
    Backend(BackendError),
    ReservationRetained { cause: BackendError },
}

impl From<BackendError> for OfflineDownloadError {
    fn from(error: BackendError) -> Self {
        Self::Backend(error)
    }
}

// Both variants keep their immutable account/root and user-intent ticket.
enum PreparedOfflineVersion<'a> {
    Existing(Box<CachedPlaintextVerification<'a>>),
    Download(Box<PlaintextDownloadStage<'a>>),
}

impl OpenCloudPlaceholderBackend {
    fn verification_stopped(&self, cancellation: &CancellationToken) -> bool {
        cancellation.is_cancelled()
            || cancellation.is_expired()
            || self.revoked.load(Ordering::Acquire)
            || self.client.token_generation() != self.token_generation
    }

    fn verification_error(&self, cancellation: &CancellationToken) -> BackendError {
        if cancellation.is_cancelled() {
            BackendError::Cancelled
        } else {
            BackendError::Unavailable
        }
    }

    /// Admit one explicit, bounded file job against its exact authenticated
    /// catalog tuple. Network and full-file hashing hold no backend/auth/cache
    /// publication guard. The caller owns scheduling, cancellation and status.
    pub fn download_file_offline_for_binding(
        &self,
        expected: &FileCacheBindingExpectation<'_>,
        cancellation: &CancellationToken,
    ) -> Result<raiun_cache::ContentRecord, OfflineDownloadError> {
        self.download_file_offline_impl(expected, None, cancellation, || {}, |_| {}, || {})
    }

    /// Acquire a member of an existing complete folder pin without creating
    /// independent per-file AlwaysOffline policy. The exact authenticated file
    /// binding and the live pin membership must both survive final publication.
    pub fn download_pinned_file_offline_for_binding(
        &self,
        expected: &FileCacheBindingExpectation<'_>,
        pin_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<raiun_cache::ContentRecord, OfflineDownloadError> {
        self.download_file_offline_impl(expected, Some(pin_id), cancellation, || {}, |_| {}, || {})
    }

    #[cfg(test)]
    pub(super) fn download_pinned_file_with_test_hook(
        &self,
        expected: &FileCacheBindingExpectation<'_>,
        pin_id: &str,
        cancellation: &CancellationToken,
        after_verification: impl FnOnce(),
    ) -> Result<raiun_cache::ContentRecord, OfflineDownloadError> {
        self.download_file_offline_impl(
            expected,
            Some(pin_id),
            cancellation,
            after_verification,
            |_| {},
            || {},
        )
    }

    #[cfg(test)]
    pub(super) fn download_file_offline_with_test_hook(
        &self,
        expected: &FileCacheBindingExpectation<'_>,
        cancellation: &CancellationToken,
        after_verification: impl FnOnce(),
    ) -> Result<raiun_cache::ContentRecord, OfflineDownloadError> {
        self.download_file_offline_impl(
            expected,
            None,
            cancellation,
            after_verification,
            |_| {},
            || {},
        )
    }

    #[cfg(test)]
    pub(super) fn download_file_offline_with_chunk_hook(
        &self,
        expected: &FileCacheBindingExpectation<'_>,
        cancellation: &CancellationToken,
        chunk_staged: impl FnMut(u64),
    ) -> Result<raiun_cache::ContentRecord, OfflineDownloadError> {
        self.download_file_offline_impl(expected, None, cancellation, || {}, chunk_staged, || {})
    }

    #[cfg(test)]
    pub(super) fn download_file_offline_with_commit_hook(
        &self,
        expected: &FileCacheBindingExpectation<'_>,
        cancellation: &CancellationToken,
        commit_admitted: impl FnOnce(),
    ) -> Result<raiun_cache::ContentRecord, OfflineDownloadError> {
        self.download_file_offline_impl(
            expected,
            None,
            cancellation,
            || {},
            |_| {},
            commit_admitted,
        )
    }

    fn download_file_offline_impl(
        &self,
        expected: &FileCacheBindingExpectation<'_>,
        pin_id: Option<&str>,
        cancellation: &CancellationToken,
        after_verification: impl FnOnce(),
        mut chunk_staged: impl FnMut(u64),
        commit_admitted: impl FnOnce(),
    ) -> Result<raiun_cache::ContentRecord, OfflineDownloadError> {
        let cache = self.cache.as_ref().ok_or(BackendError::Unavailable)?;
        let (identity, binding, prepared) = {
            let _lease = self
                .lease_gate
                .read()
                .map_err(|_| BackendError::Unavailable)?;
            check_cancel(cancellation)?;
            self.ensure_active()?;
            let (identity, binding) = self.resolve_file_cache_binding_under_lease(expected)?;
            let (scope, version) = self.content_cache_key(&binding)?;
            let entry = raiun_core::backend::RemoteEntry {
                id: binding.remote_id.clone(),
                path: binding.path.clone(),
                directory: false,
                size: binding.size,
                etag: binding.etag.clone(),
                modified_unix: 0,
                writable: false,
                encrypted: false,
            };
            let _publication = self.begin_scoped_publish(cancellation)?;
            let prepared = match cache.content_record(&scope, &version) {
                Ok(_) => PreparedOfflineVersion::Existing(Box::new(
                    match pin_id {
                        Some(pin_id) => {
                            cache.begin_cached_plaintext_pin_verification(&scope, &entry, pin_id)
                        }
                        None => cache.begin_cached_plaintext_offline_verification(&scope, &entry),
                    }
                    .map_err(|_| BackendError::Unavailable)?,
                )),
                Err(raiun_cache::CacheError::NotFound) => {
                    PreparedOfflineVersion::Download(Box::new(
                        match pin_id {
                            Some(pin_id) => {
                                cache.begin_plaintext_pin_download(&scope, &entry, pin_id)
                            }
                            None => cache.begin_plaintext_offline_download(&scope, &entry),
                        }
                        .map_err(|_| BackendError::Unavailable)?,
                    ))
                }
                Err(_) => return Err(BackendError::Unavailable.into()),
            };
            (identity, binding, prepared)
        };
        let verified = match prepared {
            PreparedOfflineVersion::Existing(existing) => {
                check_cancel(cancellation)?;
                existing
                    .finish_cancellable(|| self.verification_stopped(cancellation))
                    .map_err(|_| self.verification_error(cancellation))?
            }
            PreparedOfflineVersion::Download(mut stage) => {
                let transfer = (|| -> Result<(), BackendError> {
                    let mut offset = 0_u64;
                    let mut buffer = vec![
                        0_u8;
                        usize::try_from(binding.size.min(1024 * 1024))
                            .map_err(|_| BackendError::InvalidRange)?
                    ];
                    // The zero-length request still checks current root, ancestors,
                    // resource, strong ETag and size; it does not invent an empty hit.
                    loop {
                        check_cancel(cancellation)?;
                        self.ensure_active()?;
                        let length =
                            usize::try_from((binding.size - offset).min(buffer.len() as u64))
                                .map_err(|_| BackendError::InvalidRange)?;
                        let count = self
                            .client
                            .read_callback_range_cancellable_with_context(
                                RemoteRangeRequest {
                                    space: &binding.space_id,
                                    expected_root_id: &binding.root_resource_id,
                                    path: &binding.path,
                                    expected_id: &binding.remote_id,
                                    expected_etag: &binding.etag,
                                    expected_size: binding.size,
                                    offset,
                                },
                                &mut buffer[..length],
                                RangeReadContext {
                                    deadline: cancellation.request_deadline(),
                                    token_generation: self.token_generation,
                                },
                                || {
                                    cancellation.is_cancelled()
                                        || cancellation.is_expired()
                                        || self.revoked.load(Ordering::Acquire)
                                        || self.client.token_generation() != self.token_generation
                                },
                            )
                            .map_err(|error| self.reject_cached_cloud_error(error))?;
                        if count != length {
                            return Err(BackendError::Unavailable);
                        }
                        stage
                            .append(offset, &buffer[..count])
                            .map_err(|_| BackendError::Unavailable)?;
                        offset = offset
                            .checked_add(count as u64)
                            .ok_or(BackendError::InvalidRange)?;
                        chunk_staged(offset);
                        if offset == binding.size {
                            break;
                        }
                    }
                    check_cancel(cancellation)?;
                    Ok(())
                })();
                if let Err(error) = transfer {
                    // Only this typed, unfinished GET reservation is eligible.
                    // A cleanup failure leaves its bytes charged and preserved.
                    if stage.abort().is_err() {
                        return Err(OfflineDownloadError::ReservationRetained { cause: error });
                    }
                    return Err(error.into());
                }
                stage
                    .finish_cancellable(|| self.verification_stopped(cancellation))
                    .map_err(|_| OfflineDownloadError::ReservationRetained {
                        cause: self.verification_error(cancellation),
                    })?
            }
        };
        after_verification();
        // A root/catalog replacement must take the write lease. Hold this read
        // lease only for the final identity check and short durable transaction.
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        check_cancel(cancellation)?;
        self.ensure_active()?;
        let (current_identity, current_binding) =
            self.resolve_file_cache_binding_under_lease(expected)?;
        if current_identity != identity || current_binding != binding {
            return Err(BackendError::NotFound.into());
        }
        let _publication = self.begin_scoped_publish(cancellation)?;
        check_cancel(cancellation)?;
        self.ensure_active()?;
        // Cancellation is cooperative: this successful final admission is
        // the point after which completion may win a concurrent cancellation.
        // The short durable transaction is not interrupted or rolled back by
        // a later flag change. Auth/root and intent fences still span it.
        commit_admitted();
        // Both exact-root lease and token-generation permit span the commit;
        // the cache additionally fences current metadata and durable intent.
        verified
            .commit()
            .map_err(|_| OfflineDownloadError::Backend(BackendError::Unavailable))
        // Report the durable outcome even if cancellation raced after admission.
    }
}

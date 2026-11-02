//! One live encrypted child FILE create. Original private source custody and
//! native completion belong to the caller; this helper never queues or replays.
use super::*;
use std::time::Duration;
pub struct VaultChildFileCreateRequest<'a> {
    pub scope: &'a VaultSessionScope,
    pub epoch: &'a VaultSessionEpoch,
    pub vault_root_path: &'a str,
    pub logical_path: &'a str,
    pub parent_resource_id: &'a str,
    pub parent_etag: &'a str,
    pub expected_token_generation: u64,
    pub provider_generation: Arc<AtomicU64>,
    pub expected_provider_generation: u64,
    pub deadline: Instant,
    pub cancelled: &'a dyn Fn() -> bool,
}
pub struct VaultChildFileCreateTarget {
    scope: VaultSessionScope,
    epoch: VaultSessionEpoch,
    root_path: String,
    logical_path: String,
    parent_id: String,
    parent_etag: String,
    encoded_target: String,
    integrity_token: String,
    token_generation: u64,
    provider_generation: Arc<AtomicU64>,
    expected_provider_generation: u64,
    plaintext_len: u64,
    plaintext_sha256: [u8; 32],
}
impl VaultChildFileCreateTarget {
    pub fn encoded_target(&self) -> &str {
        &self.encoded_target
    }
    pub fn integrity_token(&self) -> &str {
        &self.integrity_token
    }
}
pub struct VaultVerifiedChildFile {
    entry: RemoteEntry,
    target: VaultChildFileCreateTarget,
}
impl VaultVerifiedChildFile {
    pub fn entry(&self) -> &RemoteEntry {
        &self.entry
    }
    pub fn scope(&self) -> &VaultSessionScope {
        &self.target.scope
    }
    pub fn matches_epoch(&self, epoch: &VaultSessionEpoch) -> bool {
        self.target.epoch.same_identity(epoch)
    }
    pub fn root_path(&self) -> &str {
        &self.target.root_path
    }
    pub fn parent_resource_id(&self) -> &str {
        &self.target.parent_id
    }
    pub fn token_generation(&self) -> u64 {
        self.target.token_generation
    }
    pub fn plaintext_sha256(&self) -> [u8; 32] {
        self.target.plaintext_sha256
    }
    pub fn provider_current(&self, generation: &Arc<AtomicU64>, expected: u64) -> bool {
        Arc::ptr_eq(generation, &self.target.provider_generation)
            && expected == self.target.expected_provider_generation
            && generation.load(Ordering::Acquire) == expected
    }
}
pub enum VaultChildFileCreateOutcome {
    Verified(VaultVerifiedChildFile),
    NeedsReconciliation { reason: ErrorKind },
}
fn local(backend: &VaultBackend, r: &VaultChildFileCreateRequest<'_>) -> Result<(), CloudError> {
    if (r.cancelled)()
        || Instant::now() >= r.deadline
        || backend.client.token_generation() != r.expected_token_generation
        || r.provider_generation.load(Ordering::Acquire) != r.expected_provider_generation
    {
        return Err(conflict("encrypted file create admission changed"));
    }
    Ok(())
}
fn metadata_context(
    r: &VaultChildFileCreateRequest<'_>,
) -> Result<crate::RangeContextGuard, CloudError> {
    let deadline = (Instant::now() + Duration::from_secs(30)).min(r.deadline);
    let context = RangeReadContext {
        deadline,
        token_generation: r.expected_token_generation,
    };
    context.remaining()?;
    Ok(crate::RangeContextGuard::enter(context))
}
impl VaultBackend {
    fn check_child_file_context(
        &self,
        r: &VaultChildFileCreateRequest<'_>,
    ) -> Result<(), CloudError> {
        local(self, r)?;
        if self.offline_only
            || self.offline_cache.is_some()
            || self.offline_root.is_some()
            || r.scope != &self.scope
            || r.vault_root_path != self.root_path
            || r.logical_path == "/"
            || normalize_virtual_path(r.logical_path)? != r.logical_path
            || r.expected_token_generation == 0
            || r.expected_provider_generation == 0
            || r.parent_resource_id.is_empty()
            || r.parent_resource_id.len() > 4096
            || r.parent_resource_id.chars().any(char::is_control)
        {
            return Err(conflict("encrypted file create context changed"));
        }
        validate_virtual_path(r.logical_path)?;
        validate_existing_overwrite_etag(r.parent_etag)?;
        self.sessions
            .try_lock_session_epoch(r.scope, r.epoch)
            .map_err(vault_error)?
            .ok_or_else(|| conflict("original file create unlock is unavailable"))?;
        Ok(())
    }
    /// Bounded metadata-only admission for either child kind. Directory ETag is
    /// captured freshly; original opaque directory ID/path cannot be adopted anew.
    pub fn child_create_parent_at_epoch_with_context(
        &self,
        scope: &VaultSessionScope,
        epoch: &VaultSessionEpoch,
        parent: &RemoteEntry,
        context: RangeReadContext,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<RemoteEntry, CloudError> {
        let _context = crate::RangeContextGuard::enter(context);
        self.client.ensure_context_current(context)?;
        if scope != &self.scope || !parent.directory || (cancelled)() {
            return Err(conflict("vault child parent context changed"));
        }
        self.sessions
            .try_lock_session_epoch(scope, epoch)
            .map_err(vault_error)?
            .ok_or_else(|| conflict("vault child parent unlock changed"))?;
        let state = self.revalidate_root()?;
        let fresh = self.stat_raw(&state, &parent.path)?;
        if !fresh.directory
            || !fresh.writable
            || fresh.id != parent.id
            || fresh.path != parent.path
            || !state.space.writable
        {
            return Err(conflict("vault child parent identity or role changed"));
        }
        validate_existing_overwrite_etag(&fresh.etag)?;
        self.client.ensure_context_current(context)?;
        self.sessions
            .try_lock_session_epoch(scope, epoch)
            .map_err(vault_error)?
            .ok_or_else(|| conflict("vault child parent unlock changed"))?;
        if (cancelled)() {
            return Err(conflict("vault child parent cancelled"));
        }
        Ok(fresh)
    }
    pub fn prepare_child_file_create_guarded(
        &self,
        r: &VaultChildFileCreateRequest<'_>,
        len: u64,
        sha: [u8; 32],
    ) -> Result<VaultChildFileCreateTarget, CloudError> {
        let _context = metadata_context(r)?;
        self.check_child_file_context(r)?;
        if len > (1 << 30) || sha == [0; 32] {
            return Err(invalid("encrypted file create source exceeds its bound"));
        }
        let state = self.revalidate_root()?;
        if self.current_parent_binding(r.logical_path)?
            != (r.parent_resource_id.to_owned(), r.parent_etag.to_owned())
        {
            return Err(conflict("encrypted file create parent changed"));
        }
        let encoded = self.prepare_file_create_target_for_parent(
            r.logical_path,
            &VaultPendingParentRef::Stable {
                resource_id: r.parent_resource_id.to_owned(),
            },
            None,
        )?;
        let fresh = self.revalidate_root()?;
        self.check_child_file_context(r)?;
        if fresh.integrity_token != state.integrity_token
            || self.current_parent_binding(r.logical_path)?
                != (r.parent_resource_id.to_owned(), r.parent_etag.to_owned())
        {
            return Err(conflict("encrypted file create preparation changed"));
        }
        Ok(VaultChildFileCreateTarget {
            scope: r.scope.clone(),
            epoch: r.epoch.clone(),
            root_path: r.vault_root_path.to_owned(),
            logical_path: r.logical_path.to_owned(),
            parent_id: r.parent_resource_id.to_owned(),
            parent_etag: r.parent_etag.to_owned(),
            encoded_target: encoded,
            integrity_token: state.integrity_token,
            token_generation: r.expected_token_generation,
            provider_generation: r.provider_generation.clone(),
            expected_provider_generation: r.expected_provider_generation,
            plaintext_len: len,
            plaintext_sha256: sha,
        })
    }
    /// Original source is already private/durable. The hook is one local-only
    /// native proof and durable send claim; all later failures are uncertain.
    pub fn create_child_file_guarded<R: Read>(
        &self,
        r: &VaultChildFileCreateRequest<'_>,
        target: VaultChildFileCreateTarget,
        source: &mut R,
        private_ciphertext_directory: &Path,
        before_send: &mut dyn FnMut() -> Result<(), CloudError>,
    ) -> Result<VaultChildFileCreateOutcome, CloudError> {
        self.check_child_file_context(r)?;
        if target.scope != *r.scope
            || !target.epoch.same_identity(r.epoch)
            || target.root_path != r.vault_root_path
            || target.logical_path != r.logical_path
            || target.parent_id != r.parent_resource_id
            || target.parent_etag != r.parent_etag
            || target.token_generation != r.expected_token_generation
            || !Arc::ptr_eq(&target.provider_generation, &r.provider_generation)
            || target.expected_provider_generation != r.expected_provider_generation
        {
            return Err(conflict("encrypted file create target changed"));
        }
        let directory = fs::symlink_metadata(private_ciphertext_directory).map_err(io_error)?;
        if !directory.is_dir() || directory.file_type().is_symlink() {
            return Err(invalid("private encrypted create staging unavailable"));
        }
        let temp = tempfile::tempdir_in(private_ciphertext_directory).map_err(io_error)?;
        let cipher_path = temp.path().join("source-ciphertext");
        let mut input = HashReader {
            input: source,
            backend: self,
            request: r,
            hash: Sha256::new(),
            len: 0,
            eof: false,
            expected: target.plaintext_len,
        };
        self.sessions
            .encrypt_file_transactional_at_epoch(
                r.scope,
                r.epoch,
                &mut input,
                &cipher_path,
                target.plaintext_len,
                1 << 30,
            )
            .map_err(vault_error)?;
        input.verify(target.plaintext_sha256)?;
        self.check_child_file_context(r)?;
        let (url, parent_url) = {
            let _context = metadata_context(r)?;
            let state = self.revalidate_root()?;
            if state.integrity_token != target.integrity_token
                || self.current_parent_binding(r.logical_path)?
                    != (target.parent_id.clone(), target.parent_etag.clone())
                || self.prepare_file_create_target(r.logical_path, None)? != target.encoded_target
            {
                return Err(conflict("encrypted file create baseline changed"));
            }
            let physical = format!(
                "{}/{}",
                self.root_path.trim_end_matches('/'),
                target.encoded_target
            );
            (
                self.url_for_physical(&state, &physical)?,
                self.target_url(&state, &logical_parent(r.logical_path))?,
            )
        };
        let ciphertext = File::open(&cipher_path).map_err(io_error)?;
        let ciphertext_len = ciphertext.metadata().map_err(io_error)?.len();
        let budget = self.client.transfer_budget();
        let cancellation = budget.cancellation();
        let timeout =
            crate::transfer_timeout_with_budget(&budget, TransferDirection::Upload, ciphertext_len)
                .min(r.deadline.saturating_duration_since(Instant::now()));
        if timeout.is_zero() {
            return Err(conflict("encrypted file create expired"));
        }
        let context = RangeReadContext {
            deadline: Instant::now() + timeout,
            token_generation: r.expected_token_generation,
        };
        let (request, token) =
            self.client
                .request_async_with_context(Method::PUT, &url, Some(context))?;
        let request = request
            .header(IF_NONE_MATCH, "*")
            .header("If", format!("<{parent_url}> ([{}])", target.parent_etag))
            .header(CONTENT_LENGTH, ciphertext_len)
            .header(CONTENT_TYPE, "application/octet-stream");
        self.check_child_file_context(r)?;
        before_send()?;
        self.check_child_file_context(r)?;
        let watchdog_cancellation = cancellation.clone();
        let body_tokens = self.client.token_generation.clone();
        let body_provider = r.provider_generation.clone();
        let expected_token = r.expected_token_generation;
        let expected_provider = r.expected_provider_generation;
        let deadline = r.deadline;
        let result = (|| {
            crate::async_body::run_body_operation_cancellable(
                self.client.body_idle_timeout(),
                timeout,
                || {
                    self.check_child_file_context(r).is_err()
                        || watchdog_cancellation.is_cancelled()
                },
                move |progress| async move {
                    let stream = crate::async_body::budgeted_upload_stream(
                        tokio::fs::File::from_std(ciphertext),
                        ciphertext_len,
                        budget,
                        move || {
                            Instant::now() >= deadline
                                || body_tokens.load(Ordering::Acquire) != expected_token
                                || body_provider.load(Ordering::Acquire) != expected_provider
                                || cancellation.is_cancelled()
                        },
                        progress,
                    );
                    let response = request
                        .timeout(timeout)
                        .body(reqwest::Body::wrap_stream(stream))
                        .send()
                        .await
                        .map_err(network)?;
                    crate::checked_async(response, &[StatusCode::CREATED], &token)?;
                    Ok(())
                },
            )?;
            self.check_child_file_context(r)?;
            let entry = {
                let _context = metadata_context(r)?;
                let state = self.revalidate_root()?;
                if state.integrity_token != target.integrity_token {
                    return Err(conflict("vault create root changed"));
                }
                let entry = self.stat_raw(&state, r.logical_path)?;
                let (_, parent) = self.parent_listing(&state, r.logical_path)?;
                if entry.directory
                    || entry.id.is_empty()
                    || entry.id == target.parent_id
                    || entry.id == r.scope.resource_id()
                    || entry.path != r.logical_path
                    || entry.size != target.plaintext_len
                    || parent.root.id != target.parent_id
                    || !parent.root.writable
                {
                    return Err(conflict("encrypted created file binding changed"));
                }
                validate_existing_overwrite_etag(&entry.etag)?;
                entry
            };
            self.authenticate_created_file(r, &target, &entry, temp.path())?;
            Ok(entry)
        })();
        Ok(match result {
            Ok(entry) => {
                VaultChildFileCreateOutcome::Verified(VaultVerifiedChildFile { entry, target })
            }
            Err(error) => VaultChildFileCreateOutcome::NeedsReconciliation { reason: error.kind },
        })
    }
    fn authenticate_created_file(
        &self,
        r: &VaultChildFileCreateRequest<'_>,
        target: &VaultChildFileCreateTarget,
        entry: &RemoteEntry,
        private: &Path,
    ) -> Result<(), CloudError> {
        let url = {
            let _context = metadata_context(r)?;
            let state = self.revalidate_root()?;
            if state.integrity_token != target.integrity_token {
                return Err(conflict("created vault root changed"));
            }
            let root =
                Url::parse(&state.space_dav_root).map_err(|_| invalid("vault DAV root invalid"))?;
            let root_entry = self.client.stat_at_dav(&root, "/")?;
            if !root_entry.directory || !root_entry.writable || !state.space.writable {
                return Err(conflict("created file Space root changed"));
            }
            super::super::conditional_delete::resource_delete_url(
                &self.client.server,
                &root,
                &state.space.id,
                &root_entry.id,
                &entry.id,
            )?
        };
        let path = private.join("readback-ciphertext");
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(io_error)?;
        let len = ciphertext_len_from_plaintext(target.plaintext_len)?;
        let budget = self.client.transfer_budget();
        let cancellation = budget.cancellation();
        let timeout =
            crate::transfer_timeout_with_budget(&budget, TransferDirection::Download, len)
                .min(r.deadline.saturating_duration_since(Instant::now()));
        if timeout.is_zero() {
            return Err(conflict("encrypted create readback expired"));
        }
        let context = RangeReadContext {
            deadline: Instant::now() + timeout,
            token_generation: r.expected_token_generation,
        };
        let (request, token) =
            self.client
                .request_async_with_context(Method::GET, &url, Some(context))?;
        let watchdog_cancellation = cancellation.clone();
        let copied = crate::async_body::run_body_operation_cancellable(
            self.client.body_idle_timeout(),
            timeout,
            || self.check_child_file_context(r).is_err() || watchdog_cancellation.is_cancelled(),
            move |progress| async move {
                let response = request
                    .header(IF_MATCH, &entry.etag)
                    .timeout(timeout)
                    .send()
                    .await
                    .map_err(network)?;
                let mut response = crate::checked_async(response, &[StatusCode::OK], &token)?;
                if response.content_length() != Some(len) {
                    return Err(conflict("encrypted create readback size changed"));
                }
                let mut output = tokio::fs::File::from_std(output);
                let copied = crate::async_body::copy_response_body(
                    &mut response,
                    &mut output,
                    len,
                    &budget,
                    || local(self, r).is_err() || cancellation.is_cancelled(),
                    &progress,
                )
                .await?;
                use tokio::io::AsyncWriteExt;
                output.flush().await.map_err(io_error)?;
                output.sync_all().await.map_err(io_error)?;
                Ok(copied)
            },
        )?;
        if copied != len {
            return Err(conflict("encrypted create readback incomplete"));
        }
        self.check_child_file_context(r)?;
        let mut input = File::open(&path).map_err(io_error)?;
        let mut sink = HashSink {
            backend: self,
            request: r,
            hash: Sha256::new(),
            len: 0,
            expected: target.plaintext_len,
        };
        self.sessions
            .decrypt_file_to_private_writer_at_epoch(
                r.scope,
                r.epoch,
                &mut input,
                &mut sink,
                1 << 30,
                target.plaintext_len,
            )
            .map_err(vault_error)?;
        sink.verify(target.plaintext_sha256)?;
        self.check_child_file_context(r)?;
        let _context = metadata_context(r)?;
        let state = self.revalidate_root()?;
        let after = self.stat_raw(&state, r.logical_path)?;
        let (_, parent) = self.parent_listing(&state, r.logical_path)?;
        if state.integrity_token != target.integrity_token
            || after.id != entry.id
            || after.etag != entry.etag
            || after.size != entry.size
            || after.path != entry.path
            || after.directory
            || parent.root.id != target.parent_id
            || !parent.root.writable
        {
            return Err(conflict(
                "encrypted created file changed after authentication",
            ));
        }
        self.check_child_file_context(r)
    }
}
struct HashReader<'a, 'r, R> {
    input: &'a mut R,
    backend: &'a VaultBackend,
    request: &'a VaultChildFileCreateRequest<'r>,
    hash: Sha256,
    len: u64,
    eof: bool,
    expected: u64,
}
impl<R: Read> Read for HashReader<'_, '_, R> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        local(self.backend, self.request)
            .map_err(|_| io::Error::other("vault create cancelled"))?;
        let n = self.input.read(b)?;
        let len = self
            .len
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("vault create size overflow"))?;
        if len > self.expected {
            return Err(io::Error::other("vault create source length changed"));
        }
        self.len = len;
        self.hash.update(&b[..n]);
        if n == 0 && !b.is_empty() {
            self.eof = true;
        }
        Ok(n)
    }
}
impl<R: Read> HashReader<'_, '_, R> {
    fn verify(self, sha: [u8; 32]) -> Result<(), CloudError> {
        let actual: [u8; 32] = self.hash.finalize().into();
        if !self.eof || self.len != self.expected || actual != sha {
            return Err(conflict("vault create source digest changed"));
        }
        Ok(())
    }
}
struct HashSink<'a, 'r> {
    backend: &'a VaultBackend,
    request: &'a VaultChildFileCreateRequest<'r>,
    hash: Sha256,
    len: u64,
    expected: u64,
}
impl Write for HashSink<'_, '_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        local(self.backend, self.request)
            .map_err(|_| io::Error::other("vault create cancelled"))?;
        let len = self
            .len
            .checked_add(b.len() as u64)
            .ok_or_else(|| io::Error::other("vault readback size overflow"))?;
        if len > self.expected {
            return Err(io::Error::other("vault readback exceeds captured length"));
        }
        self.len = len;
        self.hash.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        local(self.backend, self.request).map_err(|_| io::Error::other("vault create cancelled"))
    }
}
impl HashSink<'_, '_> {
    fn verify(self, sha: [u8; 32]) -> Result<(), CloudError> {
        let actual: [u8; 32] = self.hash.finalize().into();
        if self.len != self.expected || actual != sha {
            return Err(conflict("vault create authenticated readback mismatch"));
        }
        Ok(())
    }
}

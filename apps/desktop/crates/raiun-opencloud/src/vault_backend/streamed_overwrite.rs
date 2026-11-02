//! Streamed existing-file overwrite using the existing vault codec. Only
//! ciphertext enters private temporary storage. Neither reader nor digest sink
//! performs registry re-entry or network I/O while exact-epoch crypto runs.
use super::*;

/// Separate bounded streaming admission; the legacy whole-body API stays512KiB.
pub const MAX_GUARDED_VAULT_STREAMED_OVERWRITE_BYTES: u64 = 1024 * 1024 * 1024;

pub(super) struct DigestReader<'a, 'g, R> {
    source: &'a mut R,
    backend: &'a VaultBackend,
    guard: &'a ExistingOverwriteGuard<'g>,
    digest: Sha256,
    bytes: u64,
    eof: bool,
}
impl<'a, 'g, R: Read> DigestReader<'a, 'g, R> {
    pub(super) fn new(
        source: &'a mut R,
        backend: &'a VaultBackend,
        guard: &'a ExistingOverwriteGuard<'g>,
    ) -> Self {
        Self {
            source,
            backend,
            guard,
            digest: Sha256::new(),
            bytes: 0,
            eof: false,
        }
    }
    pub(super) fn verify(self, expected: [u8; 32]) -> Result<(), CloudError> {
        self.guard.check_local(self.backend)?;
        let digest: [u8; 32] = self.digest.finalize().into();
        if !self.eof || self.bytes != self.guard.plaintext_len || digest != expected {
            return Err(conflict("encrypted stream source digest or length changed"));
        }
        Ok(())
    }
}
impl<R: Read> Read for DigestReader<'_, '_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.guard
            .check_local(self.backend)
            .map_err(stream_unavailable)?;
        let read = self.source.read(buffer)?;
        self.guard
            .check_local(self.backend)
            .map_err(stream_unavailable)?;
        let bytes = self
            .bytes
            .checked_add(read as u64)
            .ok_or_else(stream_overflow)?;
        if bytes > self.guard.plaintext_len || bytes > self.guard.maximum_plaintext_len {
            return Err(stream_overflow());
        }
        self.digest.update(&buffer[..read]);
        self.bytes = bytes;
        if read == 0 && !buffer.is_empty() {
            self.eof = true;
        }
        Ok(read)
    }
}
struct DigestSink<'a, 'g> {
    backend: &'a VaultBackend,
    guard: &'a ExistingOverwriteGuard<'g>,
    digest: Sha256,
    bytes: u64,
}
impl<'a, 'g> DigestSink<'a, 'g> {
    fn new(backend: &'a VaultBackend, guard: &'a ExistingOverwriteGuard<'g>) -> Self {
        Self {
            backend,
            guard,
            digest: Sha256::new(),
            bytes: 0,
        }
    }
    fn verify(self, expected: [u8; 32]) -> Result<(), CloudError> {
        self.guard.check_local(self.backend)?;
        let digest: [u8; 32] = self.digest.finalize().into();
        if self.bytes != self.guard.plaintext_len || digest != expected {
            return Err(conflict(
                "authenticated encrypted stream readback did not match",
            ));
        }
        Ok(())
    }
}
impl Write for DigestSink<'_, '_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.guard
            .check_local(self.backend)
            .map_err(stream_unavailable)?;
        let bytes = self
            .bytes
            .checked_add(buffer.len() as u64)
            .ok_or_else(stream_overflow)?;
        if bytes > self.guard.plaintext_len || bytes > self.guard.maximum_plaintext_len {
            return Err(stream_overflow());
        }
        self.digest.update(buffer);
        self.bytes = bytes;
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.guard
            .check_local(self.backend)
            .map_err(stream_unavailable)
    }
}
fn stream_unavailable(_: CloudError) -> io::Error {
    io::Error::other("encrypted stream admission is no longer current")
}
fn stream_overflow() -> io::Error {
    io::Error::other("encrypted stream exceeds its captured length")
}
impl VaultBackend {
    fn validate_streamed_overwrite_context(
        &self,
        request: &VaultExistingOverwriteRequest<'_>,
        plaintext_len: u64,
        private_ciphertext_directory: &Path,
    ) -> Result<(), CloudError> {
        if self.offline_only || self.offline_cache.is_some() || self.offline_root.is_some() {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "guarded streamed overwrite requires an online cache-free backend",
            ));
        }
        if request.scope != &self.scope
            || request.vault_root_path != self.root_path
            || request.logical_path == "/"
            || normalize_virtual_path(request.logical_path)? != request.logical_path
            || request.original_resource_id.trim().is_empty()
            || request.original_resource_id.len() > 4096
            || request.original_resource_id.chars().any(char::is_control)
            || request.expected_token_generation == 0
            || request.expected_provider_generation == 0
            || plaintext_len > MAX_GUARDED_VAULT_STREAMED_OVERWRITE_BYTES
        {
            return Err(invalid("invalid guarded encrypted stream context"));
        }
        validate_virtual_path(request.logical_path)?;
        validate_existing_overwrite_etag(request.original_etag)?;
        let directory = fs::symlink_metadata(private_ciphertext_directory).map_err(io_error)?;
        if !directory.is_dir() || directory.file_type().is_symlink() {
            return Err(invalid("encrypted stream private staging is unavailable"));
        }
        Ok(())
    }

    /// Consume a fresh, immutable authenticated reader once, encrypting through
    /// the existing exact live epoch. Hash/count the actual encoded plaintext
    /// before any PUT, then authenticate the full returned ciphertext into a
    /// digest sink. No seek, whole-body buffer, plaintext temporary file, queue,
    /// epoch restoration, changed-baseline adoption or automatic retry exists.
    /// The caller retains its original account/root/native source custody and
    /// admitted private ciphertext directory throughout this call.
    pub fn overwrite_existing_streamed_reader_guarded<R: Read>(
        &self,
        request: &VaultExistingOverwriteRequest<'_>,
        source: &mut R,
        plaintext_len: u64,
        expected_plaintext_sha256: [u8; 32],
        private_ciphertext_directory: &Path,
    ) -> Result<VaultExistingOverwriteOutcome, CloudError> {
        self.validate_streamed_overwrite_context(
            request,
            plaintext_len,
            private_ciphertext_directory,
        )?;
        let guard = ExistingOverwriteGuard {
            request,
            plaintext_len,
            private_ciphertext_directory,
            maximum_plaintext_len: MAX_GUARDED_VAULT_STREAMED_OVERWRITE_BYTES,
            expected_plaintext_sha256: Some(expected_plaintext_sha256),
            dispatched: Cell::new(false),
        };
        let result = (|| {
            guard.check(self)?;
            let decoded = self
                .sessions
                .decrypt_path_at_epoch(request.scope, request.epoch, request.encoded_target)
                .map_err(vault_error)?;
            if format!("/{}", decoded.components().collect::<Vec<_>>().join("/"))
                != request.logical_path
            {
                return Err(conflict("encrypted stream encoded target changed"));
            }
            let condition = WriteCondition::Match(request.original_etag.to_owned());
            let admitted = self.prepare_write_target(request.logical_path, &condition)?;
            if admitted != request.encoded_target {
                return Err(conflict("encrypted stream admission target changed"));
            }
            guard.check(self)?;
            let state = self.revalidate_root()?;
            guard.check(self)?;
            guard.check_original(&self.stat_raw(&state, request.logical_path)?)?;
            guard.check(self)?;
            let cancelled = || guard.check(self).is_err();
            let uploaded = self.put_vault_reader_inner(
                &state,
                request.logical_path,
                source,
                plaintext_len,
                condition,
                VaultPutOptions {
                    expectation: VaultPutExpectation {
                        encoded_target: Some(request.encoded_target),
                        parent_binding: None,
                        expected_token_generation: Some(request.expected_token_generation),
                        external_token_generation: Some((
                            Arc::clone(&request.provider_generation),
                            request.expected_provider_generation,
                        )),
                        caller_cancelled: Some(&cancelled),
                    },
                    guarded: Some(&guard),
                },
            )?;
            self.readback_streamed_overwrite(&guard, &uploaded, expected_plaintext_sha256)
        })();
        match result {
            Ok(verified) => Ok(VaultExistingOverwriteOutcome::Verified(verified)),
            Err(error) if guard.dispatched.get() => {
                Ok(VaultExistingOverwriteOutcome::NeedsReconciliation { reason: error.kind })
            }
            Err(error) => Err(error),
        }
    }

    /// Read-only full authenticated digest verification of an already returned
    /// overwrite revision. This sends no PUT and grants no local cleanup, retry
    /// or in-sync authority; the caller must retain original operation custody.
    pub fn verify_existing_streamed_readback_guarded(
        &self,
        request: &VaultExistingOverwriteRequest<'_>,
        uploaded: &RemoteEntry,
        plaintext_len: u64,
        expected_plaintext_sha256: [u8; 32],
        private_ciphertext_directory: &Path,
    ) -> Result<VaultVerifiedOverwrite, CloudError> {
        self.validate_streamed_overwrite_context(
            request,
            plaintext_len,
            private_ciphertext_directory,
        )?;
        let guard = ExistingOverwriteGuard {
            request,
            plaintext_len,
            private_ciphertext_directory,
            maximum_plaintext_len: MAX_GUARDED_VAULT_STREAMED_OVERWRITE_BYTES,
            expected_plaintext_sha256: Some(expected_plaintext_sha256),
            dispatched: Cell::new(false),
        };
        guard.check(self)?;
        let decoded = self
            .sessions
            .decrypt_path_at_epoch(request.scope, request.epoch, request.encoded_target)
            .map_err(vault_error)?;
        if format!("/{}", decoded.components().collect::<Vec<_>>().join("/"))
            != request.logical_path
        {
            return Err(conflict("encrypted readback encoded target changed"));
        }
        self.readback_streamed_overwrite(&guard, uploaded, expected_plaintext_sha256)
    }

    fn readback_streamed_overwrite(
        &self,
        guard: &ExistingOverwriteGuard<'_>,
        uploaded: &RemoteEntry,
        expected_plaintext_sha256: [u8; 32],
    ) -> Result<VaultVerifiedOverwrite, CloudError> {
        let request = guard.request;
        validate_existing_overwrite_etag(&uploaded.etag)?;
        if uploaded.directory
            || uploaded.id != request.original_resource_id
            || uploaded.path != request.logical_path
            || uploaded.size != guard.plaintext_len
            || uploaded.etag == request.original_etag
        {
            return Err(conflict(
                "encrypted overwrite returned a different binding or unchanged revision",
            ));
        }
        guard.check(self)?;
        let fresh = self.revalidate_root()?;
        guard.check(self)?;
        let mut sink = DigestSink::new(self, guard);
        // This nominal name is never opened as plaintext; only ciphertext is
        // spooled beneath its admitted parent, and plaintext flows to the sink.
        let nominal = guard
            .private_ciphertext_directory
            .join("unpublished-streamed-readback");
        let verified = self.download_vault_inner_with_options(
            &fresh,
            request.logical_path,
            Some(&uploaded.etag),
            &nominal,
            VaultDownloadOptions {
                pin: None,
                ciphertext_digest: None,
                output: Some(&mut sink),
                guarded: Some(guard),
            },
        )?;
        sink.verify(expected_plaintext_sha256)?;
        guard.check(self)?;
        if verified.id != request.original_resource_id
            || verified.etag != uploaded.etag
            || verified.size != guard.plaintext_len
            || verified.path != request.logical_path
            || verified.directory
        {
            return Err(conflict(
                "encrypted stream authenticated readback binding changed",
            ));
        }
        let final_root = self.revalidate_root()?;
        guard.check(self)?;
        let final_entry = self.stat_raw(&final_root, request.logical_path)?;
        guard.check(self)?;
        if final_entry.id != verified.id
            || final_entry.etag != verified.etag
            || final_entry.size != verified.size
            || final_entry.directory
            || final_entry.path != verified.path
        {
            return Err(conflict(
                "encrypted stream changed after authenticated readback",
            ));
        }
        Ok(VaultVerifiedOverwrite {
            entry: verified,
            plaintext_sha256: expected_plaintext_sha256,
        })
    }

    /// ID-only original ciphertext endpoint. The Space root witness is fresh;
    /// the existing helper validates provider/Space/root concordance against
    /// both the discovered DAV reference and full original resource ID.
    pub(super) fn streamed_overwrite_resource_url(
        &self,
        state: &RootState,
        guard: &ExistingOverwriteGuard<'_>,
    ) -> Result<Url, CloudError> {
        guard.check(self)?;
        let root = Url::parse(&state.space_dav_root)
            .map_err(|_| invalid("vault Space DAV root is invalid"))?;
        let entry = self.client.stat_at_dav(&root, "/")?;
        guard.check(self)?;
        if !entry.directory || !entry.writable || !state.space.writable {
            return Err(conflict("encrypted overwrite Space root is unavailable"));
        }
        super::super::conditional_delete::resource_delete_url(
            &self.client.server,
            &root,
            &state.space.id,
            &entry.id,
            guard.request.original_resource_id,
        )
    }
}

impl WindowsVaultPlaceholderBackend {
    pub(crate) fn begin_file_delete(
        &self,
        d: &crate::vault_file_delete::VaultFileDeleteDescriptor,
    ) -> Result<Arc<dyn crate::vault_file_delete::VaultFileDeleteRecord>, BackendError> {
        d.validate()?;
        self.check_existing_saves()?;
        self.check_child_create_parent(&d.parent_identity, &d.parent, d.root)?;
        self.binding
            .with_publication(|| {
                self.binding
                    .verify_custody_context(self.custody.as_ref())
                    .map_err(|_| refused())?;
                if d.root != self.custody.root_identity() || !self.binding.delete_context_matches(d)
                {
                    return Err(refused());
                }
                let saved = self.saved(&d.original_identity).map_err(|_| refused())?;
                if saved.id != d.original.id
                    || saved.path != d.original.path
                    || (!d.empty_directory && saved.etag != d.original.etag)
                    || saved.size != d.original.size
                    || saved.directory != d.empty_directory
                {
                    return Err(refused());
                }
                Ok(())
            })
            .map_err(|_| BackendError::Unavailable)?;
        let record = self.custody.begin_file_delete(d)?;
        self.binding
            .with_publication(|| {
                self.binding
                    .verify_custody_context(self.custody.as_ref())
                    .map_err(|_| refused())?;
                Ok(())
            })
            .map_err(|_| BackendError::Unavailable)?;
        Ok(record)
    }
    pub(crate) fn publish_file_delete<T>(
        &self,
        p: &crate::vault_file_delete::VaultFileDeleteRemoteProof,
        cancel: &crate::vault_custody::VaultUploadCancellation<'_>,
        publish: impl FnOnce() -> Result<T, crate::Error>,
    ) -> Result<T, crate::Error> {
        self.binding.with_exclusive_completion(|| {
            let no = || crate::Error::EditRecoveryUnavailable;
            let d = p.descriptor();
            d.validate().map_err(|_| no())?;
            self.check_existing_saves().map_err(|_| no())?;
            if d.empty_directory {
                if p.target.is_some()
                    || !p
                        .directory_dispatch
                        .as_ref()
                        .is_some_and(|s| self.binding.matches_cleanup_dispatch(s))
                {
                    return Err(no());
                }
            } else {
                let target = p.target.as_ref().ok_or_else(no)?;
                self.binding
                    .validate_upload_target(target)
                    .map_err(|_| no())?;
                if p.directory_dispatch.is_some()
                    || target.dispatch().is_none()
                    || target.root() != d.root
                    || target.identity() != &d.original_identity
                    || !target.matches_original(&d.original)
                {
                    return Err(no());
                }
            }
            self.binding
                .verify_custody_context(self.custody.as_ref())
                .map_err(|_| no())?;
            if cancel.is_cancelled()
                || !self.binding.file_delete_proof_matches(&p.verified)
                || !p
                    .verified
                    .provider_current(&cancel.generation, cancel.expected)
                || d.root != self.custody.root_identity()
                || !self.binding.delete_context_matches(d)
                || p.verified.original().id != d.original.id
                || p.verified.original().path != d.original.path
                || p.verified.original().etag != d.original.etag
                || p.verified.original().size != d.original.size
                || p.verified.original().directory != d.empty_directory
                || p.verified.parent().id != d.parent.id
                || p.verified.parent().path != d.parent.path
            {
                return Err(no());
            }
            {
                let c = self.catalogue.lock().map_err(|_| no())?;
                let old = c.entries.get(&d.original_identity).ok_or_else(no)?;
                if old.id != d.original.id
                    || old.path != d.original.path
                    || (!d.empty_directory && old.etag != d.original.etag)
                    || old.size != d.original.size
                    || old.directory != d.empty_directory
                {
                    return Err(no());
                }
            }
            let result = publish()?;
            // A completed exact-object tombstone filters the current view only.
            // Original captures, bodies and catalogue history remain retained.
            if self
                .custody
                .catalogue_snapshot()
                .map_err(|_| no())?
                .iter()
                .any(|e| e.identity == d.original_identity)
            {
                return Err(no());
            }
            let mut c = self.catalogue.lock().map_err(|_| no())?;
            let old = c.entries.get(&d.original_identity).ok_or_else(no)?.clone();
            if old.id != d.original.id
                || old.path != d.original.path
                || (!d.empty_directory && old.etag != d.original.etag)
            {
                return Err(no());
            }
            c.entries.remove(&d.original_identity);
            c.versions.remove(&key(&old));
            if cancel.is_cancelled() {
                return Err(no());
            }
            Ok(result)
        })
    }
}

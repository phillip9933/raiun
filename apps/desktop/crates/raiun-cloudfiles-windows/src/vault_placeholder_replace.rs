// Additive replacement publication inside the original runtime module. Body
// staging and HTTP run outside its route/token/unlock publication fences.
impl WindowsVaultPlaceholderBackend {
    pub(crate) fn begin_file_replace(
        &self,
        d: &crate::vault_file_replace::VaultFileReplaceDescriptor,
    ) -> Result<Box<dyn crate::vault_file_replace::VaultFileReplaceCapture>, BackendError> {
        d.validate()?;
        self.check_existing_saves()?;
        self.check_child_create_parent(&d.parent_identity, &d.parent, d.root)?;
        self.binding.with_publication(|| {
            self.binding.verify_custody_context(self.custody.as_ref()).map_err(|_| refused())?;
            let baseline=self.binding.existing_edit_baseline(d.original_identity,d.original.clone(),d.root).map_err(|_|refused())?;
            if baseline.owner()!=&d.owner || baseline.vault()!=&d.vault
                ||baseline.remote_root()!=d.remote_root||baseline.unlock_epoch()!=d.historical_unlock_epoch
            {return Err(refused());}
            let saved=self.saved(&d.original_identity).map_err(|_|refused())?;
            if saved.id!=d.original.id||saved.path!=d.original.path||saved.etag!=d.original.etag
                ||saved.size!=d.original.size||saved.directory{return Err(refused());}
            Ok(())
        }).map_err(|_|BackendError::Unavailable)?;
        // Private history authentication may read protected bodies; never hold
        // an epoch/token/publication fence over that I/O.
        let capture=self.custody.begin_file_replace(d)?;
        self.binding.with_publication(|| {
            self.binding.verify_custody_context(self.custody.as_ref()).map_err(|_|refused())?;
            Ok(())
        }).map_err(|_|BackendError::Unavailable)?;
        Ok(capture)
    }
    pub(crate) fn publish_file_replacement<T>(
        &self,
        p: &crate::vault_file_replace::VaultFileReplaceRemoteProof,
        cancel: &crate::vault_custody::VaultUploadCancellation<'_>,
        publish: impl FnOnce() -> Result<T, crate::Error>,
    ) -> Result<T,crate::Error> {
        self.binding.with_exclusive_completion(|| {
            let no=||crate::Error::EditRecoveryUnavailable;
            let d=p.descriptor();
            d.validate().map_err(|_|no())?;
            self.check_existing_saves().map_err(|_|no())?;
            self.binding.validate_upload_target(&p.target).map_err(|_|no())?;
            self.binding.verify_custody_context(self.custody.as_ref()).map_err(|_|no())?;
            let baseline=self.binding.existing_edit_baseline(d.original_identity,d.original.clone(),d.root).map_err(|_|no())?;
            if cancel.is_cancelled()||p.target.dispatch().is_none()||p.target.root()!=d.root
                ||p.target.identity()!=&d.original_identity||!p.target.matches_original(&d.original)
                ||baseline.owner()!=&d.owner||baseline.vault()!=&d.vault
                ||baseline.remote_root()!=d.remote_root||baseline.unlock_epoch()!=d.historical_unlock_epoch
                ||p.entry().id!=d.original.id||p.entry().path!=d.original.path||p.entry().directory
                ||p.entry().size!=d.plaintext_len
                ||p.plaintext_sha256()==[0;32]
            {return Err(no());}
            {
                let c=self.catalogue.lock().map_err(|_|no())?;
                let old=c.entries.get(&d.original_identity).ok_or_else(no)?;
                if old.id!=d.original.id||old.path!=d.original.path||old.etag!=d.original.etag
                    ||old.size!=d.original.size||old.directory
                {return Err(no());}
            }
            let result=publish()?;
            // Native conversion plus its durable factual receipt precede all
            // changes to the live catalogue. Historical records stay original.
            let projected=self.custody.catalogue_snapshot().map_err(|_|no())?;
            let mut matches=projected.iter().filter(|e|e.identity==d.original_identity);
            let entry=matches.next().ok_or_else(no)?;
            if matches.next().is_some()||entry.metadata.id!=p.entry().id||entry.metadata.path!=p.entry().path
                ||entry.metadata.etag!=p.entry().etag||entry.metadata.size!=p.entry().size||entry.metadata.directory
            {return Err(no());}
            let mut c=self.catalogue.lock().map_err(|_|no())?;
            let old=c.entries.get(&d.original_identity).ok_or_else(no)?.clone();
            if old.id!=d.original.id||old.path!=d.original.path||old.etag!=d.original.etag{return Err(no());}
            let mut next=p.entry().clone();next.writable=false;
            c.versions.remove(&key(&old));c.versions.insert(key(&next),d.original_identity);
            c.entries.insert(d.original_identity,next);
            if cancel.is_cancelled(){return Err(no());}Ok(result)
        })
    }
}

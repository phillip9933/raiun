impl WindowsVaultReadBinding {
    pub(crate) fn prepare_file_delete(
        &self, original: &RemoteEntry, parent: &RemoteEntry,
        cancel: &crate::vault_custody::VaultUploadCancellation<'_>, context: raiun_opencloud::RangeReadContext,
    ) -> Result<raiun_opencloud::vault_backend::VaultFileDeleteTarget,CloudError> {
        self.check_current()?;
        let stop=||self.is_revoked()||cancel.is_cancelled();
        let r=raiun_opencloud::vault_backend::VaultFileDeleteRequest{scope:&self.scope,epoch:&self.epoch,
            vault_root_path:&self.root_path,source:original,parent,context,provider_generation:cancel.generation.clone(),
            expected_provider_generation:cancel.expected,cancelled:&stop};
        let target=self.backend.prepare_file_delete_guarded(&r)?;
        self.check_current()?;if stop(){return Err(refused());}Ok(target)
    }
    pub(crate) fn send_file_delete(
        &self,original:&RemoteEntry,parent:&RemoteEntry,target:raiun_opencloud::vault_backend::VaultFileDeleteTarget,
        cancel:&crate::vault_custody::VaultUploadCancellation<'_>,context:raiun_opencloud::RangeReadContext,
        before:&mut dyn FnMut()->Result<(),CloudError>,
    )->Result<raiun_opencloud::vault_backend::VaultFileDeleteOutcome,CloudError>{
        self.check_current()?;let stop=||self.is_revoked()||cancel.is_cancelled();
        let r=raiun_opencloud::vault_backend::VaultFileDeleteRequest{scope:&self.scope,epoch:&self.epoch,
            vault_root_path:&self.root_path,source:original,parent,context,provider_generation:cancel.generation.clone(),
            expected_provider_generation:cancel.expected,cancelled:&stop};
        let result=self.backend.delete_file_guarded(&r,target,before)?;
        if stop()||self.check_current().is_err(){return Ok(raiun_opencloud::vault_backend::VaultFileDeleteOutcome::NeedsReconciliation);}Ok(result)
    }
    pub(crate) fn file_delete_proof_matches(&self,p:&raiun_opencloud::vault_backend::VaultVerifiedFileDelete)->bool{
        p.scope()==&self.scope&&p.matches_epoch(&self.epoch)&&p.root_path()==self.root_path
            &&p.token_generation()==self.trusted.token_generation()
    }
}

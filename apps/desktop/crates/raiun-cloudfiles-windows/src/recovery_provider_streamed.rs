//! Explicit recovered v2 routing. Discovery is selection only: it never
//! reconstructs the prepared instance's fresh in-memory dispatch receipt.
use super::*;
use crate::streamed_store::{DiscoveryBudget, SnapshotStore, StreamedRecordKey};

const MAX_STREAMED_RECOVERY_SCOPES: usize = 256;
const MAX_STREAMED_RECOVERY_RECORDS: usize = 2000;
const MAX_STREAMED_RECOVERY_SCAN_ENTRIES: usize = 20_000;
const MAX_STREAMED_RECOVERY_SCAN_BYTES: u64 = 64 * 1024 * 1024;

struct SelectedStreamedRecord {
    store: Arc<SnapshotStore>,
    key: StreamedRecordKey,
    new_create: bool,
}

impl DurablePreparedEditRecovery {
    /// Select immutable v2 evidence without dispatch admission, locks that
    /// create state, attempt events, or any native completion capability.
    pub(super) fn try_check_recovered_streamed(
        &self,
        record_id: &str,
        generation: u64,
        remote: &dyn RecoveryRemote,
    ) -> Result<Option<super::SavedEditCloudCheck>, crate::JournalError> {
        let Some(context) = &self.streamed else {
            return Ok(None);
        };
        let job = remote.begin_recovery_job(context.transfer_policy);
        job.check().map_err(|_| crate::JournalError::InvalidState)?;
        let Some(selected) = self.select_recovered_streamed(record_id, generation)? else {
            return Ok(None);
        };
        // An ID that resolves in both protected formats is not selectable.
        if self
            .catalog
            .find_journal_for_record(&self.scope, self.root_identity, record_id, generation)?
            .is_some()
        {
            return Err(crate::JournalError::ScopeMismatch);
        }
        let result = if selected.new_create {
            super::saved_edit_check::check_created(&selected.store, &selected.key, remote, &job)?
        } else {
            super::saved_edit_check::check_streamed(
                &selected.store,
                &selected.key,
                self.scope.token_generation(),
                remote,
                &job,
            )?
        };
        job.check().map_err(|_| crate::JournalError::InvalidState)?;
        Ok(Some(result))
    }

    /// Return None ONLY when no selected v2 record has this ID. Corruption,
    /// exhausted discovery, wrong generation and format collisions are errors,
    /// never permission to fall through to another format or account.
    pub(super) fn try_dispatch_recovered_streamed(
        &self,
        record_id: &str,
        generation: u64,
        remote: &dyn RecoveryRemote,
        approval: ExplicitRecoveryApproval,
    ) -> Result<
        Option<(ReconciliationOutcome, Option<crate::VerifiedEditReadback>)>,
        crate::JournalError,
    > {
        // Disabled v2 must preserve the legacy validator/routing unchanged.
        if self.streamed.is_none() {
            return Ok(None);
        }
        let policy = self
            .streamed
            .as_ref()
            .ok_or(crate::JournalError::InvalidState)?
            .transfer_policy;
        let job = remote.begin_recovery_job(policy);
        job.check().map_err(|_| crate::JournalError::InvalidState)?;
        if !valid_scope_binding(&self.scope, self.root_identity)
            || record_id.len() != 32
            || !record_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || generation == 0
        {
            return Err(crate::JournalError::InvalidEdit);
        }
        let Some(selected) = self.select_recovered_streamed(record_id, generation)? else {
            return Ok(None);
        };
        // Resolve the legacy route independently. An error cannot be mistaken
        // for absence, and a matching legacy ID is an ambiguous format choice.
        if self
            .catalog
            .find_journal_for_record(&self.scope, self.root_identity, record_id, generation)?
            .is_some()
        {
            return Err(crate::JournalError::ScopeMismatch);
        }
        let adapter = remote
            .streamed_remote_for_job(&job)
            .ok_or(crate::JournalError::InvalidState)?;
        let local_job = job.clone();
        let result = crate::streamed_reconcile::reconcile_recovered_streamed_edit(
            &selected.store,
            &selected.key,
            selected.key.scope(),
            &*adapter,
            approval,
            Arc::new(move || local_job.is_stopped()),
        )
        .map_err(crate::edit_journal::admission_error)?;
        let proof = result
            .verified
            .map(crate::VerifiedEditReadback::from_streamed)
            .transpose()?
            .map(|proof| proof.with_recovery_job(job.clone()));
        job.check().map_err(|_| crate::JournalError::InvalidState)?;
        Ok(Some((result.outcome, proof)))
    }

    fn select_recovered_streamed(
        &self,
        record_id: &str,
        generation: u64,
    ) -> Result<Option<SelectedStreamedRecord>, crate::JournalError> {
        let Some(context) = &self.streamed else {
            return Ok(None);
        };
        // Clamp discovery work only. The store's actual capture/storage quota
        // is unchanged, and a single budget spans catalogs AND every selected
        // scope. Reinitializing it in the loop could hide an aggregate overrun.
        let mut scan_policy = context.policy;
        scan_policy.max_entries = scan_policy
            .max_entries
            .min(MAX_STREAMED_RECOVERY_SCAN_ENTRIES);
        scan_policy.max_metadata_bytes_per_scan = scan_policy
            .max_metadata_bytes_per_scan
            .min(MAX_STREAMED_RECOVERY_SCAN_BYTES);
        let mut budget = DiscoveryBudget::new(scan_policy);
        let scopes = SnapshotStore::discover_state_scopes_bounded(
            Arc::clone(&context.state),
            Arc::clone(&self.catalog.protector),
            context.policy,
            &mut budget,
        )
        .map_err(crate::edit_journal::admission_error)?;
        if scopes.len() > MAX_STREAMED_RECOVERY_SCOPES {
            return Err(crate::JournalError::ScanLimit);
        }
        let mut found = None;
        let mut scanned = 0usize;
        for scope in scopes
            .into_iter()
            .filter(|scope| scope_matches_provider(scope, &self.scope, self.root_identity))
        {
            let store = SnapshotStore::open_existing_admitted(
                Arc::clone(&context.state),
                scope,
                Arc::clone(&self.catalog.protector),
                context.policy,
            )
            .map_err(crate::edit_journal::admission_error)?;
            for record in store
                .discover_records_bounded(&mut budget)
                .map_err(crate::edit_journal::admission_error)?
            {
                scanned = scanned
                    .checked_add(1)
                    .ok_or(crate::JournalError::ScanLimit)?;
                if scanned > MAX_STREAMED_RECOVERY_RECORDS {
                    return Err(crate::JournalError::ScanLimit);
                }
                if record.key.record_id() != record_id {
                    continue;
                }
                // A second ID in another selected scope is ambiguous even if
                // its generation differs; never select by a guessed path.
                if record.key.generation() != generation || found.is_some() {
                    return Err(crate::JournalError::ScopeMismatch);
                }
                found = Some(SelectedStreamedRecord {
                    store: Arc::clone(&store),
                    key: record.key,
                    new_create: record.manifest.binding().remote.is_none(),
                });
            }
        }
        // The reconciler revalidates this exact commitment and authenticates
        // the complete body under its record dispatch lease BEFORE any HTTP.
        Ok(found)
    }
}

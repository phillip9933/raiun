// Metadata-only helper, intended as a child module of windows_folder_sync.
// Caller supplies the authenticated Runtime account identity, never a request-derived one.
use super::super::windows_media_requests::MediaRequest;
use super::*;
use raiun_core::MediaImportJob;

impl Runtime {
    fn media_destination_entry(
        &self,
        space_id: &str,
        path: &str,
        authorized: &AtomicU64,
    ) -> Result<raiun_core::backend::RemoteEntry, String> {
        self.check(authorized)?;
        let space = self.space(space_id)?;
        if !space.writable || path == "/" || raiun_core::validate_remote_path(path).is_err() {
            return Err("Choose a writable ordinary media destination folder".into());
        }
        let entry = self
            .client
            .stat(space_id, path)
            .map_err(|_| "Could not verify the media destination")?;
        self.check(authorized)?;
        if !entry.directory || entry.encrypted || !entry.writable || entry.id.trim().is_empty() {
            return Err("The media destination is unavailable".into());
        }
        Ok(entry)
    }

    /// Local recovery metadata is read-only; no run, automatic dispatch, or upload verification.
    /// trusted_account_id must be retained from Setup verification by the caller.
    pub fn handle_media_metadata(
        &mut self,
        request: MediaRequest,
        authorized: &AtomicU64,
        trusted_account_id: &str,
    ) -> Result<Value, String> {
        self.check(authorized)?;
        let document = self.document()?;
        match request {
            MediaRequest::Jobs => {
                let mut rows = Vec::new();
                for job in document.media_jobs() {
                    rows.push(json!({"job":job,"status":self.engine.media_import_status(&job.id).map_err(store_error)?,"queued":false,"active_account":job.account_id == trusted_account_id}));
                }
                self.check(authorized)?;
                Ok(json!({"account_id":trusted_account_id,"jobs":rows}))
            }
            MediaRequest::Status { job_id } => {
                let job = document
                    .media_jobs()
                    .iter()
                    .find(|job| job.id == job_id)
                    .ok_or("Media backup was not found")?;
                let status = self
                    .engine
                    .media_import_status(&job.id)
                    .map_err(store_error)?;
                self.check(authorized)?;
                Ok(
                    json!({"job":job,"status":status,"queued":false,"active_account":job.account_id == trusted_account_id}),
                )
            }
            MediaRequest::Destination { space_id, path } => {
                let entry = self.media_destination_entry(&space_id, &path, authorized)?;
                Ok(
                    json!({"id":entry.id,"path":entry.path,"space_id":space_id,"account_id":trusted_account_id}),
                )
            }
            MediaRequest::Set {
                job,
                expected_revision,
                expected_account_id,
            } => {
                if expected_account_id != trusted_account_id || job.account_id != trusted_account_id
                {
                    return Err("Media backup belongs to another account".into());
                }
                let previous = document
                    .media_jobs()
                    .iter()
                    .find(|previous| previous.id == job.id);
                let enabled_only = previous.is_some_and(|previous| {
                    let mut comparable = previous.clone();
                    comparable.enabled = job.enabled;
                    comparable.revision = job.revision;
                    comparable == job
                });
                // A pure disable may persist while the source volume is offline.
                let pin = if job.enabled || !enabled_only {
                    let entry = self.media_destination_entry(
                        &job.space_id,
                        &job.destination_root,
                        authorized,
                    )?;
                    if entry.id != job.destination_root_resource_id {
                        return Err("The media destination changed; choose it again".into());
                    }
                    Some(self.admit_media_source(&job, document.config(), document.media_jobs())?)
                } else {
                    None
                };
                self.check(authorized)?;
                if let Some(pin) = &pin {
                    pin.verify_path().map_err(|_| "The media source changed")?;
                }
                let saved = self
                    .store
                    .set_media_job(document.revision(), expected_revision, job.clone())
                    .map_err(store_error)?;
                let job = saved
                    .media_jobs()
                    .iter()
                    .find(|saved| saved.id == job.id)
                    .ok_or("Media backup was not saved")?;
                Ok(json!({"job":job}))
            }
            MediaRequest::Remove {
                job_id,
                expected_revision,
                expected_account_id,
            } => {
                let job = document
                    .media_jobs()
                    .iter()
                    .find(|job| job.id == job_id)
                    .ok_or("Media backup was not found")?;
                if expected_account_id != trusted_account_id || job.account_id != trusted_account_id
                {
                    return Err("Media backup belongs to another account".into());
                }
                self.check(authorized)?;
                // Store itself refuses currently known retained recovery/attempts.
                self.store
                    .remove_media_job(document.revision(), &job_id, expected_revision)
                    .map_err(store_error)?;
                Ok(json!({"removed":true,"job_id":job_id}))
            }
            MediaRequest::Recovery {
                job_id,
                expected_revision,
                expected_account_id,
                limit,
                cursor,
            } => {
                if trusted_account_id != self.account_id
                    || expected_account_id != trusted_account_id
                {
                    return Err("Media recovery belongs to another saved account".into());
                }
                let job = document
                    .media_jobs()
                    .iter()
                    .find(|job| job.id == job_id)
                    .ok_or("Media backup was not found")?;
                if job.account_id != trusted_account_id || job.revision != expected_revision {
                    return Err("Media backup changed or belongs to another account".into());
                }
                let page = self
                    .engine
                    .media_import_recovery(&job_id, trusted_account_id, limit, cursor.as_ref())
                    .map_err(|_| "Could not read local media recovery status")?;
                self.check(authorized)?;
                let current = self.document()?;
                if current
                    .media_jobs()
                    .iter()
                    .find(|job| job.id == job_id)
                    .is_none_or(|job| {
                        job.account_id != trusted_account_id || job.revision != expected_revision
                    })
                {
                    return Err("Media backup changed while reading recovery status".into());
                }
                self.check(authorized)?;
                Ok(
                    json!({"job_id":job_id,"account_id":trusted_account_id,"revision":expected_revision,"page":page}),
                )
            }
            MediaRequest::Run {
                job_id,
                expected_revision,
                expected_account_id,
            } => {
                let job = document
                    .media_jobs()
                    .iter()
                    .find(|job| job.id == job_id)
                    .ok_or("Media backup was not found")?;
                if expected_account_id != trusted_account_id
                    || job.account_id != trusted_account_id
                    || job.revision != expected_revision
                {
                    return Err("Media backup account or settings changed".into());
                }
                Err("Media backup execution is not supported by this Windows worker".into())
            }
        }
    }
    fn admit_media_source(
        &self,
        job: &MediaImportJob,
        config: &Config,
        jobs: &[MediaImportJob],
    ) -> Result<PinnedDirectory, String> {
        // Existing ordinary-root admission checks private state, registered cloud
        // root, configured pair overlap and no-reparse pinned local directory.
        let pair = FolderPair {
            id: job.id.clone(),
            local_path: job.source_root.clone(),
            space_id: job.space_id.clone(),
            vault: None,
            remote_path: job.destination_root.clone(),
            mode: SyncMode::UploadOnly,
            excluded_paths: vec![],
        };
        let pin = self.admit(&pair, config, None)?;
        for other in jobs
            .iter()
            .filter(|other| other.id != job.id && other.account_id == job.account_id)
        {
            if configured_roots_overlap(&other.source_root, &job.source_root)
                .map_err(|_| "Could not verify media source boundaries")?
            {
                return Err("Media source overlaps another backup source".into());
            }
            if other.space_id == job.space_id && other.destination_root == job.destination_root {
                return Err("Another media backup targets this destination".into());
            }
        }
        Ok(pin)
    }
}

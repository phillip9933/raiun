// Media control helper, intended as a child module of windows_folder_sync.
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
                Err("Media backup runs must be queued by the Windows worker".into())
            }
        }
    }
    /// Idle recurring selection uses durable status; uncertain attempts never replay.
    pub fn periodic_media_tick(&mut self, authorized: &AtomicU64) -> Option<Result<(), String>> {
        if self.check(authorized).is_err()
            || self.engine.revocation_handle().is_revoked()
            || std::time::Instant::now() < self.next_media_sync
        {
            return None;
        }
        let result = (|| {
            let document = self.document()?;
            if document.paused() {
                return Ok(false);
            }
            let now = unix_time_now().min(i64::MAX as u64) as i64;
            let mut preparation_error = None;
            for job in document.media_jobs() {
                if !job.enabled
                    || job.account_id != self.account_id
                    || document.paused_space_ids().contains(&job.space_id)
                {
                    continue;
                }
                let status = self
                    .engine
                    .media_import_status(&job.id)
                    .map_err(store_error)?;
                if !media_job_is_due(status.as_ref(), now, job.interval_seconds)
                    || self
                        .engine
                        .media_import_has_unresolved(&job.id)
                        .map_err(store_error)?
                {
                    continue;
                }
                let (revision, job, pin) = match self.prepare_media_run(
                    &job.id,
                    job.revision,
                    &self.account_id,
                    authorized,
                ) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        self.check(authorized)?;
                        if self.engine.revocation_handle().is_revoked() {
                            return Err("The media account was revoked".into());
                        }
                        // An offline camera must not hide another due source.
                        preparation_error.get_or_insert(error);
                        continue;
                    }
                };
                self.run_media_job(revision, job, pin, authorized)?;
                return Ok(true); // At most one job before returning to command arbitration.
            }
            match preparation_error {
                Some(error) => Err(error),
                None => Ok(false),
            }
        })();
        self.next_media_sync =
            std::time::Instant::now() + Duration::from_secs(if result.is_ok() { 30 } else { 60 });
        match result {
            Ok(false) => None,
            Ok(true) => Some(Ok(())),
            Err(error) => Some(Err(error)),
        }
    }

    /// Prepare one explicit run from saved metadata, not caller-supplied paths.
    /// This is fresh admission, not historical source identity continuity.
    pub fn prepare_media_run(
        &self,
        job_id: &str,
        expected_revision: u64,
        expected_account: &str,
        authorized: &AtomicU64,
    ) -> Result<(u64, MediaImportJob, PinnedDirectory), String> {
        self.check(authorized)?;
        if expected_account != self.account_id || self.engine.revocation_handle().is_revoked() {
            return Err("The media account changed or was revoked".into());
        }
        let document = self.document()?;
        let job = document
            .media_jobs()
            .iter()
            .find(|job| job.id == job_id)
            .ok_or("Media backup was not found")?
            .clone();
        if job.account_id != self.account_id
            || job.revision != expected_revision
            || !job.enabled
            || document.paused()
            || document.paused_space_ids().contains(&job.space_id)
        {
            return Err("Media backup settings changed or are paused".into());
        }
        if self
            .engine
            .media_import_has_unresolved(&job.id)
            .map_err(store_error)?
        {
            return Err("Retained media recovery needs review before another run".into());
        }
        let destination =
            self.media_destination_entry(&job.space_id, &job.destination_root, authorized)?;
        if destination.id != job.destination_root_resource_id {
            return Err("The media destination changed; choose it again".into());
        }
        let pin = self.admit_media_source(&job, document.config(), document.media_jobs())?;
        pin.verify_path().map_err(|_| "The media source changed")?;
        self.check(authorized)?;
        let current = self.document()?;
        if current.revision() != document.revision()
            || !current.media_jobs().contains(&job)
            || self.engine.revocation_handle().is_revoked()
        {
            return Err("Media backup changed before it could be queued".into());
        }
        Ok((document.revision(), job, pin))
    }

    /// Keep the prepared source pin alive until Engine returns. The caller sends
    /// only queued acceptance before this method and serializes later commands.
    pub fn run_media_job(
        &mut self,
        revision: u64,
        job: MediaImportJob,
        pin: PinnedDirectory,
        authorized: &AtomicU64,
    ) -> Result<(), String> {
        self.check(authorized)?;
        let current = self.document()?;
        let revocation = self.engine.revocation_handle();
        if revocation.is_revoked()
            || current.revision() != revision
            || !current.media_jobs().contains(&job)
            || job.account_id != self.account_id
            || !job.enabled
            || current.paused()
            || current.paused_space_ids().contains(&job.space_id)
        {
            return Err("Media backup changed or was paused before execution".into());
        }
        pin.verify_path().map_err(|_| "The media source changed")?;
        let destination =
            self.media_destination_entry(&job.space_id, &job.destination_root, authorized)?;
        if destination.id != job.destination_root_resource_id {
            return Err("The media destination changed before execution".into());
        }
        // A retained unresolved stage is never an automatic retry candidate.
        if self
            .engine
            .media_import_has_unresolved(&job.id)
            .map_err(store_error)?
        {
            return Err("Retained media recovery needs review before another run".into());
        }
        self.check(authorized)?;
        let generation = self.generation;
        let result = self
            .engine
            .run_media_import_job_from_root_cancellable(&job, &pin, &|| {
                authorized.load(Ordering::Acquire) != generation
                    || revocation.is_revoked()
                    || pin.verify_path().is_err()
            });
        self.check(authorized)?;
        if revocation.is_revoked() {
            return Err("Media run was interrupted by an account transition".into());
        }
        pin.verify_path()
            .map_err(|_| "The media source changed during execution")?;
        result.map(|_| ()).map_err(|_| {
            "Media backup needs attention; source and retained recovery were preserved".into()
        })
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
        self.check_source_admission(
            &job.source_root,
            &pin,
            windows_profile_registry::SourceKind::MediaJob,
            &job.id,
        )?;
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

// Same durable due-state rule as Unix: no retry of running/attention/uncertain state.
fn media_job_is_due(
    status: Option<&raiun_engine::MediaImportRunStatus>,
    now: i64,
    interval_seconds: u32,
) -> bool {
    let Some(status) = status else {
        return true;
    };
    if !matches!(status.state.as_str(), "completed" | "interrupted") {
        return false;
    }
    let delay = if status.state == "completed" && status.waiting_for_stability > 0 {
        i64::from(interval_seconds.min(raiun_engine::MEDIA_STABLE_FILE_SECONDS as u32))
    } else {
        i64::from(interval_seconds)
    };
    now.saturating_sub(status.updated_unix) >= delay
}

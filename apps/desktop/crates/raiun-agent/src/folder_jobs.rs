//! Explicit, account-bound folder operations. Plans are never replay authority.
//! Restart preserves unfinished work as interrupted; already admitted uploads may
//! continue through the mount's sole ordinary-create uploader after cancellation.
//! Local staging is capped per job by the existing account cache quota. The
//! conservative 32-job retained-history bound requires explicit local review
//! when full; this module never deletes old plans, staging or recovery bodies.
use super::{Runtime, account_engine_dir};
use raiun_cache::OrdinaryCreateState;
use raiun_core::backend::{ErrorKind, RemoteEntry};
use raiun_engine::{CreateHandoffRequest, CreateUploadHandle, DurableCreateReceipt, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const MAX_JOBS: usize = 32;
const MAX_ENTRIES: usize = 100_000;
const MAX_DEPTH: usize = 128;
const MAX_BYTES: u64 = 1 << 40;
const MAX_PLAN_BYTES: u64 = 64 << 20;
const NOFOLLOW: i32 = 0x20000; // Linux O_NOFOLLOW; this module is Linux-only.
const MESSAGE: &str =
    "Folder operation binding changed or cancellation was requested; admitted uploads may continue";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Status {
    job_id: String,
    kind: String,
    state: String,
    space_id: String,
    remote_path: String,
    files_total: u64,
    folders_total: u64,
    bytes_total: u64,
    files_completed: u64,
    folders_completed: u64,
    bytes_completed: u64,
    cancel_requested: bool,
    error: Option<String>,
    auth_generation: u64,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: u64,
    inode: u64,
    len: u64,
    modified: i64,
    modified_ns: i64,
    changed: i64,
    changed_ns: i64,
    directory: bool,
}
impl Identity {
    fn read(metadata: &Metadata) -> Result<Self, String> {
        if !(metadata.is_dir() || metadata.is_file())
            || metadata.file_type().is_symlink()
            || (metadata.is_file() && metadata.nlink() != 1)
        {
            return Err(
                "Choose a folder containing only ordinary folders and files with one link".into(),
            );
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            len: metadata.len(),
            modified: metadata.mtime(),
            modified_ns: metadata.mtime_nsec(),
            changed: metadata.ctime(),
            changed_ns: metadata.ctime_nsec(),
            directory: metadata.is_dir(),
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceEntry {
    relative: String,
    identity: Identity,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    account_id: String,
    cloud_root: PathBuf,
    root_id: String,
    target: Option<RemoteEntry>,
    parent_id: Option<String>,
    source: Option<PathBuf>,
    entries: Vec<SourceEntry>,
    status: Status,
}
struct Job {
    plan: Plan,
    directory: PathBuf,
    status: Mutex<Status>,
    cancelled: AtomicBool,
}
impl Job {
    fn update(&self, edit: impl FnOnce(&mut Status)) -> Result<Status, String> {
        let mut status = self
            .status
            .lock()
            .map_err(|_| "Folder status unavailable")?;
        edit(&mut status);
        atomic_json(&self.directory, "status.json", &*status)?;
        Ok(status.clone())
    }
    fn status(&self) -> Result<Status, String> {
        self.status
            .lock()
            .map(|s| s.clone())
            .map_err(|_| "Folder status unavailable".into())
    }
}
#[derive(Default)]
struct Registry {
    jobs: BTreeMap<String, Arc<Job>>,
    loaded: BTreeSet<PathBuf>,
    workers: Vec<JoinHandle<()>>,
}
#[derive(Default)]
pub(super) struct FolderJobs {
    registry: Mutex<Registry>,
}
impl FolderJobs {
    pub(super) fn new() -> Self {
        Self::default()
    }
    pub(super) fn cancel_all_and_wait(&self) -> Result<(), String> {
        let workers = {
            let mut registry = self
                .registry
                .lock()
                .map_err(|_| "Folder jobs unavailable")?;
            for job in registry.jobs.values() {
                job.cancelled.store(true, Ordering::Release);
            }
            std::mem::take(&mut registry.workers)
        };
        let mut failed = false;
        for worker in workers {
            failed |= worker.join().is_err();
        }
        if failed {
            Err("A folder worker stopped unexpectedly; retained work needs review".into())
        } else {
            Ok(())
        }
    }
    fn load(&self, directory: &Path, account: &str, generation: u64) -> Result<(), String> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "Folder jobs unavailable")?;
        if registry.loaded.contains(directory) {
            for job in registry
                .jobs
                .values()
                .filter(|job| job.plan.account_id == account)
            {
                if job.status()?.auth_generation != generation {
                    job.cancelled.store(true, Ordering::Release);
                    job.update(|status| {
                        if !terminal(&status.state) {
                            status.state = "interrupted".into();
                            status.error = Some(MESSAGE.into());
                        }
                        status.auth_generation = generation;
                    })?;
                }
            }
            return Ok(());
        }
        private_directory(directory)?;
        let mut count = 0;
        for entry in fs::read_dir(directory).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "Invalid retained folder job")?;
            if !valid_id(&name) {
                return Err("Unexpected retained folder job directory; review local state".into());
            }
            count += 1;
            if count > MAX_JOBS {
                return Err("Retained folder job limit reached".into());
            }
            private_directory(&entry.path())?;
            let plan_path = entry.path().join("plan.json");
            match fs::symlink_metadata(&plan_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(io_error(error)),
                Ok(_) => {}
            }
            let plan: Plan = read_json(&plan_path, MAX_PLAN_BYTES)?;
            let status_path = entry.path().join("status.json");
            let mut status: Status = match fs::symlink_metadata(&status_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => plan.status.clone(),
                Err(error) => return Err(io_error(error)),
                Ok(_) => read_json(&status_path, 64 << 10)?,
            };
            if plan.account_id != account || status.job_id != name || plan.status.job_id != name {
                return Err("Retained folder job account binding is invalid".into());
            }
            if !terminal(&status.state) {
                status.state = "interrupted".into();
                status.error = Some("Raiun restarted; this folder job will not resume. Admitted uploads are retained separately".into());
            }
            status.auth_generation = generation;
            atomic_json(&entry.path(), "status.json", &status)?;
            registry.jobs.insert(
                name,
                Arc::new(Job {
                    plan,
                    directory: entry.path(),
                    status: Mutex::new(status),
                    cancelled: AtomicBool::new(false),
                }),
            );
        }
        registry.loaded.insert(directory.to_owned());
        Ok(())
    }
}

impl Runtime {
    pub(super) fn handle_folder_job(self: &Arc<Self>, request: &Value) -> Result<Value, String> {
        let generation = request
            .get("expected_auth_generation")
            .and_then(Value::as_u64)
            .ok_or("Refresh folder jobs before continuing")?;
        if self.operation_generation()? != generation {
            return Err(MESSAGE.into());
        }
        let settings = self
            .settings
            .lock()
            .map_err(|_| "Settings unavailable")?
            .clone();
        let account = settings.account_id.as_deref().ok_or("Sign in first")?;
        let directory = account_engine_dir(&self.dir, account).join("folder-jobs");
        self.folder_jobs.load(&directory, account, generation)?;
        let action = text(request, "action")?;
        if action == "folder_job_list" {
            let registry = self
                .folder_jobs
                .registry
                .lock()
                .map_err(|_| "Folder jobs unavailable")?;
            let statuses = registry
                .jobs
                .values()
                .filter(|job| job.plan.account_id == account)
                .map(|job| job.status())
                .collect::<Result<Vec<_>, _>>()?;
            return serde_json::to_value(statuses)
                .map_err(|_| "Could not encode folder jobs".into());
        }
        if action == "folder_job_prepare" {
            return self.prepare_folder_job(request, &settings, generation, &directory);
        }
        let job = self
            .folder_jobs
            .registry
            .lock()
            .map_err(|_| "Folder jobs unavailable")?
            .jobs
            .get(text(request, "job_id")?)
            .cloned()
            .ok_or("Folder job not found")?;
        if job.plan.account_id != account || job.status()?.auth_generation != generation {
            return Err(MESSAGE.into());
        }
        match action {
            "folder_job_status" => value(job.status()?),
            "folder_job_cancel" => {
                job.cancelled.store(true, Ordering::Release);
                value(job.update(|status| {
                    status.cancel_requested = true;
                    if status.state == "prepared" {
                        status.state = "cancelled".into();
                    }
                })?)
            }
            "folder_job_start" => self.start_folder_job(job, generation),
            _ => Err("Unknown folder job action".into()),
        }
    }

    fn folder_current(&self, job: &Job, generation: u64) -> bool {
        !job.cancelled.load(Ordering::Acquire)
            && self.auth_generation.load(Ordering::Acquire) == generation
            && !self.shutdown.load(Ordering::Acquire)
            && !self.auth_transition.load(Ordering::Acquire)
            && !self.retiring.load(Ordering::Acquire)
            && !self.offline_namespace.load(Ordering::Acquire)
            && self.settings.lock().is_ok_and(|settings| {
                !settings.paused
                    && !settings
                        .paused_space_ids
                        .contains(&job.plan.status.space_id)
                    && settings.mount_enabled
                    && settings.account_id.as_deref() == Some(&job.plan.account_id)
                    && settings.config.cloud_root == job.plan.cloud_root
            })
    }

    fn prepare_folder_job(
        self: &Arc<Self>,
        request: &Value,
        settings: &super::Settings,
        generation: u64,
        directory: &Path,
    ) -> Result<Value, String> {
        let space = text(request, "space_id")?;
        super::validate_space_id(space)?;
        let path = text(request, "remote_path")?;
        raiun_core::validate_remote_path(path).map_err(str::to_owned)?;
        if path == "/" || path.len() > 4096 {
            return Err("Choose a folder below the Space root".into());
        }
        let kind = text(request, "kind")?;
        if !matches!(kind, "upload" | "delete") {
            return Err("Choose upload or delete".into());
        }
        let account = settings.account_id.clone().ok_or("Sign in first")?;
        let engine = self.engine()?;
        {
            let auth = self.auth_state.lock().map_err(|_| "Account unavailable")?;
            if auth.account_id.as_deref() != Some(&account) || auth.session.is_none() {
                return Err(MESSAGE.into());
            }
        }
        let check = || {
            self.operation_generation().is_ok_and(|g| g == generation)
                && !self.offline_namespace.load(Ordering::Acquire)
                && self.settings.lock().is_ok_and(|current| {
                    !current.paused
                        && !current.paused_space_ids.iter().any(|id| id == space)
                        && current.account_id == settings.account_id
                        && current.mount_enabled
                        && current.config.cloud_root == settings.config.cloud_root
                })
        };
        ensure(&check)?;
        let spaces = engine.live_spaces().map_err(cloud_error)?;
        if !spaces
            .iter()
            .any(|s| s.id == space && s.writable && !s.encrypted)
        {
            return Err("Choose a writable unencrypted Space".into());
        }
        let root = engine.live_stat(space, "/").map_err(cloud_error)?;
        if !root.directory || !root.writable || root.encrypted || root.id.is_empty() {
            return Err("The Space root is unavailable".into());
        }
        let target;
        let parent_id;
        let source;
        let mut entries = Vec::new();
        let (files_total, folders_total, bytes_total);
        if kind == "upload" {
            let parent_path = path.rsplit_once('/').ok_or("Invalid folder path")?.0;
            let parent = if parent_path.is_empty() {
                root.clone()
            } else {
                engine.live_stat(space, parent_path).map_err(cloud_error)?
            };
            if !parent.directory || !parent.writable || parent.encrypted || parent.id.is_empty() {
                return Err("Choose an existing writable parent folder".into());
            }
            let proof = engine
                .capture_new_plaintext_create_parent_for_space(
                    space,
                    path,
                    Some(&parent.id),
                    &check,
                )
                .map_err(cloud_error)?;
            if proof.scope().root_resource_id() != root.id || proof.scope().account_id() != account
            {
                return Err(MESSAGE.into());
            }
            parent_id = Some(proof.parent_resource_id().to_owned());
            target = None;
            let chosen = PathBuf::from(text(request, "source_path")?);
            let chosen = super::resolve_without_symlinks(&chosen)?;
            if !chosen.is_dir() {
                return Err("Choose an existing local folder".into());
            }
            for excluded in [&self.dir, &settings.config.cloud_root] {
                if super::paths_overlap_existing(&chosen, excluded) {
                    return Err("The source overlaps the cloud root or private state".into());
                }
            }
            source = Some(chosen.clone());
            scan_source(
                &chosen,
                Path::new(""),
                0,
                &mut entries,
                &mut (MAX_PLAN_BYTES as usize / 2),
                &check,
            )?;
            if entries
                .iter()
                .any(|entry| remote_path(path, &entry.relative).len() > 4096)
            {
                return Err("An uploaded folder path exceeds the safe remote path limit".into());
            }
            files_total = entries.iter().filter(|e| !e.identity.directory).count() as u64;
            folders_total = entries.iter().filter(|e| e.identity.directory).count() as u64;
            bytes_total =
                entries
                    .iter()
                    .filter(|e| !e.identity.directory)
                    .try_fold(0u64, |sum, e| {
                        sum.checked_add(e.identity.len)
                            .filter(|v| *v <= MAX_BYTES)
                            .ok_or("Folder is too large")
                    })?;
        } else {
            let entry = engine.live_stat(space, path).map_err(cloud_error)?;
            if !entry.directory
                || !entry.writable
                || entry.encrypted
                || entry.id.is_empty()
                || entry.etag.is_empty()
            {
                return Err("Choose a writable unencrypted folder with a current version".into());
            }
            target = Some(entry);
            parent_id = None;
            source = None;
            // A delete is one parent operation; descendants are not enumerated or
            // independently deleted. Totals express the exact parent operation.
            files_total = 0;
            folders_total = 1;
            bytes_total = 0;
        }
        if kind == "upload"
            && bytes_total
                > engine
                    .offline_cache_usage()
                    .map_err(cloud_error)?
                    .quota_bytes
        {
            return Err("Folder exceeds this account's cache limit; choose a smaller folder or review Storage settings".into());
        }
        if kind == "upload" {
            check_headroom(directory, bytes_total)?;
        }
        let job_id = random_id()?;
        let status = Status {
            job_id: job_id.clone(),
            kind: kind.into(),
            state: "prepared".into(),
            space_id: space.into(),
            remote_path: path.into(),
            files_total,
            folders_total,
            bytes_total,
            files_completed: 0,
            folders_completed: 0,
            bytes_completed: 0,
            cancel_requested: false,
            error: None,
            auth_generation: generation,
        };
        let plan = Plan {
            account_id: account,
            cloud_root: settings.config.cloud_root.clone(),
            root_id: root.id,
            target,
            parent_id,
            source,
            entries,
            status: status.clone(),
        };
        let job = Arc::new(Job {
            plan,
            directory: directory.join(&job_id),
            status: Mutex::new(status),
            cancelled: AtomicBool::new(false),
        });
        if !self.folder_current(&job, generation) {
            return Err(MESSAGE.into());
        }
        let mounted = self.mount.lock().map_err(|_| "Mount unavailable")?;
        if !mounted.as_ref().is_some_and(|m| m.is_mounted()) {
            return Err("Mount this account before preparing a folder operation".into());
        }
        drop(mounted);
        let mut registry = self
            .folder_jobs
            .registry
            .lock()
            .map_err(|_| "Folder jobs unavailable")?;
        let stored_count = fs::read_dir(directory)
            .map_err(io_error)?
            .take(MAX_JOBS + 1)
            .collect::<Result<Vec<_>, _>>()
            .map_err(io_error)?
            .len();
        if stored_count >= MAX_JOBS {
            return Err("Folder job history limit reached; retained plans require review".into());
        }
        if !self.folder_current(&job, generation) {
            return Err(MESSAGE.into());
        }
        private_directory(&job.directory)?;
        atomic_json(&job.directory, "plan.json", &job.plan)?;
        atomic_json(&job.directory, "status.json", &job.status()?)?;
        registry.jobs.insert(job_id, job.clone());
        value(job.status()?)
    }

    fn start_folder_job(self: &Arc<Self>, job: Arc<Job>, generation: u64) -> Result<Value, String> {
        let mut registry = self
            .folder_jobs
            .registry
            .lock()
            .map_err(|_| "Folder jobs unavailable")?;
        if registry.jobs.values().any(|other| {
            other
                .status()
                .is_ok_and(|s| matches!(s.state.as_str(), "queued" | "preparing" | "uploading"))
        }) {
            return Err("Another folder operation is still running".into());
        }
        if job.status()?.state != "prepared" || !self.folder_current(&job, generation) {
            return Err("This folder job cannot be started; prepare it again".into());
        }
        let engine = self.engine()?;
        {
            let auth = self.auth_state.lock().map_err(|_| "Account unavailable")?;
            if auth.account_id.as_deref() != Some(&job.plan.account_id) || auth.session.is_none() {
                return Err(MESSAGE.into());
            }
        }
        let (lease, uploader) = {
            let mount = self.mount.lock().map_err(|_| "Mount unavailable")?;
            let mount = mount
                .as_ref()
                .filter(|m| m.is_mounted())
                .ok_or("Mount this account first")?;
            let uploader = mount.create_upload_handle();
            if job.plan.status.kind == "upload"
                && !uploader
                    .as_ref()
                    .is_some_and(CreateUploadHandle::is_accepting)
            {
                return Err("The mounted uploader is unavailable".into());
            }
            (
                mount
                    .reserve_folder_job(&job.plan.status.space_id, &job.plan.status.remote_path)?,
                uploader,
            )
        };
        let root = engine
            .live_stat(&job.plan.status.space_id, "/")
            .map_err(cloud_error)?;
        if root.id != job.plan.root_id || !self.folder_current(&job, generation) {
            return Err(MESSAGE.into());
        }
        if let Some(source) = &job.plan.source {
            verify_source(source, &job.plan.entries, &|| {
                self.folder_current(&job, generation)
            })?;
        }
        if job.plan.status.kind == "upload" {
            check_headroom(&job.directory, job.plan.status.bytes_total)?;
        }
        let status = job.update(|s| s.state = "queued".into())?;
        let runtime = self.clone();
        let worker_job = job.clone();
        let worker = thread::Builder::new().name("raiun-folder-job".into()).spawn(move || {
            let _lease = lease;
            let check = || runtime.folder_current(&worker_job, generation);
            let result = run_job(&worker_job, &engine, uploader.as_ref(), &check);
            let _ = worker_job.update(|status| {
                if result.is_ok() { status.state = "complete".into(); }
                else if worker_job.cancelled.load(Ordering::Acquire) { status.state = "cancelled".into(); status.cancel_requested = true; status.error = Some(MESSAGE.into()); }
                else if !check() { status.state = "interrupted".into(); status.error = Some(MESSAGE.into()); }
                else { status.state = "failed".into(); status.error = Some("Folder operation stopped; inspect retained uploads before preparing any replacement. No automatic retry was attempted".into()); }
            });
        }).map_err(io_error);
        match worker {
            Ok(worker) => {
                registry.workers.push(worker);
                value(status)
            }
            Err(error) => {
                job.update(|s| {
                    s.state = "failed".into();
                    s.error = Some(error.clone());
                })?;
                Err(error)
            }
        }
    }
}

fn run_job(
    job: &Job,
    engine: &Engine,
    uploader: Option<&CreateUploadHandle>,
    check: &(dyn Fn() -> bool + Sync),
) -> Result<(), String> {
    ensure(check)?;
    let status = &job.plan.status;
    job.update(|s| s.state = "preparing".into())?;
    if status.kind == "delete" {
        let target = job
            .plan
            .target
            .as_ref()
            .ok_or("Delete identity unavailable")?;
        engine
            .delete_folder_job(
                &status.space_id,
                &status.remote_path,
                &job.plan.root_id,
                &target.id,
                &target.etag,
                check,
            )
            .map_err(cloud_error)?;
        atomic_json(
            &job.directory,
            "delete-receipt.json",
            &json!({"space_id":status.space_id,"path":status.remote_path,"id":target.id,"etag":target.etag,"parent_delete_confirmed":true}),
        )?;
        job.update(|s| s.folders_completed = 1)?;
        return Ok(());
    }
    let uploader = uploader.ok_or("Mounted uploader unavailable")?;
    let source = job.plan.source.as_ref().ok_or("Source unavailable")?;
    verify_source(source, &job.plan.entries, check)?;
    // Reprove destination absence and the exact prepared parent before creating
    // anything. The Engine rechecks each created directory and mutation.
    let proof = engine
        .capture_new_plaintext_create_parent_for_space(
            &status.space_id,
            &status.remote_path,
            job.plan.parent_id.as_deref(),
            check,
        )
        .map_err(cloud_error)?;
    if proof.scope().root_resource_id() != job.plan.root_id {
        return Err(MESSAGE.into());
    }
    let folders = job
        .plan
        .entries
        .iter()
        .filter(|e| e.identity.directory)
        .map(|entry| remote_path(&status.remote_path, &entry.relative))
        .collect::<Vec<_>>();
    let created = engine
        .create_folder_job_tree(
            &status.space_id,
            &job.plan.root_id,
            job.plan
                .parent_id
                .as_deref()
                .ok_or("Prepared parent unavailable")?,
            &folders,
            check,
        )
        .map_err(cloud_error)?;
    atomic_json(&job.directory, "folder-receipts.json", &created)?;
    job.update(|s| {
        s.folders_completed = created.len() as u64;
        s.state = "uploading".into();
    })?;
    let parents = created
        .into_iter()
        .map(|e| (e.path, e.id))
        .collect::<BTreeMap<_, _>>();
    let files = job
        .plan
        .entries
        .iter()
        .filter(|e| !e.identity.directory)
        .collect::<Vec<_>>();
    let source_directories = job
        .plan
        .entries
        .iter()
        .filter(|entry| entry.identity.directory)
        .map(|entry| (entry.relative.clone(), entry.identity.clone()))
        .collect::<BTreeMap<_, _>>();
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let receipts = Mutex::new(Vec::new());
    let enqueue_done = AtomicBool::new(false);
    thread::scope(|scope| -> Result<(), String> {
        let observer = scope.spawn(|| -> Result<(), String> {
            let mut complete = 0;
            let mut bytes = 0;
            while !enqueue_done.load(Ordering::Acquire) && !failed.load(Ordering::Acquire) {
                ensure(check)?;
                let result = observe_receipts(
                    engine,
                    &mut *receipts.lock().map_err(|_| "Folder receipts unavailable")?,
                    &mut complete,
                    &mut bytes,
                );
                if let Err(error) = result {
                    failed.store(true, Ordering::Release);
                    return Err(error);
                }
                job.update(|s| {
                    s.files_completed = complete;
                    s.bytes_completed = bytes;
                })?;
                thread::sleep(Duration::from_millis(250));
            }
            Ok(())
        });
        let mut workers = Vec::new();
        for _ in 0..4.min(files.len()) {
            workers.push(scope.spawn(|| -> Result<(), String> {
                loop {
                    if failed.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    ensure(check)?;
                    let index = next.fetch_add(1, Ordering::AcqRel);
                    let Some(entry) = files.get(index) else {
                        return Ok(());
                    };
                    let current = || check() && !failed.load(Ordering::Acquire);
                    let result = enqueue_file(
                        job,
                        engine,
                        uploader,
                        source,
                        entry,
                        index,
                        &parents,
                        &source_directories,
                        &current,
                    );
                    match result {
                        Ok(receipt) => receipts
                            .lock()
                            .map_err(|_| "Folder receipts unavailable")?
                            .push(receipt),
                        Err(error) => {
                            failed.store(true, Ordering::Release);
                            return Err(error);
                        }
                    }
                }
            }));
        }
        let mut error = None;
        for worker in workers {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    error.get_or_insert(e);
                }
                Err(_) => {
                    error.get_or_insert_with(|| "Folder enqueue worker stopped".into());
                }
            }
        }
        enqueue_done.store(true, Ordering::Release);
        match observer.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                error.get_or_insert(e);
            }
            Err(_) => {
                error.get_or_insert_with(|| "Folder progress worker stopped".into());
            }
        }
        if let Some(error) = error {
            Err(error)
        } else {
            Ok(())
        }
    })?;
    let mut receipts = receipts
        .into_inner()
        .map_err(|_| "Folder receipts unavailable")?;
    let progress = job.status()?;
    let mut complete = progress.files_completed;
    let mut bytes = progress.bytes_completed;
    loop {
        ensure(check)?;
        observe_receipts(engine, &mut receipts, &mut complete, &mut bytes)?;
        job.update(|s| {
            s.files_completed = complete;
            s.bytes_completed = bytes;
        })?;
        if complete == status.files_total {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn observe_receipts(
    engine: &Engine,
    receipts: &mut Vec<DurableCreateReceipt>,
    complete: &mut u64,
    bytes: &mut u64,
) -> Result<(), String> {
    let mut index = 0;
    while index < receipts.len() {
        let receipt = &receipts[index];
        let original = receipt.storage_receipt();
        let actual = engine
            .create_handoff_receipt_metadata(
                receipt.scope(),
                &original.write.logical_path,
                &original.handoff_id,
            )
            .map_err(cloud_error)?
            .ok_or("An admitted folder upload is missing")?;
        if !actual.has_same_immutable_binding(original) {
            return Err(MESSAGE.into());
        }
        match actual.state {
            OrdinaryCreateState::Verified
                if actual.remote.is_some() && actual.local_handoff_acknowledged =>
            {
                *complete += 1;
                *bytes += actual.byte_len;
                receipts.swap_remove(index);
                continue;
            }
            OrdinaryCreateState::Conflict | OrdinaryCreateState::Uncertain => {
                return Err("An admitted upload needs review; automatic retry is disabled".into());
            }
            _ => {}
        }
        index += 1;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn enqueue_file(
    job: &Job,
    engine: &Engine,
    uploader: &CreateUploadHandle,
    source: &Path,
    entry: &SourceEntry,
    index: usize,
    parents: &BTreeMap<String, String>,
    source_directories: &BTreeMap<String, Identity>,
    check: &(dyn Fn() -> bool + Sync),
) -> Result<DurableCreateReceipt, String> {
    ensure(check)?;
    let path = remote_path(&job.plan.status.remote_path, &entry.relative);
    let parent_path = path.rsplit_once('/').ok_or("Invalid file path")?.0;
    let expected_parent = parents
        .get(parent_path)
        .ok_or("Created folder identity unavailable")?;
    let proof = engine
        .capture_new_plaintext_create_parent_for_space(
            &job.plan.status.space_id,
            &path,
            Some(expected_parent),
            check,
        )
        .map_err(cloud_error)?;
    if proof.scope().root_resource_id() != job.plan.root_id
        || proof.scope().account_id() != job.plan.account_id
    {
        return Err(MESSAGE.into());
    }
    let body_name = format!("body-{index}");
    let body_path = job.directory.join(&body_name);
    let mut body = OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(NOFOLLOW)
        .open(&body_path)
        .map_err(io_error)?;
    let original_path = source.join(&entry.relative);
    // Check each ancestor against the prepared tree before opening; the fd's
    // own dev/inode/timestamps then defeat leaf or parent replacement races.
    verify_ancestors(source, &entry.relative, source_directories)?;
    let mut original = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW | 0x800) // O_NONBLOCK avoids a replaced FIFO blocking shutdown.
        .open(&original_path)
        .map_err(io_error)?;
    if Identity::read(&original.metadata().map_err(io_error)?)? != entry.identity {
        return Err("A source file changed after preparation".into());
    }
    let mut hash = Sha256::new();
    let mut len = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        ensure(check)?;
        let count = original.read(&mut buffer).map_err(io_error)?;
        if count == 0 {
            break;
        }
        len = len
            .checked_add(count as u64)
            .filter(|v| *v <= entry.identity.len)
            .ok_or("Source file grew during snapshot")?;
        body.write_all(&buffer[..count]).map_err(io_error)?;
        hash.update(&buffer[..count]);
    }
    if len != entry.identity.len
        || Identity::read(&original.metadata().map_err(io_error)?)? != entry.identity
    {
        return Err("A source file changed during snapshot".into());
    }
    verify_ancestors(source, &entry.relative, source_directories)?;
    if Identity::read(&fs::symlink_metadata(&original_path).map_err(io_error)?)? != entry.identity {
        return Err("A source file was replaced during snapshot".into());
    }
    body.sync_all().map_err(io_error)?;
    fs::set_permissions(&body_path, fs::Permissions::from_mode(0o400)).map_err(io_error)?;
    body.sync_all().map_err(io_error)?;
    File::open(&job.directory)
        .and_then(|f| f.sync_all())
        .map_err(io_error)?;
    drop(body);
    let body = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW)
        .open(&body_path)
        .map_err(io_error)?;
    let digest = format!("{:x}", hash.finalize());
    let handoff = random_id()?;
    let max_pending_bytes = engine
        .offline_cache_usage()
        .map_err(cloud_error)?
        .quota_bytes;
    ensure(check)?;
    let receipt = engine
        .queue_new_plaintext_create_scoped(
            CreateHandoffRequest {
                parent: &proof,
                source: &body,
                expected_len: len,
                expected_sha256: &digest,
                handoff_id: &handoff,
                max_pending_bytes,
            },
            check,
        )
        .map_err(cloud_error)?;
    // The exact job receipt is durable before granting uploader dispatch custody.
    atomic_json(
        &job.directory,
        &format!("receipt-{index}.json"),
        &receipt_projection(&receipt),
    )?;
    let acknowledged = engine
        .acknowledge_create_handoff(
            receipt.scope(),
            &path,
            &handoff,
            receipt.storage_receipt(),
            check,
        )
        .map_err(cloud_error)?;
    uploader
        .wake_scope(acknowledged.scope())
        .map_err(cloud_error)?;
    Ok(acknowledged)
}

fn receipt_projection(receipt: &DurableCreateReceipt) -> Value {
    let r = receipt.storage_receipt();
    json!({"scope":{"origin":receipt.scope().origin(),"account_id":receipt.scope().account_id(),"space_id":receipt.scope().space_id(),"root_id":receipt.scope().root_resource_id(),"protection":"plaintext"},
        "handoff_id":r.handoff_id,"write_id":r.write.id,"parent_id":r.write.parent_resource_id,"name":r.write.name,"path":r.write.logical_path,"resource_id":r.write.resource_id,"base":r.write.base,
        "content":{"resource_id":r.write.content.resource_id,"etag":r.write.content.etag,"protection":"plaintext"},"created_at_unix":r.write.created_at_unix,"len":r.byte_len,"sha256":r.sha256})
}

fn scan_source(
    root: &Path,
    relative: &Path,
    depth: usize,
    entries: &mut Vec<SourceEntry>,
    remaining: &mut usize,
    check: &dyn Fn() -> bool,
) -> Result<(), String> {
    ensure(check)?;
    if depth > MAX_DEPTH || entries.len() >= MAX_ENTRIES {
        return Err("Folder exceeds the bounded tree limit".into());
    }
    let metadata = fs::symlink_metadata(root.join(relative)).map_err(io_error)?;
    let identity = Identity::read(&metadata)?;
    let directory = identity.directory;
    let relative_text = relative
        .to_str()
        .ok_or("Folder names must be valid UTF-8")?
        .to_owned();
    if relative_text.len() > 32 * 1024 {
        return Err("Folder path is too long".into());
    }
    *remaining = remaining
        .checked_sub(relative_text.len() + 512)
        .ok_or("Folder metadata exceeds the bounded plan limit")?;
    entries.push(SourceEntry {
        relative: relative_text,
        identity: identity.clone(),
    });
    if directory {
        let mut children = Vec::new();
        for entry in fs::read_dir(root.join(relative)).map_err(io_error)? {
            ensure(check)?;
            if children.len() + entries.len() >= MAX_ENTRIES {
                return Err("Folder exceeds the bounded tree limit".into());
            }
            let entry = entry.map_err(io_error)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "Folder names must be valid UTF-8")?;
            safe_component(&name)?;
            children.push(name);
        }
        children.sort();
        for name in children {
            scan_source(
                root,
                &relative.join(name),
                depth + 1,
                entries,
                remaining,
                check,
            )?;
        }
        if Identity::read(&fs::symlink_metadata(root.join(relative)).map_err(io_error)?)?
            != identity
        {
            return Err("Source folder changed during preparation".into());
        }
    }
    Ok(())
}
fn verify_source(
    source: &Path,
    entries: &[SourceEntry],
    check: &dyn Fn() -> bool,
) -> Result<(), String> {
    for entry in entries {
        ensure(check)?;
        if Identity::read(&fs::symlink_metadata(source.join(&entry.relative)).map_err(io_error)?)?
            != entry.identity
        {
            return Err("Source folder changed; prepare a new job".into());
        }
    }
    Ok(())
}
fn verify_ancestors(
    source: &Path,
    relative: &str,
    directories: &BTreeMap<String, Identity>,
) -> Result<(), String> {
    let mut path = Path::new(relative).parent();
    while let Some(parent) = path {
        let relative = parent.to_str().ok_or("Invalid source path")?;
        let expected = directories
            .get(relative)
            .ok_or("Source ancestor unavailable")?;
        if Identity::read(&fs::symlink_metadata(source.join(parent)).map_err(io_error)?)?
            != *expected
        {
            return Err("Source folder changed".into());
        }
        path = parent.parent();
    }
    Ok(())
}
fn safe_component(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 255
        || matches!(name, "." | "..")
        || name.contains(['/', '\\'])
        || name.chars().any(char::is_control)
        || name
            .chars()
            .any(|c| matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        || name.ends_with([' ', '.'])
    {
        return Err("Folder contains a name that cannot be uploaded safely".into());
    }
    Ok(())
}
fn remote_path(root: &str, relative: &str) -> String {
    if relative.is_empty() {
        root.into()
    } else {
        format!("{root}/{relative}")
    }
}
fn check_headroom(directory: &Path, bytes: u64) -> Result<(), String> {
    let required = bytes
        .checked_mul(3)
        .and_then(|value| value.checked_add(64 << 20))
        .ok_or("Folder staging size exceeds its safe bound")?;
    if fs2::available_space(directory).map_err(io_error)? < required {
        return Err("Not enough private storage for safe folder staging; free space before starting this job".into());
    }
    Ok(())
}
fn random_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| "Could not generate folder job identity")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn terminal(state: &str) -> bool {
    matches!(state, "complete" | "cancelled" | "failed" | "interrupted")
}
fn ensure(check: &dyn Fn() -> bool) -> Result<(), String> {
    if check() { Ok(()) } else { Err(MESSAGE.into()) }
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("Missing {key}"))
}
fn value(status: Status) -> Result<Value, String> {
    serde_json::to_value(status).map_err(|_| "Could not encode folder status".into())
}
fn io_error(_: std::io::Error) -> String {
    "Folder job storage is unavailable; existing work was retained".into()
}
fn cloud_error(error: raiun_core::backend::CloudError) -> String {
    if error.kind == ErrorKind::NotFound {
        "The chosen remote folder is no longer available".into()
    } else {
        "Could not confirm the folder operation; no automatic retry was attempted".into()
    }
}
fn private_directory(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err("Invalid private folder job path".into());
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err("Private folder job path contains an unsafe component".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&current)
                    .map_err(io_error)?;
                if let Some(parent) = current.parent() {
                    File::open(parent)
                        .and_then(|f| f.sync_all())
                        .map_err(io_error)?;
                }
            }
            Err(error) => return Err(io_error(error)),
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink()
        || metadata.uid() != raiun_headless::effective_user_id()
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err("Invalid private folder job directory".into());
    }
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(io_error)
}
fn atomic_json(directory: &Path, name: &str, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|_| "Could not encode retained folder job")?;
    if bytes.len() as u64 > MAX_PLAN_BYTES {
        return Err("Folder plan is too large".into());
    }
    let temporary = directory.join(format!(".{}-{}", name, random_id()?));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(NOFOLLOW)
        .open(&temporary)
        .map_err(io_error)?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(io_error)?;
    let destination = directory.join(name);
    match fs::symlink_metadata(&destination) {
        Ok(metadata) if !private_job_file(&metadata) => return Err("Unsafe retained folder job file; existing work was preserved".into()),
        Ok(_) => {},
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => return Err(io_error(error)),
    }
    fs::rename(&temporary, destination).map_err(io_error)?;
    File::open(directory)
        .and_then(|f| f.sync_all())
        .map_err(io_error)
}
fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, maximum: u64) -> Result<T, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW)
        .open(path)
        .map_err(io_error)?;
    let metadata = file.metadata().map_err(io_error)?;
    if !private_job_file(&metadata) || metadata.len() > maximum
    {
        return Err("Invalid retained folder job file".into());
    }
    serde_json::from_reader(file.take(maximum + 1))
        .map_err(|_| "Retained folder job is invalid; review local state".into())
}

fn private_job_file(metadata: &Metadata) -> bool {
    metadata.is_file() && !metadata.file_type().is_symlink()
        && metadata.uid() == raiun_headless::effective_user_id()
        && metadata.nlink() == 1 && metadata.mode() & 0o077 == 0
}

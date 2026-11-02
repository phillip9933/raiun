//! Durable ordinary-create admission and explicitly owned background delivery.
use super::*;
use raiun_cache::{OrdinaryCreateReceipt, OrdinaryCreateRequest, OrdinaryCreateState};
#[cfg(unix)]
use raiun_core::backend::OperationCancellation;

#[derive(Debug, Clone)]
pub struct VerifiedCreateParent {
    scope: CacheScope,
    path: String,
    parent_resource_id: String,
}
impl VerifiedCreateParent {
    pub fn scope(&self) -> &CacheScope {
        &self.scope
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn parent_resource_id(&self) -> &str {
        &self.parent_resource_id
    }
}
pub struct CreateHandoffRequest<'a> {
    pub parent: &'a VerifiedCreateParent,
    pub source: &'a File,
    pub expected_len: u64,
    pub expected_sha256: &'a str,
    pub handoff_id: &'a str,
    pub max_pending_bytes: u64,
}
#[derive(Debug, Clone)]
pub struct DurableCreateReceipt {
    scope: CacheScope,
    receipt: OrdinaryCreateReceipt,
}
impl DurableCreateReceipt {
    pub fn scope(&self) -> &CacheScope {
        &self.scope
    }
    pub fn storage_receipt(&self) -> &OrdinaryCreateReceipt {
        &self.receipt
    }
}
#[derive(Debug, Clone)]
pub struct PendingCreateView {
    pub receipt: OrdinaryCreateReceipt,
    pub entry: RemoteEntry,
}
fn refused() -> CloudError {
    CloudError::new(
        ErrorKind::Conflict,
        "ordinary create binding or authority changed; local bytes retained",
    )
}
fn current(check: &dyn Fn() -> bool) -> Result<(), CloudError> {
    if check() { Ok(()) } else { Err(refused()) }
}
fn admitted(state: OrdinaryCreateState) -> bool {
    state != OrdinaryCreateState::Staged
}
fn active(state: OrdinaryCreateState) -> bool {
    admitted(state) && state != OrdinaryCreateState::Verified
}

impl Engine {
    pub(super) fn create_cache(&self, scope: &CacheScope) -> Result<&Cache, CloudError> {
        let identity = self.account_scope.as_ref().ok_or_else(refused)?;
        if self.vault_binding.is_some()
            || scope.protection() != ScopeProtection::PlaintextAllowed
            || scope.account_id() != identity.account_id
            || scope.origin() != identity.origin
            || self.backend.server_origin().as_deref() != Some(scope.origin())
        {
            return Err(refused());
        }
        Ok(&self.offline_cache.as_ref().ok_or_else(refused)?.cache)
    }
    /// Record local custody failure visibility only; this does not attempt an upload.
    pub fn record_create_handoff_failure(
        &self,
        scope: &CacheScope,
        path: &str,
    ) -> Result<(), CloudError> {
        self.create_cache(scope)?;
        validate_remote_path(path).map_err(|_| refused())?;
        if !path.starts_with('/') || path == "/" || path.ends_with('/') {
            return Err(refused());
        }
        let context = self.offline_cache.as_ref().ok_or_else(refused)?;
        // Match retained original scope metadata, never obtain fresh network authority.
        if self
            .cached_scope(scope.space_id(), context)
            .map_err(cache_cloud_error)?
            != *scope
        {
            return Err(refused());
        }
        let transfer = self.begin_transfer(None, scope.space_id(), path, "upload")?;
        self.finish_transfer(
            transfer,
            "failed",
            0,
            Some("File saved locally but upload could not be queued. Open Saved upload copies in Transfers to recover it."),
        )
    }
    pub fn ordinary_create_scope(&self, space: &str) -> Result<Option<CacheScope>, CloudError> {
        if self.offline_cache.is_none() {
            return Ok(None);
        }
        match self.ordinary_write_scope(space) {
            Ok(scope) => Ok(Some(scope)),
            Err(error) if error.kind == ErrorKind::Offline => {
                let context = self.offline_cache.as_ref().ok_or_else(refused)?;
                self.cached_scope(space, context)
                    .map(Some)
                    .map_err(cache_cloud_error)
            }
            Err(error) => Err(error),
        }
    }
    pub fn capture_new_plaintext_create_parent(
        &self,
        expected_scope: &CacheScope,
        path: &str,
        expected_parent_id: Option<&str>,
        check: &dyn Fn() -> bool,
    ) -> Result<VerifiedCreateParent, CloudError> {
        self.prove_create_parent(expected_scope, path, expected_parent_id, check, true)
    }
    fn prove_create_parent(
        &self,
        expected_scope: &CacheScope,
        path: &str,
        expected_parent_id: Option<&str>,
        check: &dyn Fn() -> bool,
        require_absence: bool,
    ) -> Result<VerifiedCreateParent, CloudError> {
        self.create_cache(expected_scope)?;
        current(check)?;
        validate_remote_path(path).map_err(|_| refused())?;
        if !path.starts_with('/') || path == "/" || path.ends_with('/') {
            return Err(refused());
        }
        let (scope, root) = self.online_plaintext_scope(expected_scope.space_id())?;
        if scope != *expected_scope || !root.writable {
            return Err(refused());
        }
        if !self
            .backend
            .spaces()?
            .into_iter()
            .any(|space| space.id == scope.space_id() && space.writable && !space.encrypted)
        {
            return Err(refused());
        }
        let parent_path = parent_path(path)?;
        if parent_path != "/" && expected_parent_id.is_none() {
            return Err(refused());
        }
        let mut parent = root;
        let mut ancestor = String::new();
        for component in parent_path.split('/').filter(|part| !part.is_empty()) {
            current(check)?;
            ancestor.push('/');
            ancestor.push_str(component);
            parent = self.backend.stat(scope.space_id(), &ancestor)?;
            if !parent.directory || parent.encrypted || !parent.writable || parent.path != ancestor
            {
                return Err(refused());
            }
        }
        if expected_parent_id.is_some_and(|id| id != parent.id) {
            return Err(refused());
        }
        if require_absence {
            match self.backend.stat(scope.space_id(), path) {
                Err(error) if error.kind == ErrorKind::NotFound => {}
                Ok(_) => return Err(refused()),
                Err(error) => return Err(error),
            }
        }
        current(check)?;
        Ok(VerifiedCreateParent {
            scope,
            path: path.into(),
            parent_resource_id: parent.id,
        })
    }
    pub fn queue_new_plaintext_create_scoped(
        &self,
        request: CreateHandoffRequest<'_>,
        check: &dyn Fn() -> bool,
    ) -> Result<DurableCreateReceipt, CloudError> {
        let parent = request.parent;
        let cache = self.create_cache(&parent.scope)?;
        current(check)?;
        let metadata = request.source.metadata().map_err(io_error)?;
        if !metadata.is_file() || metadata.len() != request.expected_len {
            return Err(refused());
        }
        self.clean_create_headroom(&parent.scope, request.expected_len);
        let mut source = request.source.try_clone().map_err(io_error)?;
        source.seek(SeekFrom::Start(0)).map_err(io_error)?;
        let staged = cache
            .stage_ordinary_create(
                &parent.scope,
                OrdinaryCreateRequest {
                    max_pending_bytes: request.max_pending_bytes,
                    handoff_id: request.handoff_id.into(),
                    parent_resource_id: parent.parent_resource_id.clone(),
                    name: parent.path.rsplit('/').next().ok_or_else(refused)?.into(),
                    logical_path: parent.path.clone(),
                    expected_len: request.expected_len,
                    expected_sha256: request.expected_sha256.into(),
                },
                &mut source,
            )
            .map_err(cache_cloud_error)?;
        // Serialize only final bounded namespace proof/admission with existing
        // mutators. No body copy or background transfer holds this gate.
        let _execution = self.execution()?;
        let proof = self.capture_new_plaintext_create_parent(
            &parent.scope,
            &parent.path,
            Some(&parent.parent_resource_id),
            check,
        )?;
        if proof.parent_resource_id != parent.parent_resource_id {
            return Err(refused());
        }
        // The namespace proof above may perform bounded metadata HTTP; none
        // occurs while this publication guard is held. Serialize invalidation
        // and Ready CAS with cached_list's check-and-publish transaction.
        let _metadata = self.metadata_publication()?;
        current(check)?;
        cache
            .invalidate_paths(&parent.scope, &[&parent.path])
            .map_err(cache_cloud_error)?;
        let receipt = if staged.state == OrdinaryCreateState::Staged {
            cache
                .admit_ordinary_create(&parent.scope, &staged)
                .map_err(cache_cloud_error)?
        } else {
            staged
        };
        current(check)?;
        if receipt.state != OrdinaryCreateState::Ready {
            return Err(refused());
        }
        Ok(DurableCreateReceipt {
            scope: parent.scope.clone(),
            receipt,
        })
    }
    pub fn create_receipt_for_handoff(
        &self,
        scope: &CacheScope,
        path: &str,
        handoff_id: &str,
    ) -> Result<Option<DurableCreateReceipt>, CloudError> {
        let cache = self.create_cache(scope)?;
        let Some(receipt) = cache
            .ordinary_create_for_handoff(scope, handoff_id)
            .map_err(cache_cloud_error)?
        else {
            return Ok(None);
        };
        if receipt.write.logical_path != path {
            return Err(refused());
        }
        if receipt.state == OrdinaryCreateState::Staged {
            return Ok(None);
        }
        Ok(Some(self.validate_create_receipt(
            scope, path, handoff_id, &receipt,
        )?))
    }
    pub fn validate_create_receipt(
        &self,
        scope: &CacheScope,
        path: &str,
        handoff_id: &str,
        expected: &OrdinaryCreateReceipt,
    ) -> Result<DurableCreateReceipt, CloudError> {
        let cache = self.create_cache(scope)?;
        let actual = cache
            .ordinary_create_for_handoff(scope, handoff_id)
            .map_err(cache_cloud_error)?
            .ok_or_else(refused)?;
        // Cache normalizes only lifecycle/write-state/remote/ACK/disposition.
        // Every immutable write and body binding must match the durable intent.
        if !admitted(actual.state)
            || !actual.has_same_immutable_binding(expected)
            || actual.write.logical_path != path
        {
            return Err(refused());
        }
        if actual.body_evicted {
            // Only Cache's committed clean tombstone can replace opening the
            // body for cleanup. Missing unresolved/unqualified bodies fail.
            if actual.state != OrdinaryCreateState::Verified
                || actual.write.state != WriteState::Verified
                || !actual.local_handoff_acknowledged
                || actual.remote.is_none()
            {
                return Err(refused());
            }
        } else {
            let _body = cache
                .open_content(scope, &actual.write.content)
                .map_err(cache_cloud_error)?;
        }
        Ok(DurableCreateReceipt {
            scope: scope.clone(),
            receipt: actual,
        })
    }
    /// FUSE calls only after its exact V3 receipt and directory are fsynced.
    /// This records local acceptance, never remote delivery or replay authority.
    pub fn acknowledge_create_handoff(
        &self,
        scope: &CacheScope,
        path: &str,
        handoff_id: &str,
        expected: &OrdinaryCreateReceipt,
        check: &dyn Fn() -> bool,
    ) -> Result<DurableCreateReceipt, CloudError> {
        current(check)?;
        let actual = self.validate_create_receipt(scope, path, handoff_id, expected)?;
        let cache = self.create_cache(scope)?;
        let receipt = cache
            .acknowledge_ordinary_create_handoff(scope, &actual.receipt)
            .map_err(cache_cloud_error)?;
        current(check)?;
        // Cleanup is separate and best effort. It cannot alter an accepted
        // handoff/verified result into uncertain delivery or grant a resend.
        self.clean_create_headroom(scope, 0);
        Ok(DurableCreateReceipt {
            scope: scope.clone(),
            receipt,
        })
    }
    fn clean_create_headroom(&self, scope: &CacheScope, incoming_len: u64) {
        let Ok(cache) = self.create_cache(scope) else {
            return;
        };
        let Ok(quota) = cache.try_quota_bytes() else {
            return;
        };
        let target = quota.saturating_sub(incoming_len.saturating_mul(2));
        let _ = cache.evict_acknowledged_ordinary_create_bodies(scope, target, 64);
    }
    pub fn fetch_create_snapshot(
        &self,
        scope: &CacheScope,
        path: &str,
        handoff_id: &str,
    ) -> Result<FetchSnapshot, CloudError> {
        let receipt = self
            .create_receipt_for_handoff(scope, path, handoff_id)?
            .ok_or_else(refused)?;
        let file = self
            .create_cache(scope)?
            .open_content(scope, &receipt.receipt.write.content)
            .map_err(cache_cloud_error)?;
        Ok(FetchSnapshot {
            _temp: None,
            file: SnapshotReader::Cached(file),
        })
    }
    pub(super) fn create_view(
        &self,
        scope: &CacheScope,
        receipt: OrdinaryCreateReceipt,
    ) -> Result<PendingCreateView, CloudError> {
        let mut entry = self.remote_entry_for_pending_in_scope(scope, &receipt.write)?;
        entry.id = format!("raiun-pending-create:{}", receipt.handoff_id);
        entry.etag = format!("\"raiun-local-create:{}\"", receipt.handoff_id);
        entry.writable = false;
        Ok(PendingCreateView { receipt, entry })
    }
    pub fn pending_create(
        &self,
        scope: &CacheScope,
        path: &str,
    ) -> Result<Option<PendingCreateView>, CloudError> {
        if self.offline_cache.is_none() {
            return Ok(None);
        }
        let cache = self.create_cache(scope)?;
        let Some(write) = cache
            .pending_write_for_path(scope, path)
            .map_err(cache_cloud_error)?
        else {
            return Ok(None);
        };
        let Some(receipt) = cache
            .ordinary_create_for_write(scope, write.id)
            .map_err(cache_cloud_error)?
        else {
            return Ok(None);
        };
        if !active(receipt.state) {
            return Ok(None);
        }
        self.create_view(scope, receipt).map(Some)
    }
    pub fn pending_create_children(
        &self,
        scope: &CacheScope,
        parent_id: &str,
    ) -> Result<Vec<PendingCreateView>, CloudError> {
        if self.offline_cache.is_none() {
            return Ok(Vec::new());
        }
        let cache = self.create_cache(scope)?;
        let mut result = Vec::new();
        for write in cache
            .pending_writes_for_parent(scope, parent_id)
            .map_err(cache_cloud_error)?
        {
            if let Some(receipt) = cache
                .ordinary_create_for_write(scope, write.id)
                .map_err(cache_cloud_error)?
                && active(receipt.state)
            {
                if result.len() >= MAX_LIST_ENTRIES {
                    return Err(refused());
                }
                result.push(self.create_view(scope, receipt)?);
            }
        }
        Ok(result)
    }
    pub fn has_pending_create_overlap(
        &self,
        scope: &CacheScope,
        path: &str,
    ) -> Result<bool, CloudError> {
        if self.offline_cache.is_none() {
            return Ok(false);
        }
        self.create_cache(scope)?
            .ordinary_create_path_blocked(scope, path)
            .map_err(cache_cloud_error)
    }
    pub fn ordinary_create_page(
        &self,
        scope: &CacheScope,
        after: Option<i64>,
        limit: usize,
    ) -> Result<raiun_cache::OrdinaryCreatePage, CloudError> {
        self.create_cache(scope)?
            .ordinary_creates(scope, after, limit)
            .map_err(cache_cloud_error)
    }
    // Trusted live scope registration is needed for first mutations/listings.
    // Cache NotFound denotes an absent scope row, never a silent clean answer.
    // Normal legacy Match paths retain their original behavior. The public
    // overlap query protects all unresolved writes; this guard additionally
    // isolates only new-ledger custody. The complete scan never returns a
    // truncated clean answer and retains only one bounded page at a time.
    fn ledger_overlap(&self, scope: &CacheScope, path: &str) -> Result<bool, CloudError> {
        let cache = self.create_cache(scope)?;
        if !cache
            .ordinary_create_path_blocked(scope, path)
            .map_err(cache_cloud_error)?
        {
            return Ok(false);
        }
        let mut after = None;
        loop {
            let page = cache
                .ordinary_creates(scope, after, 256)
                .map_err(cache_cloud_error)?;
            for receipt in page.items {
                let other = receipt.write.logical_path.as_str();
                if receipt.state != OrdinaryCreateState::Verified
                    && (path == other
                        || path == "/"
                        || other == "/"
                        || path
                            .strip_prefix(other)
                            .is_some_and(|tail| tail.starts_with('/'))
                        || other
                            .strip_prefix(path)
                            .is_some_and(|tail| tail.starts_with('/')))
                {
                    return Ok(true);
                }
            }
            match page.next_after {
                Some(next) if after.is_none_or(|old| next > old) => after = Some(next),
                Some(_) => return Err(refused()),
                None => return Ok(false),
            }
        }
    }
    pub(super) fn create_overlap_live(
        &self,
        scope: &CacheScope,
        path: &str,
    ) -> Result<bool, CloudError> {
        let cache = self.create_cache(scope)?;
        match self.ledger_overlap(scope, path) {
            Err(error) if error.kind == ErrorKind::NotFound => {
                cache
                    .invalidate_paths(scope, &[path])
                    .map_err(cache_cloud_error)?;
                self.ledger_overlap(scope, path)
            }
            result => result,
        }
    }
    pub(super) fn guard_create_mutation(
        &self,
        space: &str,
        paths: &[&str],
    ) -> Result<(), CloudError> {
        if self.offline_cache.is_none() || self.vault_binding.is_some() {
            return Ok(());
        }
        let (scope, _) = self.online_plaintext_scope(space)?;
        for path in paths {
            if self.create_overlap_live(&scope, path)? {
                return Err(refused());
            }
        }
        Ok(())
    }
}

pub struct CreateUploadHooks {
    pub is_current: Arc<dyn Fn() -> bool + Send + Sync>,
    pub dispatch_allowed: Arc<dyn Fn(&CacheScope) -> bool + Send + Sync>,
}
#[cfg(unix)]
mod owner {
    use super::*;
    use std::io::Write;
    use std::{
        sync::Condvar,
        thread::{self, JoinHandle},
        time::Duration,
    };
    struct Shared {
        engine: Engine,
        stopping: AtomicBool,
        token: OperationCancellation,
        scopes: Mutex<Vec<CacheScope>>,
        wake: Condvar,
        signal: Mutex<u64>,
        hooks: CreateUploadHooks,
    }
    pub struct CreateUploadOwner {
        shared: Arc<Shared>,
        workers: Vec<JoinHandle<()>>,
        _lock: File,
        _directory: File,
    }
    #[derive(Clone)]
    pub struct CreateUploadHandle {
        shared: Arc<Shared>,
    }
    impl CreateUploadHandle {
        pub fn is_accepting(&self) -> bool {
            !self.shared.stopping.load(Ordering::Acquire) && (self.shared.hooks.is_current)()
        }
        pub fn wake_scope(&self, scope: &CacheScope) -> Result<(), CloudError> {
            if !self.is_accepting() {
                return Err(refused());
            }
            let mut scopes = self.shared.scopes.lock().map_err(|_| refused())?;
            if !scopes.contains(scope) {
                if scopes.len() >= 256 {
                    return Err(refused());
                }
                self.shared
                    .engine
                    .create_cache(scope)?
                    .recover_interrupted_ordinary_creates(scope)
                    .map_err(cache_cloud_error)?;
                scopes.push(scope.clone());
            }
            drop(scopes);
            let mut signal = self.shared.signal.lock().map_err(|_| refused())?;
            *signal = signal.wrapping_add(1);
            self.shared.wake.notify_all();
            Ok(())
        }
        pub fn stop_admission(&self) {
            self.shared.stopping.store(true, Ordering::Release);
            self.shared.token.cancel();
            self.shared.wake.notify_all();
        }
    }
    impl CreateUploadOwner {
        pub fn handle(&self) -> CreateUploadHandle {
            CreateUploadHandle {
                shared: self.shared.clone(),
            }
        }
        pub fn stop_and_join(&mut self) -> Result<(), CloudError> {
            self.handle().stop_admission();
            let mut panicked = false;
            for worker in self.workers.drain(..) {
                panicked |= worker.join().is_err();
            }
            if panicked { Err(refused()) } else { Ok(()) }
        }
    }
    impl Drop for CreateUploadOwner {
        fn drop(&mut self) {
            let _ = self.stop_and_join();
        }
    }
    impl Engine {
        pub fn start_create_upload_owner(
            &self,
            hooks: CreateUploadHooks,
        ) -> Result<CreateUploadOwner, CloudError> {
            if self.offline_cache.is_none()
                || self.vault_binding.is_some()
                || self.account_scope.is_none()
            {
                return Err(refused());
            }
            let directory = File::from(
                rustix::fs::open(
                    &self.inner.state_dir,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(io_error)?,
            );
            let lock = File::from(
                rustix::fs::openat(
                    &directory,
                    ".ordinary-create-uploader.lock",
                    rustix::fs::OFlags::CREATE
                        | rustix::fs::OFlags::RDWR
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                )
                .map_err(io_error)?,
            );
            use std::os::unix::fs::MetadataExt;
            let metadata = lock.metadata().map_err(io_error)?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != directory.metadata().map_err(io_error)?.uid()
                || metadata.mode() & 0o077 != 0
            {
                return Err(refused());
            }
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                .map_err(io_error)?;
            // Recovery is scoped lazily on first watch, after this sole-owner lock.
            let shared = Arc::new(Shared {
                engine: self.clone(),
                stopping: AtomicBool::new(false),
                token: OperationCancellation::new(),
                scopes: Mutex::new(Vec::new()),
                wake: Condvar::new(),
                signal: Mutex::new(0),
                hooks,
            });
            let mut owner = CreateUploadOwner {
                shared: shared.clone(),
                workers: Vec::new(),
                _lock: lock,
                _directory: directory,
            };
            // One coordinator-free receiver per worker; bounded two-row SQL
            // discovery, not an in-memory queue of every pending body.
            for index in 0..2 {
                let engine = self.clone();
                let shared = shared.clone();
                owner.workers.push(
                    thread::Builder::new()
                        .name(format!("raiun-create-{index}"))
                        .spawn(move || run(engine, shared))
                        .map_err(io_error)?,
                );
            }
            Ok(owner)
        }
    }
    fn run(engine: Engine, shared: Arc<Shared>) {
        loop {
            if shared.stopping.load(Ordering::Acquire) {
                return;
            }
            let scopes = match shared.scopes.lock() {
                Ok(scopes) => scopes.clone(),
                Err(_) => return,
            };
            let mut did_work = false;
            for scope in scopes {
                if shared.stopping.load(Ordering::Acquire)
                    || engine.inner.sync_paused.load(Ordering::Acquire)
                    || !(shared.hooks.is_current)()
                {
                    break;
                }
                let Ok(cache) = engine.create_cache(&scope) else {
                    continue;
                };
                if !(shared.hooks.dispatch_allowed)(&scope) {
                    continue;
                }
                let Ok(ready) = cache.ready_ordinary_creates(&scope, 2) else {
                    continue;
                };
                for receipt in ready {
                    if shared.stopping.load(Ordering::Acquire) {
                        return;
                    }
                    match engine.deliver_create(&scope, &receipt, &shared.token, &|| {
                        !shared.stopping.load(Ordering::Acquire)
                            && (shared.hooks.is_current)()
                            && (shared.hooks.dispatch_allowed)(&scope)
                    }) {
                        Ok(work) => did_work |= work,
                        Err(error)
                            if !shared.stopping.load(Ordering::Acquire)
                                && (shared.hooks.is_current)()
                                && !engine.inner.sync_paused.load(Ordering::Acquire)
                                && error.kind != ErrorKind::Offline =>
                        {
                            // Definitely pre-claim validation/storage failures
                            // require attention. A stale claim cannot be reset
                            // by this Ready-only CAS.
                            let _ = cache.block_ordinary_create(&scope, &receipt);
                        }
                        Err(_) => {}
                    }
                }
            }
            let Ok(signal) = shared.signal.lock() else {
                return;
            };
            drop(shared.wake.wait_timeout(
                signal,
                if did_work {
                    Duration::from_millis(10)
                } else {
                    Duration::from_secs(1)
                },
            ));
        }
    }
    impl Engine {
        fn deliver_create(
            &self,
            scope: &CacheScope,
            receipt: &OrdinaryCreateReceipt,
            token: &OperationCancellation,
            check: &dyn Fn() -> bool,
        ) -> Result<bool, CloudError> {
            if self.inner.sync_paused.load(Ordering::Acquire) {
                return Ok(false);
            }
            let cache = self.create_cache(scope)?;
            current(check)?;
            let mut body = cache
                .open_content_cancellable(scope, &receipt.write.content, || token.is_cancelled())
                .map_err(cache_cloud_error)?;
            let mut source = NamedTempFile::new_in(self.cache_dir()).map_err(io_error)?;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                if token.is_cancelled() {
                    return Err(refused());
                }
                let count = body.read(&mut buffer).map_err(io_error)?;
                if count == 0 {
                    break;
                }
                source
                    .as_file_mut()
                    .write_all(&buffer[..count])
                    .map_err(io_error)?;
            }
            drop(body);
            source.as_file().sync_all().map_err(io_error)?;
            if hash_cancelled(source.path(), token)? != receipt.sha256
                || source.as_file().metadata().map_err(io_error)?.len() != receipt.byte_len
            {
                return Err(refused());
            }
            // Remember pause refusal independently of its present value: a
            // fast resume must not turn an unclaimed paused job into Conflict.
            let paused_seen = std::cell::Cell::new(false);
            let preclaim_check = || {
                if self.inner.sync_paused.load(Ordering::Acquire) {
                    paused_seen.set(true);
                    false
                } else {
                    check()
                }
            };
            let proof = self.capture_new_plaintext_create_parent(
                scope,
                &receipt.write.logical_path,
                Some(&receipt.write.parent_resource_id),
                &preclaim_check,
            );
            if paused_seen.get() || self.inner.sync_paused.load(Ordering::Acquire) {
                return Ok(false);
            }
            proof?;
            let authorized = current(&preclaim_check);
            if paused_seen.get() {
                return Ok(false);
            }
            authorized?;
            let Some(claim) = cache
                .claim_ordinary_create(scope, receipt)
                .map_err(cache_cloud_error)?
            else {
                return Ok(false);
            };
            let mut transfer = None;
            let mut completed = false;
            let outcome = (|| {
                if token.is_cancelled() {
                    return Err(refused());
                }
                current(&|| check() && !self.inner.sync_paused.load(Ordering::Acquire))?;
                {
                    let _metadata = self.metadata_publication()?;
                    cache
                        .invalidate_paths(scope, &[&receipt.write.logical_path])
                        .map_err(cache_cloud_error)?;
                }
                transfer = Some(self.begin_transfer(
                    None,
                    scope.space_id(),
                    &receipt.write.logical_path,
                    "upload",
                )?);
                let uploaded = self.backend.upload_in_root_with_cancellation(
                    scope.space_id(),
                    &receipt.write.logical_path,
                    source.path(),
                    WriteCondition::Absent,
                    scope.root_resource_id(),
                    token,
                )?;
                if uploaded.id.is_empty()
                    || uploaded.directory
                    || uploaded.encrypted
                    || !uploaded.writable
                    || uploaded.path != receipt.write.logical_path
                    || uploaded.size != receipt.byte_len
                    || !strong(&uploaded.etag)
                {
                    return Err(refused());
                }
                current(&|| check() && !self.inner.sync_paused.load(Ordering::Acquire))?;
                let download = NamedTempFile::new_in(self.cache_dir()).map_err(io_error)?;
                let verified = self.backend.download_in_root_with_cancellation(
                    scope.space_id(),
                    &receipt.write.logical_path,
                    Some(&uploaded.etag),
                    download.path(),
                    scope.root_resource_id(),
                    token,
                )?;
                if verified.id != uploaded.id
                    || verified.etag != uploaded.etag
                    || verified.path != uploaded.path
                    || verified.size != receipt.byte_len
                    || verified.directory
                    || verified.encrypted
                    || !verified.writable
                    || hash_cancelled(download.path(), token)? != receipt.sha256
                    || fs::metadata(download.path()).map_err(io_error)?.len() != receipt.byte_len
                {
                    return Err(refused());
                }
                current(&|| check() && !self.inner.sync_paused.load(Ordering::Acquire))?;
                if token.is_cancelled() {
                    return Err(refused());
                }
                self.prove_create_parent(
                    scope,
                    &receipt.write.logical_path,
                    Some(&receipt.write.parent_resource_id),
                    &|| check() && !self.inner.sync_paused.load(Ordering::Acquire),
                    false,
                )?;
                current(&|| check() && !self.inner.sync_paused.load(Ordering::Acquire))?;
                cache
                    .complete_ordinary_create(scope, &claim, &verified, &receipt.sha256)
                    .map_err(cache_cloud_error)?;
                completed = true;
                Ok(())
            })();
            let progress = if let Some(id) = transfer {
                self.finish_transfer(
                    id,
                    if completed { "completed" } else { "failed" },
                    if completed { receipt.byte_len } else { 0 },
                    outcome
                        .as_ref()
                        .err()
                        .map(|error: &CloudError| error.message.as_str()),
                )
            } else {
                Ok(())
            };
            if outcome.is_err() && !completed {
                cache
                    .mark_ordinary_create_uncertain(scope, claim)
                    .map_err(cache_cloud_error)?;
            }
            if completed {
                self.clean_create_headroom(scope, 0);
            }
            progress?;
            Ok(true)
        }
    }
    fn hash_cancelled(path: &Path, token: &OperationCancellation) -> Result<String, CloudError> {
        let mut file = File::open(path).map_err(io_error)?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            if token.is_cancelled() {
                return Err(refused());
            }
            let count = file.read(&mut buffer).map_err(io_error)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
        Ok(format!("{:x}", hash.finalize()))
    }
    fn strong(etag: &str) -> bool {
        etag.len() >= 2
            && etag.starts_with('"')
            && etag.ends_with('"')
            && !etag.contains(['\r', '\n'])
    }
}
#[cfg(unix)]
pub use owner::{CreateUploadHandle, CreateUploadOwner};

//! One operation-specific joined FILE/DIRECTORY child-create phase driver.
//! Raw native custody never leaves its original owner thread; SDK workers own
//! only sealed targets, metadata proofs and authenticated private readers.
use super::*;
use crate::close_capture_admission::OwnedCreateAdmission;
use crate::file_create_phase::TaskFlight;
use crate::namespace_intent::{CapturedAuthorization, NamespaceObjectKind};
use crate::opencloud::vault_child_create::VaultChildCreateParent;
use crate::{VaultCachedChildCreateRecord, VaultChildCreateRecord, VaultChildCreateSource};
use raiun_opencloud::vault_backend::{
    VaultChildDirectoryCreateOutcome, VaultChildDirectoryCreateTarget, VaultChildFileCreateOutcome,
    VaultChildFileCreateTarget, VaultVerifiedChildDirectory, VaultVerifiedChildFile,
};
use sha2::Digest;
use std::sync::atomic::{AtomicBool, AtomicU64};
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Discover,
    Prepare,
    Send,
}
struct Key {
    nonce: u64,
    context: usize,
    root: crate::ConfiguredRootIdentity,
    authorization: CapturedAuthorization,
    generation: u64,
    kind: NamespaceObjectKind,
}
enum Pins {
    File(native_vault_file_create::VaultFilePins),
    Directory(native_vault_directory_create::VaultDirectoryPins),
}
#[derive(Clone)]
enum Proof {
    File(native_vault_file_create::VaultFileSendProof),
    Directory(native_vault_directory_create::VaultDirectorySendProof),
}
impl Proof {
    fn check(&self) -> Result<(), Error> {
        match self {
            Self::File(p) => p.check(),
            Self::Directory(p) => p.check(),
        }
    }
}
impl Pins {
    fn verify(&self, connection: &ConfiguredRootConnection, converted: bool) -> Result<(), Error> {
        match self {
            Self::File(p) => p.verify(connection, converted),
            Self::Directory(p) => p.verify(connection, converted),
        }
    }
    fn source(&self, sha: Option<[u8; 32]>) -> VaultChildCreateSource {
        match self {
            Self::File(p) => VaultChildCreateSource {
                kind: NamespaceObjectKind::File,
                volume: p.file().volume_serial,
                file: p.file().file_index,
                usn: p.usn(),
                parent_file: p.parent_file().file_index,
                parent_usn: p.parent_usn(),
                components: p.components().to_vec(),
                plaintext_len: p.len(),
                plaintext_sha256: sha,
            },
            Self::Directory(p) => VaultChildCreateSource {
                kind: NamespaceObjectKind::Directory,
                volume: p.file().volume_serial,
                file: p.file().file_index,
                usn: p.usn(),
                parent_file: p.parent_file().file_index,
                parent_usn: p.parent_usn(),
                components: p.components().to_vec(),
                plaintext_len: 0,
                plaintext_sha256: None,
            },
        }
    }
    fn proof(&self) -> Result<Proof, Error> {
        match self {
            Self::File(p) => Ok(Proof::File(p.send_proof()?)),
            Self::Directory(p) => Ok(Proof::Directory(p.send_proof()?)),
        }
    }
}
enum Target {
    Cached(raiun_opencloud::vault_backend::VaultCachedChildTarget),
    File(VaultChildFileCreateTarget),
    Directory(VaultChildDirectoryCreateTarget),
}
impl Target {
    fn encoded(&self) -> &str {
        match self {
            Self::Cached(t) => t.encoded_target(),
            Self::File(t) => t.encoded_target(),
            Self::Directory(t) => t.encoded_target(),
        }
    }
    fn integrity(&self) -> &str {
        match self {
            Self::Cached(t) => t.integrity_token(),
            Self::File(t) => t.integrity_token(),
            Self::Directory(t) => t.integrity_token(),
        }
    }
}
enum Verified {
    Cached(crate::opencloud::VaultCachedNamespaceQueued),
    File(VaultVerifiedChildFile),
    Directory(VaultVerifiedChildDirectory),
}
impl Verified {
    fn entry(&self) -> Option<&raiun_core::backend::RemoteEntry> {
        match self {
            Self::Cached(_) => None,
            Self::File(p) => Some(p.entry()),
            Self::Directory(p) => Some(p.entry()),
        }
    }
}
struct Prepared {
    parent: Arc<VaultChildCreateParent>,
    source: VaultChildCreateSource,
    target: Target,
}
struct Sent {
    parent: Arc<VaultChildCreateParent>,
    record: Record,
    proof: Verified,
}
enum Record {
    Online(Arc<dyn VaultChildCreateRecord>),
    Cached(Arc<dyn VaultCachedChildCreateRecord>),
}
impl Record {
    fn root(&self) -> crate::ConfiguredRootIdentity {
        match self {
            Self::Online(r) => r.descriptor().root,
            Self::Cached(r) => r.descriptor().root,
        }
    }
    fn parent_identity(&self) -> [u8; 16] {
        match self {
            Self::Online(r) => r.descriptor().parent_identity,
            Self::Cached(r) => r.descriptor().parent_identity,
        }
    }
    fn logical_path(&self) -> &str {
        match self {
            Self::Online(r) => &r.descriptor().logical_path,
            Self::Cached(r) => &r.descriptor().logical_path,
        }
    }
    fn online_descriptor(&self) -> Result<&crate::VaultChildCreateDescriptor, BackendError> {
        match self {
            Self::Online(r) => Ok(r.descriptor()),
            Self::Cached(_) => Err(BackendError::Unavailable),
        }
    }
    fn claim_send(&self) -> Result<(), BackendError> {
        self.online_descriptor()?;
        match self {
            Self::Online(r) => r.claim_send(),
            Self::Cached(_) => Err(BackendError::Unavailable),
        }
    }
    fn record_remote(
        &self,
        proof: &crate::VaultChildCreateRemoteProof,
    ) -> Result<(), BackendError> {
        match self {
            Self::Online(r) => r.record_remote(proof),
            Self::Cached(_) => Err(BackendError::Unavailable),
        }
    }
    fn record_native_completed(&self, identity: [u8; 16]) -> Result<(), BackendError> {
        match self {
            Self::Online(r) => r.record_native_completed(identity),
            Self::Cached(_) => Err(BackendError::Unavailable),
        }
    }
    fn source(&self) -> &VaultChildCreateSource {
        match self {
            Self::Online(r) => &r.descriptor().source,
            Self::Cached(r) => &r.descriptor().source,
        }
    }
    fn open_reader(
        &self,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Box<dyn std::io::Read + Send>, BackendError> {
        match self {
            Self::Online(r) => r.open_reader(cancelled),
            Self::Cached(r) => r.open_reader(cancelled),
        }
    }
    fn record_local_queued(
        &self,
        receipt: &crate::VaultCachedNamespaceQueued,
    ) -> Result<(), BackendError> {
        match self {
            Self::Online(r) => r.record_local_queued(receipt),
            Self::Cached(r) => r.record_local_queued(receipt),
        }
    }
    fn record_local_queued_native(
        &self,
        receipt: &crate::VaultCachedNamespaceQueued,
        identity: [u8; 16],
        file: u64,
        usn: i64,
    ) -> Result<(), BackendError> {
        match self {
            Self::Online(r) => r.record_local_queued_native(receipt, identity, file, usn),
            Self::Cached(r) => r.record_local_queued_native(receipt, identity, file, usn),
        }
    }
}
enum Operation {
    // Volatile pre-capture polling only: retains the same original parent,
    // epoch, admission, candidate and job deadline. No discovery or mutation.
    AwaitClosedWriter {
        parent: Arc<VaultChildCreateParent>,
    },
    Discover {
        backend: Arc<crate::OpenCloudPlaceholderBackend>,
        components: Vec<String>,
        job: crate::StreamedRecoveryJob,
        current: crate::opencloud::file_create::Current,
        generation: Arc<AtomicU64>,
    },
    Prepare {
        parent: Arc<VaultChildCreateParent>,
        source: VaultChildCreateSource,
    },
    Send {
        parent: Arc<VaultChildCreateParent>,
        record: Record,
        proof: Proof,
        target: Target,
        dispatch: Arc<dyn Fn() -> bool + Send + Sync>,
    },
}
enum ReplyKind {
    Discovered(Result<Option<Arc<VaultChildCreateParent>>, BackendError>),
    Prepared(Result<Prepared, BackendError>),
    Sent(Result<Sent, BackendError>),
}
pub struct VaultChildCreateTask {
    key: Arc<Key>,
    operation: Option<Operation>,
    _flight: TaskFlight,
}
pub struct VaultChildCreateReply {
    key: Arc<Key>,
    phase: Phase,
    reply: ReplyKind,
}
impl VaultChildCreateReply {
    /// Fixed phase information only, including discovery of ordinary parents.
    pub fn failure_context(&self) -> &'static str {
        match &self.reply {
            ReplyKind::Discovered(Err(_)) => {
                "Creation paused: account-bound parent classification failed. Recovery files have been kept."
            }
            ReplyKind::Discovered(Ok(_)) => {
                "Creation paused: parent classification reply or native source admission failed. Recovery files have been kept."
            }
            ReplyKind::Prepared(_) => {
                "Encrypted creation paused: protected source preparation or durable intent publication failed. Recovery files have been kept."
            }
            ReplyKind::Sent(_) => {
                "Encrypted creation paused: cloud verification or native completion failed. Recovery files have been kept."
            }
        }
    }
}
pub enum VaultChildCreateStep {
    Task(VaultChildCreateTask),
    Ordinary,
    BusyBeforeCapture(VaultChildCreateTask),
    Busy,
    Completed,
    Held,
}
impl VaultChildCreateTask {
    pub fn kind(&self) -> NamespaceObjectKind {
        self.key.kind
    }
    pub fn execute(mut self) -> VaultChildCreateReply {
        let operation = self
            .operation
            .take()
            .expect("single-use private vault create task");
        let (phase, reply) = match operation {
            Operation::AwaitClosedWriter { parent } => (
                Phase::Discover,
                ReplyKind::Discovered(parent.check().map(|()| Some(parent.clone()))),
            ),
            Operation::Discover {
                backend,
                components,
                job,
                current,
                generation,
            } => (
                Phase::Discover,
                ReplyKind::Discovered(backend.capture_vault_child_create_parent(
                    &components,
                    self.key.root,
                    self.key.authorization,
                    &job,
                    current,
                    generation,
                )),
            ),
            Operation::Prepare { parent, source } => {
                let result = (|| {
                    parent.check()?;
                    let name = source.components.last().ok_or(BackendError::Unavailable)?;
                    let path = format!("{}/{}", parent.metadata().path.trim_end_matches('/'), name);
                    let stop = || parent.is_stopped();
                    let cancellation = crate::vault_custody::VaultUploadCancellation {
                        generation: parent.generation(),
                        expected: parent.authorization().agent_generation,
                        cancelled: &stop,
                    };
                    let budget = parent.job().cancellation().bounded_request();
                    let context = raiun_opencloud::RangeReadContext {
                        deadline: budget.deadline(),
                        token_generation: parent.authorization().token_generation,
                    };
                    let binding = parent.vault().backend().binding();
                    let target = if binding.is_cached_only() {
                        Target::Cached(
                            binding
                                .prepare_cached_child_create(
                                    &path,
                                    parent.metadata(),
                                    source.kind == NamespaceObjectKind::Directory,
                                    &stop,
                                )
                                .map_err(|_| BackendError::Unavailable)?,
                        )
                    } else {
                        match source.kind {
                            NamespaceObjectKind::File => Target::File(
                                binding
                                    .prepare_child_file_create(
                                        &path,
                                        parent.metadata(),
                                        source.plaintext_len,
                                        source.plaintext_sha256.ok_or(BackendError::Unavailable)?,
                                        parent.job().deadline(),
                                        &cancellation,
                                    )
                                    .map_err(|_| BackendError::Unavailable)?,
                            ),
                            NamespaceObjectKind::Directory => Target::Directory(
                                binding
                                    .prepare_child_directory_create(
                                        &path,
                                        parent.metadata(),
                                        &cancellation,
                                        context,
                                    )
                                    .map_err(|_| BackendError::Unavailable)?,
                            ),
                        }
                    };
                    parent.check()?;
                    Ok(Prepared {
                        parent,
                        source,
                        target,
                    })
                })();
                (Phase::Prepare, ReplyKind::Prepared(result))
            }
            Operation::Send {
                parent,
                record,
                proof,
                target,
                dispatch,
            } => {
                let result = (|| {
                    parent.check()?;
                    proof.check().map_err(|_| BackendError::Unavailable)?;
                    let stop = || parent.is_stopped();
                    let cancellation = crate::vault_custody::VaultUploadCancellation {
                        generation: parent.generation(),
                        expected: parent.authorization().agent_generation,
                        cancelled: &stop,
                    };
                    let mut before = || {
                        if stop() || !dispatch() {
                            return Err(raiun_core::backend::CloudError::new(
                                raiun_core::backend::ErrorKind::Forbidden,
                                "vault create stopped",
                            ));
                        }
                        proof.check().map_err(|_| {
                            raiun_core::backend::CloudError::new(
                                raiun_core::backend::ErrorKind::Conflict,
                                "vault create native source changed",
                            )
                        })?;
                        record.claim_send().map_err(|_| {
                            raiun_core::backend::CloudError::new(
                                raiun_core::backend::ErrorKind::Forbidden,
                                "vault create durable claim unavailable",
                            )
                        })
                    };
                    let binding = parent.vault().backend().binding();
                    let source = record.source();
                    let verified = match target {
                        Target::Cached(target) => {
                            if !dispatch() {
                                return Err(BackendError::Unavailable);
                            }
                            proof.check().map_err(|_| BackendError::Unavailable)?;
                            let result = if source.kind == NamespaceObjectKind::File {
                                let original = parent.clone();
                                let mut reader =
                                    record.open_reader(Arc::new(move || original.is_stopped()))?;
                                binding.queue_cached_child_create(
                                    target,
                                    &mut reader,
                                    source.plaintext_len,
                                    source.plaintext_sha256.ok_or(BackendError::Unavailable)?,
                                    &stop,
                                )
                            } else {
                                let sha: [u8; 32] = sha2::Sha256::digest([]).into();
                                binding.queue_cached_child_create(
                                    target,
                                    &mut std::io::empty(),
                                    0,
                                    sha,
                                    &stop,
                                )
                            }
                            .map_err(|_| BackendError::Unavailable)?;
                            parent.check()?;
                            proof.check().map_err(|_| BackendError::Unavailable)?;
                            let receipt = match &record {
                                Record::Online(r) => crate::opencloud::VaultCachedNamespaceQueued::child(
                                    r.descriptor(), result,
                                )?,
                                Record::Cached(r) => crate::opencloud::VaultCachedNamespaceQueued::child_pending_parent(
                                    r.descriptor(), result,
                                )?,
                            };
                            record.record_local_queued(&receipt)?;
                            Verified::Cached(receipt)
                        }
                        Target::File(target) => {
                            let original = parent.clone();
                            let cancel: Arc<dyn Fn() -> bool + Send + Sync> =
                                Arc::new(move || original.is_stopped());
                            let mut reader = record.open_reader(cancel)?;
                            match parent
                                .vault()
                                .backend()
                                .send_child_file_create(
                                    record.parent_identity(),
                                    record.logical_path(),
                                    parent.metadata(),
                                    target,
                                    &mut reader,
                                    parent.job().deadline(),
                                    &cancellation,
                                    &mut before,
                                )
                                .map_err(|_| BackendError::Unavailable)?
                            {
                                VaultChildFileCreateOutcome::Verified(proof) => {
                                    Verified::File(proof)
                                }
                                VaultChildFileCreateOutcome::NeedsReconciliation { .. } => {
                                    return Err(BackendError::Unavailable);
                                }
                            }
                        }
                        Target::Directory(target) => {
                            let budget = parent.job().cancellation().bounded_request();
                            let context = raiun_opencloud::RangeReadContext {
                                deadline: budget.deadline(),
                                token_generation: parent.authorization().token_generation,
                            };
                            match binding
                                .send_child_directory_create(
                                    record.logical_path(),
                                    parent.metadata(),
                                    target,
                                    &cancellation,
                                    &mut before,
                                    context,
                                )
                                .map_err(|_| BackendError::Unavailable)?
                            {
                                VaultChildDirectoryCreateOutcome::Verified(proof) => {
                                    Verified::Directory(proof)
                                }
                                VaultChildDirectoryCreateOutcome::NeedsReconciliation {
                                    ..
                                } => return Err(BackendError::Unavailable),
                            }
                        }
                    };
                    parent.check()?;
                    proof.check().map_err(|_| BackendError::Unavailable)?;
                    if !matches!(&verified, Verified::Cached(_)) {
                        let remote = crate::VaultChildCreateRemoteProof::new(
                            record.online_descriptor()?,
                            verified.entry().ok_or(BackendError::Unavailable)?,
                        )?;
                        record.record_remote(&remote)?;
                    }
                    Ok(Sent {
                        parent,
                        record,
                        proof: verified,
                    })
                })();
                (Phase::Send, ReplyKind::Sent(result))
            }
        };
        VaultChildCreateReply {
            key: self.key.clone(),
            phase,
            reply,
        }
    }
}
impl VaultChildCreateReply {
    pub fn kind(&self) -> NamespaceObjectKind {
        self.key.kind
    }
}
#[derive(Default)]
pub(super) struct Owner {
    closed: bool,
    nonce: u64,
    attempt: Option<Attempt>,
}
struct Attempt {
    key: Arc<Key>,
    phase: Phase,
    done: Arc<AtomicBool>,
    backend: Arc<crate::OpenCloudPlaceholderBackend>,
    components: Vec<String>,
    name: String,
    job: crate::StreamedRecoveryJob,
    current: crate::opencloud::file_create::Current,
    generation: Arc<AtomicU64>,
    ticket: OwnedCreateAdmission,
    local: Option<Pins>,
    parent: Option<Arc<VaultChildCreateParent>>,
    published: bool,
}
impl Attempt {
    fn task(&mut self, phase: Phase, operation: Operation) -> VaultChildCreateTask {
        let (done, flight) = TaskFlight::new();
        self.phase = phase;
        self.done = done;
        VaultChildCreateTask {
            key: self.key.clone(),
            operation: Some(operation),
            _flight: flight,
        }
    }
    fn check(&self, connection: &ConfiguredRootConnection) -> Result<(), Error> {
        use crate::CreateAdmissionStage as S;
        let refused = |stage| Error::CreateAdmission { stage };
        if !connection.connected || connection.context_key != self.key.context {
            return Err(refused(S::NativeContext));
        }
        if self.job.is_stopped() {
            return Err(refused(S::OriginalJob));
        }
        if !(self.current)(self.key.authorization) {
            return Err(refused(S::Authorization));
        }
        if !self.ticket.is_current() {
            return Err(refused(S::Ticket));
        }
        if self.backend.is_revoked()
            || self.generation.load(Ordering::Acquire) != self.key.authorization.agent_generation
        {
            return Err(refused(S::NativeContext));
        }
        let root = connection.root.as_ref().ok_or_else(|| refused(S::Root))?;
        root.verify_identity(true).map_err(|_| refused(S::Root))?;
        root.verify_registered().map_err(|_| refused(S::Root))?;
        if root.identity.volume_serial != self.key.root.volume_serial
            || root.identity.file_index != self.key.root.file_index
        {
            return Err(refused(S::Root));
        }
        Ok(())
    }
}
impl Owner {
    pub(super) fn active(&self) -> bool {
        self.attempt.is_some()
    }
}
impl ConfiguredRootConnection {
    pub(crate) fn begin_vault_child_create(
        &self,
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        components: &[&str],
        name: &str,
        kind: NamespaceObjectKind,
        auth: CapturedAuthorization,
        generation: u64,
        job: &crate::StreamedRecoveryJob,
        current: crate::opencloud::file_create::Current,
        owner_generation: Arc<AtomicU64>,
    ) -> Result<VaultChildCreateStep, Error> {
        use crate::CreateAdmissionStage as S;
        let refused = |stage| Error::CreateAdmission { stage };
        if generation == 0
            || !valid_component(name)
            || components.is_empty()
            || components.iter().any(|c| !valid_component(c))
            || !(current)(auth)
        {
            return Err(refused(S::Candidate));
        }
        let mut owner = self
            .vault_child_owner
            .try_borrow_mut()
            .map_err(|_| refused(S::OwnerBorrow))?;
        if owner.closed {
            return Err(refused(S::OwnerClosed));
        }
        if owner.attempt.is_some() {
            return Ok(VaultChildCreateStep::Busy);
        }
        let (tracker, recovery) = self.file_create_guard_context(backend)?;
        if recovery
            .has_unresolved_namespace_for_fresh_create()
            .map_err(|_| refused(S::RecoveryScan))?
        {
            return Err(refused(S::RecoveryPending));
        }
        if recovery
            .has_unresolved_content_authenticated_legacy()
            .map_err(|_| refused(S::ContentScan))?
        {
            return Err(refused(S::ContentPending));
        }
        let ticket = match tracker.try_begin_create() {
            Some(ticket) => ticket,
            None if tracker.known_busy_for_create() => return Ok(VaultChildCreateStep::Busy),
            None => return Err(refused(S::CloseAdmission)),
        };
        let observation = ticket.observation_probe();
        let original = current.clone();
        let current: crate::opencloud::file_create::Current =
            Arc::new(move |auth| original(auth) && observation());
        let root = self.root.as_ref().ok_or_else(|| refused(S::Root))?;
        owner.nonce = owner
            .nonce
            .checked_add(1)
            .ok_or_else(|| refused(S::OwnerCounter))?;
        let key = Arc::new(Key {
            nonce: owner.nonce,
            context: self.context_key,
            root: crate::ConfiguredRootIdentity {
                volume_serial: root.identity.volume_serial,
                file_index: root.identity.file_index,
            },
            authorization: auth,
            generation,
            kind,
        });
        let mut attempt = Attempt {
            key,
            phase: Phase::Discover,
            done: Arc::new(AtomicBool::new(true)),
            backend: backend.clone(),
            components: components.iter().map(|c| (*c).to_owned()).collect(),
            name: name.into(),
            job: job.clone(),
            current: current.clone(),
            generation: owner_generation.clone(),
            ticket,
            local: None,
            parent: None,
            published: false,
        };
        attempt.check(self)?;
        let task = attempt.task(
            Phase::Discover,
            Operation::Discover {
                backend: backend.clone(),
                components: attempt.components.clone(),
                job: job.clone(),
                current,
                generation: owner_generation,
            },
        );
        owner.attempt = Some(attempt);
        Ok(VaultChildCreateStep::Task(task))
    }
    pub(crate) fn advance_vault_child_create(
        &self,
        reply: VaultChildCreateReply,
    ) -> Result<VaultChildCreateStep, Error> {
        let mut owner = self
            .vault_child_owner
            .try_borrow_mut()
            .map_err(|_| Error::ConnectionStateInvalid)?;
        let mut attempt = owner.attempt.take().ok_or(Error::ConnectionStateInvalid)?;
        let mut completed = false;
        let result = (|| {
            if owner.closed
                || !Arc::ptr_eq(&attempt.key, &reply.key)
                || attempt.phase != reply.phase
                || !attempt.done.load(Ordering::Acquire)
                || attempt.key.nonce == 0
                || attempt.key.generation == 0
            {
                return Err(Error::ConnectionStateInvalid);
            }
            attempt.check(self)?;
            match reply.reply {
                ReplyKind::Discovered(result) => {
                    let Some(parent) = result.map_err(|_| Error::EditRecoveryUnavailable)? else {
                        completed = true;
                        return Ok(VaultChildCreateStep::Ordinary);
                    };
                    parent.check().map_err(|_| Error::EditRecoveryUnavailable)?;
                    let pins = match attempt.key.kind {
                        NamespaceObjectKind::File => {
                            let Some(pins) = native_vault_file_create::VaultFilePins::pin(
                                self,
                                &attempt.backend,
                                parent.components(),
                                parent.route(),
                                parent.opaque(),
                                &attempt.name,
                            )?
                            else {
                                // No child pin, snapshot, intent or SDK send exists.
                                // Keep this exact attempt rather than minting a new
                                // epoch/candidate or restarting its deadline.
                                return Ok(VaultChildCreateStep::BusyBeforeCapture(attempt.task(
                                    Phase::Discover,
                                    Operation::AwaitClosedWriter { parent },
                                )));
                            };
                            Pins::File(pins)
                        }
                        NamespaceObjectKind::Directory => {
                            Pins::Directory(native_vault_directory_create::VaultDirectoryPins::pin(
                                self,
                                &attempt.backend,
                                parent.components(),
                                parent.route(),
                                parent.opaque(),
                                &attempt.name,
                            )?)
                        }
                    };
                    let hash = match &pins {
                        Pins::File(p) => Some(p.digest(&attempt.job, &|| parent.is_stopped())?),
                        Pins::Directory(_) => None,
                    };
                    pins.verify(self, false)?;
                    let source = pins.source(hash);
                    source
                        .validate(parent.root())
                        .map_err(|_| Error::EditRecoveryUnavailable)?;
                    attempt.local = Some(pins);
                    attempt.parent = Some(parent.clone());
                    Ok(VaultChildCreateStep::Task(attempt.task(
                        Phase::Prepare,
                        Operation::Prepare { parent, source },
                    )))
                }
                ReplyKind::Prepared(result) => {
                    let prepared = result.map_err(|_| Error::EditRecoveryUnavailable)?;
                    prepared
                        .parent
                        .check()
                        .map_err(|_| Error::EditRecoveryUnavailable)?;
                    if !attempt
                        .parent
                        .as_ref()
                        .is_some_and(|p| Arc::ptr_eq(p, &prepared.parent))
                    {
                        return Err(Error::ConnectionStateInvalid);
                    }
                    let pins = attempt
                        .local
                        .as_ref()
                        .ok_or(Error::ConnectionStateInvalid)?;
                    pins.verify(self, false)?;
                    if pins.source(prepared.source.plaintext_sha256) != prepared.source {
                        return Err(Error::ConfiguredRootChanged);
                    }
                    let pending_parent = matches!(&prepared.target, Target::Cached(_))
                        && prepared
                            .parent
                            .metadata()
                            .id
                            .starts_with("raiun-pending-directory:");
                    // Publication may have happened even if any following local
                    // capture/CAS fails. Never drop original custody on error.
                    attempt.published = true;
                    let mut verify = || {
                        pins.verify(self, false)
                            .map_err(|_| BackendError::Unavailable)
                    };
                    let record = if pending_parent {
                        let descriptor = prepared
                            .parent
                            .cached_descriptor(
                                prepared.source,
                                prepared.target.encoded(),
                                prepared.target.integrity(),
                            )
                            .map_err(|_| Error::EditRecoveryUnavailable)?;
                        Record::Cached(match pins {
                            Pins::File(p) => p.with_reader(
                                &attempt.job,
                                &|| prepared.parent.is_stopped(),
                                |reader| {
                                    prepared
                                        .parent
                                        .prepare_cached_record(
                                            &descriptor,
                                            Some(reader),
                                            &mut verify,
                                        )
                                        .map_err(|_| Error::EditRecoveryUnavailable)
                                },
                            )?,
                            Pins::Directory(_) => prepared
                                .parent
                                .prepare_cached_record(&descriptor, None, &mut verify)
                                .map_err(|_| Error::EditRecoveryUnavailable)?,
                        })
                    } else {
                        let descriptor = prepared
                            .parent
                            .descriptor(
                                prepared.source,
                                prepared.target.encoded(),
                                prepared.target.integrity(),
                            )
                            .map_err(|_| Error::EditRecoveryUnavailable)?;
                        Record::Online(match pins {
                            Pins::File(p) => p.with_reader(
                                &attempt.job,
                                &|| prepared.parent.is_stopped(),
                                |reader| {
                                    prepared
                                        .parent
                                        .prepare_record(&descriptor, Some(reader), &mut verify)
                                        .map_err(|_| Error::EditRecoveryUnavailable)
                                },
                            )?,
                            Pins::Directory(_) => prepared
                                .parent
                                .prepare_record(&descriptor, None, &mut verify)
                                .map_err(|_| Error::EditRecoveryUnavailable)?,
                        })
                    };
                    let proof = pins.proof()?;
                    attempt.check(self)?;
                    if !attempt.ticket.claim_dispatch() {
                        return Err(Error::EditRecoveryUnavailable);
                    }
                    let dispatch = attempt.ticket.dispatch_probe();
                    Ok(VaultChildCreateStep::Task(attempt.task(
                        Phase::Send,
                        Operation::Send {
                            parent: prepared.parent,
                            record,
                            proof,
                            target: prepared.target,
                            dispatch,
                        },
                    )))
                }
                ReplyKind::Sent(result) => {
                    let sent = result.map_err(|_| Error::EditRecoveryUnavailable)?;
                    sent.parent
                        .check()
                        .map_err(|_| Error::EditRecoveryUnavailable)?;
                    if !attempt
                        .parent
                        .as_ref()
                        .is_some_and(|p| Arc::ptr_eq(p, &sent.parent))
                    {
                        return Err(Error::ConnectionStateInvalid);
                    }
                    let local = attempt
                        .local
                        .as_mut()
                        .ok_or(Error::ConnectionStateInvalid)?;
                    local.verify(self, false)?;
                    let source = sent.record.source();
                    let root = sent.record.root();
                    let parent_identity = sent.record.parent_identity();
                    if local.source(source.plaintext_sha256) != *source {
                        return Err(Error::ConfiguredRootChanged);
                    }
                    let stop = || sent.parent.is_stopped();
                    let cancel = crate::vault_custody::VaultUploadCancellation {
                        generation: sent.parent.generation(),
                        expected: sent.parent.authorization().agent_generation,
                        cancelled: &stop,
                    };
                    match (&sent.proof, local) {
                        (Verified::Cached(receipt), Pins::File(pins)) => {
                            let vault = sent.parent.vault().backend();
                            vault.publish_cached_child(receipt, &cancel, |identity| {
                                if stop() {
                                    return Err(Error::EditRecoveryUnavailable);
                                }
                                let cleanup = self
                                    .state
                                    .writable_cleanup
                                    .lock()
                                    .map_err(|_| Error::EditRecoveryUnavailable)?
                                    .reserve(identity)
                                    .map_err(|_| Error::EditRecoveryUnavailable)?;
                                pins.convert_queued(
                                    self,
                                    identity,
                                    || !stop() && attempt.ticket.claim_completion(),
                                    false,
                                )?;
                                pins.verify(self, true)?;
                                if stop() {
                                    return Err(Error::EditRecoveryUnavailable);
                                }
                                let sha = receipt
                                    .source_sha256()
                                    .ok_or(Error::EditRecoveryUnavailable)?;
                                sent.record
                                    .record_local_queued_native(
                                        receipt,
                                        identity,
                                        pins.file().file_index,
                                        pins.usn(),
                                    )
                                    .map_err(|_| Error::EditRecoveryUnavailable)?;
                                self.state
                                    .writable_cleanup
                                    .lock()
                                    .map_err(|_| Error::EditRecoveryUnavailable)?
                                    .publish(
                                        cleanup,
                                        WritableCleanupReceipt {
                                            dispatch: vault.binding().capture_dispatch_stamp(),
                                            root,
                                            identity,
                                            file: pins.file(),
                                            components: source.components.clone(),
                                            length: source.plaintext_len,
                                            sha256: sha,
                                            clean_hydration: false,
                                            original: receipt.entry().cloned(),
                                        },
                                    )
                                    .map_err(|_| Error::EditRecoveryUnavailable)?;
                                self.state
                                    .hydrated_files
                                    .lock()
                                    .map_err(|_| Error::EditRecoveryUnavailable)?
                                    .record(
                                        identity,
                                        pins.file().file_index,
                                        source.plaintext_len,
                                        source.components.clone(),
                                    )
                                    .map_err(|_| Error::EditRecoveryUnavailable)?;
                                Ok(())
                            })?;
                        }
                        (Verified::Cached(receipt), Pins::Directory(pins)) => {
                            sent.parent.vault().backend().publish_cached_child(
                                receipt,
                                &cancel,
                                |identity| {
                                    if stop() || !attempt.ticket.claim_completion() {
                                        return Err(Error::EditRecoveryUnavailable);
                                    }
                                    pins.convert(self, identity)?;
                                    pins.verify(self, true)?;
                                    sent.record
                                        .record_local_queued_native(
                                            receipt,
                                            identity,
                                            pins.file().file_index,
                                            pins.usn(),
                                        )
                                        .map_err(|_| Error::EditRecoveryUnavailable)
                                },
                            )?;
                        }
                        (Verified::File(proof), Pins::File(pins)) => {
                            if Some(proof.plaintext_sha256()) != source.plaintext_sha256 {
                                return Err(Error::EditRecoveryUnavailable);
                            }
                            let vault = sent.parent.vault().backend();
                            let readonly = !vault.existing_file_saves_active();
                            vault.publish_created_file(
                                proof,
                                parent_identity,
                                &cancel,
                                |identity| {
                                    if stop() {
                                        return Err(Error::EditRecoveryUnavailable);
                                    }
                                    let intent = crate::vault_custody::VaultHydrationIntent {
                                        root,
                                        identity,
                                        file_index: source.file,
                                        length: source.plaintext_len,
                                        components: source.components.clone(),
                                    };
                                    vault
                                        .persist_child_create_hydration(&intent)
                                        .map_err(|_| Error::EditRecoveryUnavailable)?;
                                    self.state
                                        .hydrated_files
                                        .lock()
                                        .map_err(|_| Error::EditRecoveryUnavailable)?
                                        .record(
                                            identity,
                                            intent.file_index,
                                            intent.length,
                                            intent.components.clone(),
                                        )
                                        .map_err(|_| Error::EditRecoveryUnavailable)?;
                                    let cleanup = self
                                        .state
                                        .writable_cleanup
                                        .lock()
                                        .map_err(|_| Error::EditRecoveryUnavailable)?
                                        .reserve(identity)
                                        .map_err(|_| Error::EditRecoveryUnavailable)?;
                                    pins.convert(
                                        self,
                                        identity,
                                        || !stop() && attempt.ticket.claim_completion(),
                                        readonly,
                                    )?;
                                    pins.verify(self, true)?;
                                    if stop() {
                                        return Err(Error::EditRecoveryUnavailable);
                                    }
                                    let mut original = proof.entry().clone();
                                    original.writable = false;
                                    self.state
                                        .writable_cleanup
                                        .lock()
                                        .map_err(|_| Error::EditRecoveryUnavailable)?
                                        .publish(
                                            cleanup,
                                            WritableCleanupReceipt {
                                                dispatch: vault.binding().capture_dispatch_stamp(),
                                                root,
                                                identity,
                                                file: pins.file(),
                                                components: source.components.clone(),
                                                length: source.plaintext_len,
                                                sha256: proof.plaintext_sha256(),
                                                clean_hydration: false,
                                                original: Some(original),
                                            },
                                        )
                                        .map_err(|_| Error::EditRecoveryUnavailable)?;
                                    sent.record
                                        .record_native_completed(identity)
                                        .map_err(|_| Error::EditRecoveryUnavailable)
                                },
                            )?;
                        }
                        (Verified::Directory(proof), Pins::Directory(pins)) => {
                            sent.parent.vault().backend().publish_created_directory(
                                proof,
                                parent_identity,
                                &cancel,
                                |identity| {
                                    if stop() || !attempt.ticket.claim_completion() {
                                        return Err(Error::EditRecoveryUnavailable);
                                    }
                                    pins.convert(self, identity)?;
                                    pins.verify(self, true)?;
                                    if stop() {
                                        return Err(Error::EditRecoveryUnavailable);
                                    }
                                    sent.record
                                        .record_native_completed(identity)
                                        .map_err(|_| Error::EditRecoveryUnavailable)
                                },
                            )?;
                        }
                        _ => return Err(Error::ConnectionStateInvalid),
                    }
                    completed = true;
                    Ok(VaultChildCreateStep::Completed)
                }
            }
        })();
        // A completed pre-admission metadata probe has no native or durable
        // custody to retain. This refusal does not authorize a replay; future
        // separately observed creates may still obtain a fresh attempt.
        let early_refusal = result.is_err()
            && attempt.local.is_none()
            && !attempt.published
            && attempt.done.load(Ordering::Acquire);
        if !completed && !early_refusal {
            owner.attempt = Some(attempt);
        }
        result
    }
    pub(crate) fn close_vault_child_create(&self) -> bool {
        let Ok(mut owner) = self.vault_child_owner.try_borrow_mut() else {
            return false;
        };
        owner.closed = true;
        if let Some(attempt) = owner.attempt.as_ref() {
            attempt.job.cancel();
            if !attempt.done.load(Ordering::Acquire) || attempt.published || attempt.local.is_some()
            {
                return false;
            }
        }
        owner.attempt.take();
        true
    }
}

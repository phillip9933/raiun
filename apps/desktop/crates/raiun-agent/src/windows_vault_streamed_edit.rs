//! Vault-bound adapter over the unchanged protected streamed snapshot codec.
//! Serialized epochs are history only; this module cannot unlock or upload.
use super::{
    vault_custody::{CaptureRef, Scope},
    vault_edit_capture::{self as legacy, Baseline, EncodedFrameRef},
};
use raiun_cloudfiles_windows::{
    EditRecordProtector, JournalError, LocalFileIdentity, RemoteEditBaseline,
    streamed_snapshot::SnapshotBinding,
    streamed_store::{CaptureReservation, SnapshotStore, StorePolicy, VerifiedPinnedSnapshot},
};
use raiun_control_windows::{DpapiSessionStore, PinnedDirectory, PrivateDirectory};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{ffi::OsStr, io::Read, sync::Arc};
use zeroize::Zeroizing;

pub(super) const MAX_BODY_BYTES: u64 = 1 << 30;
const MAGIC: &[u8] = b"RAIUN-VAULT-STREAMED-EDIT\0\x01";
const DOMAIN: &[u8] = b"raiun/vault-streamed-existing-edit/v1\0";
const MAX_DESCRIPTOR: usize = 128 * 1024;
type Result<T> = std::result::Result<T, String>;
fn refused() -> String {
    "Protected streamed vault edit is unavailable or changed".into()
}
fn policy() -> StorePolicy {
    StorePolicy {
        max_content_bytes: MAX_BODY_BYTES,
        max_state_bytes: 4 << 30,
        max_entries: 4096,
        max_metadata_bytes_per_scan: 64 << 20,
    }
}

// The stable full vault scope is included in EVERY chunk/manifest/catalog AAD.
// This storage-only namespace is not registered with ordinary recovery/replay.
struct VaultProtector {
    inner: raiun_cloudfiles_windows::DpapiEditRecordProtector,
    scope: Zeroizing<Vec<u8>>,
}
impl VaultProtector {
    fn aad(&self, aad: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(DOMAIN.to_vec());
        out.extend_from_slice(&(self.scope.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.scope);
        out.extend_from_slice(aad);
        out
    }
}
impl EditRecordProtector for VaultProtector {
    fn seal(&self, aad: &[u8], plain: &[u8]) -> std::result::Result<Vec<u8>, JournalError> {
        self.inner.seal(&self.aad(aad), plain)
    }
    fn open(&self, aad: &[u8], sealed: &[u8]) -> std::result::Result<Vec<u8>, JournalError> {
        self.inner.open(&self.aad(aad), sealed)
    }
}
fn store(scope: &Scope, create: bool) -> Result<Arc<SnapshotStore>> {
    let binding = scope.authenticated_store_binding().map_err(|_| refused())?;
    let storage = DpapiSessionStore::current_user().map_err(|_| refused())?;
    let parent =
        PinnedDirectory::open(storage.local_edit_state_directory()).map_err(|_| refused())?;
    let name = format!("vault-streamed-existing-v1-{:x}", Sha256::digest(&*binding));
    let private = Arc::new(
        if create {
            PrivateDirectory::create_or_open_under(&parent, OsStr::new(&name))
        } else {
            PrivateDirectory::open_under(&parent, OsStr::new(&name))
        }
        .map_err(|_| refused())?,
    );
    let protector = Arc::new(VaultProtector {
        inner: raiun_cloudfiles_windows::DpapiEditRecordProtector::from_existing_private_directory(
            private.clone(),
        )
        .map_err(|_| refused())?,
        scope: binding,
    });
    let scope = scope.streamed_storage_scope().map_err(|_| refused())?;
    if create {
        SnapshotStore::create_or_open(private, scope, protector, policy())
    } else {
        SnapshotStore::open_existing(private, scope, protector, policy())
    }
    .map_err(|_| refused())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Descriptor {
    version: u32,
    scope: Scope,
    capture_id: String,
    baseline: Baseline,
    snapshot: SnapshotBinding,
    plaintext_sha256: [u8; 32],
}
impl Descriptor {
    pub(super) fn scope(&self) -> &Scope {
        &self.scope
    }
    pub(super) fn id(&self) -> &str {
        &self.capture_id
    }
    pub(super) fn baseline(&self) -> &Baseline {
        &self.baseline
    }
    pub(super) fn len(&self) -> u64 {
        self.snapshot.content_len
    }
    pub(super) fn sha256(&self) -> [u8; 32] {
        self.plaintext_sha256
    }
    fn validate(&self) -> Result<()> {
        legacy::CaptureId::new(&self.capture_id).map_err(|_| refused())?;
        let baseline = &self.baseline;
        Baseline::new(
            baseline.opaque_file(),
            baseline.strong_etag(),
            baseline.unlock_epoch(),
            baseline.token_generation(),
            baseline.native_volume(),
            baseline.native_file(),
        )
        .map_err(|_| refused())?;
        if self.version != 1
            || self.capture_id
                != capture_id(
                    &self.scope,
                    &self.baseline,
                    &self
                        .snapshot
                        .relative_path
                        .split('/')
                        .map(str::to_owned)
                        .collect::<Vec<_>>(),
                    self.snapshot
                        .remote
                        .as_ref()
                        .ok_or_else(refused)?
                        .resource_id
                        .as_str(),
                    self.snapshot.remote.as_ref().ok_or_else(refused)?.byte_len,
                    self.len(),
                    self.sha256(),
                )?
            || self.snapshot.scope != self.scope.streamed_storage_scope().map_err(|_| refused())?
            || self.snapshot.generation != baseline.token_generation()
            || self.snapshot.local_file.volume_serial != baseline.native_volume()
            || self.snapshot.local_file.file_index != baseline.native_file()
            || self.snapshot.content_len > MAX_BODY_BYTES
            || self.plaintext_sha256 == [0; 32]
            || self
                .snapshot
                .remote
                .as_ref()
                .is_none_or(|r| r.etag != baseline.strong_etag())
        {
            return Err(refused());
        }
        Ok(())
    }
    pub(super) fn binding(&self) -> Result<Zeroizing<Vec<u8>>> {
        metadata_binding(&self.scope, &self.capture_id)
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) fn capture_id(
    scope: &Scope,
    baseline: &Baseline,
    components: &[String],
    remote_id: &str,
    old_len: u64,
    len: u64,
    sha: [u8; 32],
) -> Result<String> {
    let raw = Zeroizing::new(
        serde_json::to_vec(&(scope, baseline, components, remote_id, old_len, len, sha))
            .map_err(|_| refused())?,
    );
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(&*raw);
    Ok(format!("streamed_{:x}", hash.finalize()))
}
pub(super) fn metadata_binding(scope: &Scope, id: &str) -> Result<Zeroizing<Vec<u8>>> {
    legacy::CaptureId::new(id).map_err(|_| refused())?;
    let scope = scope.authenticated_store_binding().map_err(|_| refused())?;
    let mut out = Zeroizing::new(DOMAIN.to_vec());
    out.extend_from_slice(&(scope.len() as u64).to_le_bytes());
    out.extend_from_slice(&scope);
    out.extend_from_slice(id.as_bytes());
    Ok(out)
}
fn encode(descriptor: &Descriptor) -> Result<Zeroizing<Vec<u8>>> {
    descriptor.validate()?;
    let mut raw = Zeroizing::new(MAGIC.to_vec());
    serde_json::to_writer(&mut *raw, descriptor).map_err(|_| refused())?;
    if raw.len() > MAX_DESCRIPTOR {
        return Err(refused());
    }
    Ok(raw)
}
fn decode(raw: &[u8], scope: &Scope, reference: &CaptureRef) -> Result<Descriptor> {
    if !reference.is_streamed()
        || raw.len() > MAX_DESCRIPTOR
        || !raw.starts_with(MAGIC)
        || EncodedFrameRef::for_streamed_descriptor(raw).map_err(|_| refused())?
            != reference.frame()
    {
        return Err(refused());
    }
    let descriptor: Descriptor =
        serde_json::from_slice(&raw[MAGIC.len()..]).map_err(|_| refused())?;
    descriptor.validate()?;
    if descriptor.scope != *scope
        || descriptor.id() != reference.id()
        || descriptor.baseline.opaque_file() != reference.entry().opaque()
        || descriptor.baseline.strong_etag() != reference.entry().etag()
        || descriptor.snapshot.remote.as_ref().is_none_or(|r| {
            r.resource_id != reference.entry().remote_id()
                || r.byte_len != reference.entry().length()
        })
    {
        return Err(refused());
    }
    Ok(descriptor)
}

pub(super) fn validate_descriptor(raw: &[u8], scope: &Scope, reference: &CaptureRef) -> Result<()> {
    decode(raw, scope, reference).map(|_| ())
}
pub(super) struct PreparedStreamedCapture {
    descriptor: Descriptor,
    raw: Zeroizing<Vec<u8>>,
    reservation: CaptureReservation,
}
impl PreparedStreamedCapture {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        scope: &Scope,
        baseline: Baseline,
        components: &[String],
        remote_id: &str,
        old_len: u64,
        len: u64,
        sha: [u8; 32],
    ) -> Result<Self> {
        if len > MAX_BODY_BYTES || components.is_empty() || components.len() > 256 {
            return Err(refused());
        }
        let store = store(scope, true)?;
        let snapshot = SnapshotBinding {
            record_id: String::new(),
            scope: scope.streamed_storage_scope().map_err(|_| refused())?,
            generation: baseline.token_generation(),
            local_file: LocalFileIdentity {
                volume_serial: baseline.native_volume(),
                file_index: baseline.native_file(),
            },
            relative_path: components.join("/"),
            remote: Some(RemoteEditBaseline {
                resource_id: remote_id.into(),
                etag: baseline.strong_etag().into(),
                byte_len: old_len,
            }),
            content_len: len,
        };
        let reservation = store.try_begin_capture(snapshot).map_err(|_| refused())?;
        let descriptor = Descriptor {
            version: 1,
            scope: scope.clone(),
            capture_id: capture_id(scope, &baseline, components, remote_id, old_len, len, sha)?,
            baseline,
            snapshot: reservation.binding().clone(),
            plaintext_sha256: sha,
        };
        let raw = encode(&descriptor)?;
        Ok(Self {
            descriptor,
            raw,
            reservation,
        })
    }
    pub(super) fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    pub(super) fn frame(&self) -> EncodedFrameRef {
        EncodedFrameRef::for_streamed_descriptor(&self.raw).expect("validated bounded descriptor")
    }
    pub(super) fn raw(&self) -> &[u8] {
        &self.raw
    }
    pub(super) fn commit(
        self,
        source: &mut dyn Read,
        verify_source: &mut dyn FnMut() -> std::result::Result<
            (),
            raiun_cloudfiles_windows::BackendError,
        >,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<()> {
        let stage = self
            .reservation
            .capture(source, &mut || cancelled())
            .map_err(|_| refused())?;
        verify_source().map_err(|_| refused())?;
        let committed = stage
            .verify_and_commit(&mut || cancelled())
            .map_err(|_| refused())?;
        if committed.manifest().binding() != &self.descriptor.snapshot
            || committed.manifest().content_sha256() != &self.descriptor.plaintext_sha256
        {
            return Err(refused());
        }
        Ok(())
    }
}

pub(super) struct AuthenticatedStreamedCapture {
    descriptor: Descriptor,
    frame: EncodedFrameRef,
    body: Option<VerifiedPinnedSnapshot>,
}
impl AuthenticatedStreamedCapture {
    pub(super) fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    pub(super) fn frame(&self) -> EncodedFrameRef {
        self.frame
    }
    pub(super) fn take_reader(
        &mut self,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Box<dyn Read + Send>> {
        let reader = self
            .body
            .take()
            .ok_or_else(refused)?
            .into_reader(cancelled)
            .map_err(|_| refused())?;
        Ok(Box::new(reader))
    }
}
pub(super) fn reopen_with_cancel(
    raw: &[u8],
    scope: &Scope,
    reference: &CaptureRef,
    cancelled: &dyn Fn() -> bool,
) -> Result<AuthenticatedStreamedCapture> {
    let descriptor = decode(raw, scope, reference)?;
    let pinned = store(scope, false)?
        .open_verified(&descriptor.snapshot.record_id, &mut || cancelled())
        .map_err(|_| refused())?;
    if pinned.manifest().binding() != &descriptor.snapshot
        || pinned.local_check().content_sha256() != &descriptor.plaintext_sha256
        || pinned.local_check().content_len() != descriptor.len()
    {
        return Err(refused());
    }
    Ok(AuthenticatedStreamedCapture {
        descriptor,
        frame: reference.frame(),
        body: Some(pinned),
    })
}

pub(super) enum RetainedBody {
    Legacy(legacy::RetainedEdit),
    Streamed(AuthenticatedStreamedCapture),
}
impl RetainedBody {
    pub(super) fn is_streamed(&self) -> bool {
        matches!(self, Self::Streamed(_))
    }
    pub(super) fn len(&self) -> u64 {
        match self {
            Self::Legacy(v) => v.bytes_for_recovery().len() as u64,
            Self::Streamed(v) => v.descriptor.len(),
        }
    }
    pub(super) fn sha256(&self) -> [u8; 32] {
        match self {
            Self::Legacy(v) => Sha256::digest(v.bytes_for_recovery()).into(),
            Self::Streamed(v) => v.descriptor.sha256(),
        }
    }
    pub(super) fn legacy(&self) -> Option<&legacy::RetainedEdit> {
        match self {
            Self::Legacy(v) => Some(v),
            _ => None,
        }
    }
    pub(super) fn streamed_reader(
        &mut self,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Box<dyn Read + Send>> {
        match self {
            Self::Streamed(v) => v.take_reader(cancelled),
            _ => Err(refused()),
        }
    }
    pub(super) fn streamed(&self) -> Option<&AuthenticatedStreamedCapture> {
        match self {
            Self::Streamed(v) => Some(v),
            _ => None,
        }
    }
}

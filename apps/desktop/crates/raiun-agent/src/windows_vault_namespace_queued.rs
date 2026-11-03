//! Persisted local journal facts. These values never prove remote sync, grant
//! dispatch, restore an epoch or qualify native cleanup.
use raiun_cloudfiles_windows::{
    BackendError, VaultCachedNamespaceOperation as Operation, VaultCachedNamespaceQueued,
};
use raiun_core::backend::RemoteEntry;
use serde::{Deserialize, Serialize};
fn no() -> BackendError {
    BackendError::Unavailable
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Native {
    pub identity: [u8; 16],
    pub file: u64,
    pub usn: i64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Queued {
    pub operation: Operation,
    pub write_id: String,
    pub revision: u64,
    pub original: Option<RemoteEntry>,
    pub parent: RemoteEntry,
    pub entry: Option<RemoteEntry>,
    pub source_sha256: Option<[u8; 32]>,
    pub plaintext_len: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native: Option<Native>,
}
impl Queued {
    pub fn from(receipt: &VaultCachedNamespaceQueued) -> Result<Self, BackendError> {
        let q = Self {
            operation: receipt.operation(),
            write_id: receipt.write_id().into(),
            revision: receipt.revision(),
            original: receipt.original().cloned(),
            parent: receipt.parent().clone(),
            entry: receipt.entry().cloned(),
            source_sha256: receipt.source_sha256(),
            plaintext_len: receipt.plaintext_len(),
            native: None,
        };
        q.validate()?;
        Ok(q)
    }
    pub fn validate(&self) -> Result<(), BackendError> {
        let bounded =
            |s: &str, n: usize| !s.is_empty() && s.len() <= n && !s.chars().any(char::is_control);
        let entry = |e: &RemoteEntry| {
            bounded(&e.id, 4096)
                && bounded(&e.etag, 4096)
                && e.path.len() <= 32000
                && raiun_core::validate_remote_path(&e.path).is_ok()
                && (!e.directory || e.size == 0)
        };
        if !bounded(&self.write_id, 512)
            || self.revision == 0
            || self.plaintext_len > 1 << 30
            || !self.parent.directory
            || !entry(&self.parent)
            || self.source_sha256 == Some([0; 32])
            || self
                .native
                .as_ref()
                .is_some_and(|n| n.identity == [0; 16] || n.file == 0 || n.usn <= 0)
        {
            return Err(no());
        }
        if let Some(original) = &self.original {
            if !entry(original) {
                return Err(no());
            }
        }
        let delete = self.operation == Operation::DeleteFile;
        if delete != self.entry.is_none() {
            return Err(no());
        }
        if let Some(e) = &self.entry {
            if !entry(e)
                || e.path == "/"
                || e.etag != format!("raiun-pending-v1:{}:{}", self.write_id, self.revision)
                || e.size != self.plaintext_len
            {
                return Err(no());
            }
            match self.operation {
                Operation::CreateFile => {
                    if e.directory
                        || e.id != format!("raiun-pending-create:{}", self.write_id)
                        || self.original.is_some()
                        || self.source_sha256.is_none()
                    {
                        return Err(no());
                    }
                }
                Operation::CreateDirectory => {
                    if !e.directory
                        || e.id != format!("raiun-pending-directory:{}", self.write_id)
                        || self.original.is_some()
                        || self.source_sha256.is_some()
                        || self.plaintext_len != 0
                    {
                        return Err(no());
                    }
                }
                Operation::RenameFile => {
                    if e.directory
                        || self
                            .original
                            .as_ref()
                            .is_none_or(|o| o.directory || o.id != e.id || o.size != e.size)
                    {
                        return Err(no());
                    }
                }
                Operation::RetargetNeverAttemptedDirectory => {
                    if !e.directory
                        || !e.id.starts_with("raiun-pending-directory:")
                        || self
                            .original
                            .as_ref()
                            .is_none_or(|o| !o.directory || o.id != e.id)
                        || self.plaintext_len != 0
                    {
                        return Err(no());
                    }
                }
                Operation::DeleteFile => return Err(no()),
            }
        } else if self
            .original
            .as_ref()
            .is_none_or(|e| e.directory || e.size != self.plaintext_len)
        {
            return Err(no());
        }
        Ok(())
    }
    pub fn matches_receipt(&self, r: &VaultCachedNamespaceQueued) -> Result<bool, BackendError> {
        let mut q = self.clone();
        q.native = None;
        Ok(q == Self::from(r)?)
    }
    pub fn record_native(
        &mut self,
        identity: [u8; 16],
        file: u64,
        usn: i64,
    ) -> Result<(), BackendError> {
        if self.native.is_some() || identity == [0; 16] || file == 0 || usn <= 0 {
            return Err(no());
        }
        self.native = Some(Native {
            identity,
            file,
            usn,
        });
        self.validate()
    }
}
#[derive(Clone)]
pub(super) struct PendingFacts {
    pub operation: Operation,
    pub write_id: String,
    pub revision: u64,
    pub original: Option<RemoteEntry>,
    pub parent: RemoteEntry,
    pub entry: Option<RemoteEntry>,
    pub identity: [u8; 16],
    pub file: u64,
    pub usn: i64,
    pub components: Vec<String>,
    pub plaintext_len: u64,
    pub source_sha256: Option<[u8; 32]>,
}
impl Queued {
    pub fn pending_facts(&self, components: Vec<String>) -> Result<PendingFacts, BackendError> {
        self.validate()?;
        let n = self.native.as_ref().ok_or_else(no)?;
        Ok(PendingFacts {
            operation: self.operation,
            write_id: self.write_id.clone(),
            revision: self.revision,
            original: self.original.clone(),
            parent: self.parent.clone(),
            entry: self.entry.clone(),
            identity: n.identity,
            file: n.file,
            usn: n.usn,
            components,
            plaintext_len: self.plaintext_len,
            source_sha256: self.source_sha256,
        })
    }
}

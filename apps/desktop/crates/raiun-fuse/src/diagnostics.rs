//! Bounded, in-memory diagnostics for one live FUSE mount.

use fuser::Errno;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const RECENT_FAILURE_LIMIT: usize = 32;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Lookup,
    Getattr,
    Opendir,
    Readdir,
    Open,
    Write,
    Flush,
    Fsync,
    Release,
    Mkdir,
    Unlink,
    Rmdir,
    Rename,
    Create,
    Setattr,
}

impl Operation {
    fn critical(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::Write
                | Self::Flush
                | Self::Fsync
                | Self::Release
                | Self::Create
                | Self::Rename
        )
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct OperationMetrics {
    pub count: u64,
    pub total_elapsed_ms: u64,
    pub max_elapsed_ms: u64,
    pub errors_by_errno: BTreeMap<i32, u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RecentFailure {
    pub stage: Operation,
    pub errno: i32,
    pub inode: u64,
    pub timestamp_unix_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_errno: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_sha256: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DiagnosticsSnapshot {
    pub operations: BTreeMap<String, OperationMetrics>,
    pub recent_failures: Vec<RecentFailure>,
    pub unsupported_metadata_rejections: u64,
    pub lookup_absence_memo_hits: u64,
    pub empty_directory_memo_hits: u64,
    pub lookup_point_hits: u64,
}

#[derive(Default)]
struct State {
    snapshot: DiagnosticsSnapshot,
}

/// Statistics state is isolated to a filesystem instance and never persisted.
#[derive(Default)]
pub struct MountDiagnostics {
    state: Mutex<State>,
}

impl MountDiagnostics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn snapshot(&self) -> DiagnosticsSnapshot {
        self.state
            .lock()
            .map(|state| state.snapshot.clone())
            .unwrap_or_default()
    }

    pub fn operation(self: &Arc<Self>, operation: Operation, inode: u64) -> OperationGuard {
        OperationGuard {
            diagnostics: Arc::clone(self),
            operation,
            inode,
            started: Instant::now(),
        }
    }

    /// Count a provider metadata rejection outside the recent critical-failure ring.
    pub fn unsupported_metadata_rejection(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.snapshot.unsupported_metadata_rejections = state
                .snapshot
                .unsupported_metadata_rejections
                .saturating_add(1);
        }
    }

    pub fn lookup_absence_memo_hit(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.snapshot.lookup_absence_memo_hits =
                state.snapshot.lookup_absence_memo_hits.saturating_add(1);
        }
    }

    pub fn empty_directory_memo_hit(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.snapshot.empty_directory_memo_hits =
                state.snapshot.empty_directory_memo_hits.saturating_add(1);
        }
    }

    pub fn lookup_point_hit(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.snapshot.lookup_point_hits = state.snapshot.lookup_point_hits.saturating_add(1);
        }
    }
}

pub struct OperationGuard {
    diagnostics: Arc<MountDiagnostics>,
    operation: Operation,
    inode: u64,
    started: Instant,
}

impl OperationGuard {
    /// Record the errno while preserving it for the FUSE reply.
    pub fn failure(&self, errno: Errno) -> Errno {
        self.record_failure(errno, None, None, None)
    }

    pub fn cloud_failure(&self, error: &raiun_core::backend::CloudError) -> Errno {
        let errno = super::errno(error);
        let namespace_detail = matches!(
            self.operation,
            Operation::Lookup | Operation::Opendir | Operation::Readdir | Operation::Getattr
        ) && errno != Errno::ENOENT
            && errno != Errno::ENOTDIR;
        let kind = namespace_detail.then(|| format!("{:?}", error.kind).to_ascii_lowercase());
        let message_sha256 =
            namespace_detail.then(|| format!("{:x}", Sha256::digest(error.message.as_bytes())));
        self.record_failure(errno, super::local_io_errno(error), kind, message_sha256)
    }

    fn record_failure(
        &self,
        errno: Errno,
        local_errno: Option<i32>,
        error_kind: Option<String>,
        message_sha256: Option<String>,
    ) -> Errno {
        let errno_number = i32::from(errno);
        if let Ok(mut state) = self.diagnostics.state.lock() {
            let metrics = state
                .snapshot
                .operations
                .entry(format!("{:?}", self.operation).to_ascii_lowercase())
                .or_default();
            let count = metrics.errors_by_errno.entry(errno_number).or_default();
            *count = count.saturating_add(1);
            if self.operation.critical()
                || (matches!(
                    self.operation,
                    Operation::Lookup
                        | Operation::Opendir
                        | Operation::Readdir
                        | Operation::Getattr
                ) && errno != Errno::ENOENT
                    && errno != Errno::ENOTDIR)
            {
                if state.snapshot.recent_failures.len() == RECENT_FAILURE_LIMIT {
                    state.snapshot.recent_failures.remove(0);
                }
                state.snapshot.recent_failures.push(RecentFailure {
                    stage: self.operation,
                    errno: errno_number,
                    local_errno,
                    inode: self.inode,
                    timestamp_unix_ms: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis()
                        .min(u64::MAX as u128) as u64,
                    error_kind,
                    message_sha256,
                });
            }
        }
        errno
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        if let Ok(mut state) = self.diagnostics.state.lock() {
            let metrics = state
                .snapshot
                .operations
                .entry(format!("{:?}", self.operation).to_ascii_lowercase())
                .or_default();
            metrics.count = metrics.count.saturating_add(1);
            metrics.total_elapsed_ms = metrics.total_elapsed_ms.saturating_add(elapsed);
            metrics.max_elapsed_ms = metrics.max_elapsed_ms.max(elapsed);
        }
    }
}

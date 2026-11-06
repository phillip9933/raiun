//! Invocation-local, fixed preparation failure labels. No values from records,
//! requests, server messages or paths enter this trace. It grants no authority.
use crate::BackendError;
use std::sync::atomic::{AtomicU32, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub(crate) enum Category {
    None,
    NotFound,
    Cancelled,
    InvalidRange,
    Unavailable,
    Unauthorized,
    Forbidden,
    Conflict,
    Offline,
    InvalidResponse,
    Unsupported,
    Io,
    Busy,
    Invalid,
    Quota,
    ScanLimit,
    IncompleteEvidence,
    CorruptEvidence,
    PublicationUncertain,
    Snapshot,
    Pending,
    DeadlineElapsed,
}
impl Category {
    fn from_code(code: u16) -> Self {
        const ALL: &[Category] = &[
            Category::None,
            Category::NotFound,
            Category::Cancelled,
            Category::InvalidRange,
            Category::Unavailable,
            Category::Unauthorized,
            Category::Forbidden,
            Category::Conflict,
            Category::Offline,
            Category::InvalidResponse,
            Category::Unsupported,
            Category::Io,
            Category::Busy,
            Category::Invalid,
            Category::Quota,
            Category::ScanLimit,
            Category::IncompleteEvidence,
            Category::CorruptEvidence,
            Category::PublicationUncertain,
            Category::Snapshot,
            Category::Pending,
            Category::DeadlineElapsed,
        ];
        ALL.get(usize::from(code))
            .copied()
            .unwrap_or(Self::Unavailable)
    }
}
macro_rules! fixed_message {
    ($prefix:expr, $stage:literal, $category:literal) => {
        if $prefix == "File" {
            concat!(
                "File creation paused: ",
                $stage,
                " (",
                $category,
                "). Recovery files have been kept."
            )
        } else {
            concat!(
                "Folder creation paused: ",
                $stage,
                " (",
                $category,
                "). Recovery files have been kept."
            )
        }
    };
}
macro_rules! category_message {
    ($prefix:expr, $stage:literal, $category:expr) => {
        match $category {
            Category::None => fixed_message!($prefix, $stage, "unspecified"),
            Category::NotFound => fixed_message!($prefix, $stage, "not found"),
            Category::Cancelled => fixed_message!($prefix, $stage, "cancelled"),
            Category::InvalidRange => fixed_message!($prefix, $stage, "invalid range"),
            Category::Unavailable => fixed_message!($prefix, $stage, "unavailable"),
            Category::Unauthorized => fixed_message!($prefix, $stage, "authorization refused"),
            Category::Forbidden => fixed_message!($prefix, $stage, "permission refused"),
            Category::Conflict => fixed_message!($prefix, $stage, "conflict"),
            Category::Offline => fixed_message!($prefix, $stage, "offline"),
            Category::InvalidResponse => fixed_message!($prefix, $stage, "invalid metadata"),
            Category::Unsupported => fixed_message!($prefix, $stage, "unsupported"),
            Category::Io => fixed_message!($prefix, $stage, "I/O failure"),
            Category::Busy => fixed_message!($prefix, $stage, "busy"),
            Category::Invalid => fixed_message!($prefix, $stage, "invalid evidence"),
            Category::Quota => fixed_message!($prefix, $stage, "quota"),
            Category::ScanLimit => fixed_message!($prefix, $stage, "scan limit"),
            Category::IncompleteEvidence => fixed_message!($prefix, $stage, "incomplete evidence"),
            Category::CorruptEvidence => fixed_message!($prefix, $stage, "corrupt evidence"),
            Category::PublicationUncertain => {
                fixed_message!($prefix, $stage, "publication uncertain")
            }
            Category::Snapshot => fixed_message!($prefix, $stage, "snapshot verification"),
            Category::Pending => fixed_message!($prefix, $stage, "pending recovery"),
            Category::DeadlineElapsed => {
                fixed_message!($prefix, $stage, "original deadline elapsed")
            }
        }
    };
}
macro_rules! stages {
    ($($name:ident => $message:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(u16)]
        pub(crate) enum Stage { $($name),+ }
        impl Stage {
            fn from_code(code: u16) -> Self {
                const ALL: &[Stage] = &[$(Stage::$name),+];
                ALL.get(usize::from(code)).copied().unwrap_or(Self::Unknown)
            }
        }
        impl Failure {
            pub(crate) fn message(&self, prefix: &'static str) -> &'static str {
                match self.stage { $(Stage::$name => category_message!(prefix, $message, self.category)),+ }
            }
        }
    };
}
stages! {
    Unknown => "preparation did not complete",
    Job => "original operation check failed",
    Current => "original account or operation context check failed",
    Catalog => "account-bound catalogue check failed",
    AccountRoot => "verified account root check failed",
    ParentRoute => "managed parent route lookup failed",
    ParentLookup => "managed parent lookup failed",
    ParentOrdinary => "ordinary parent classification failed",
    ParentRootStat => "selected root metadata lookup failed",
    ParentStat => "parent metadata lookup failed",
    RootIdentity => "selected root identity check failed",
    RootKind => "selected root directory check failed",
    RootEncryption => "selected root ordinary-storage check failed",
    RootWritable => "selected root write-permission check failed",
    ParentIdentity => "parent identity check failed",
    ParentKind => "parent directory check failed",
    ParentEncryption => "parent ordinary-storage check failed",
    ParentWritable => "parent write-permission check failed",
    RootParentEtag => "Space-root parent version-tag check failed",
    ParentEtag => "parent version-tag check failed",
    TargetQualification => "target Space qualification failed",
    RecoveryScope => "recovery account and root binding check failed",
    RecoveryContext => "original protected recovery context check failed",
    RecoveryQuotaOpen => "protected recovery quota file is unavailable",
    RecoveryQuotaLock => "protected recovery quota lease is unavailable",
    RecoveryBefore => "protected recovery preparation check failed",
    RecoveryAfter => "protected recovery recheck failed",
    RecoveryStore => "protected intent-store preparation failed",
    RecoveryFinal => "protected root final verification failed",
    NamespaceScan => "namespace recovery verification failed",
    NamespaceValidation => "namespace custody validation failed",
    SnapshotScan => "saved snapshot verification failed",
    ExemptionMatch => "exact original snapshot correspondence check failed",
    LegacyScan => "legacy recovery verification failed",
    NamespacePending => "namespace recovery remains pending",
    SnapshotPending => "other saved-file recovery remains pending",
    LegacyPending => "legacy recovery remains pending",
    QueuedPrepare => "directory preparation is queued",
    QueuedPreflight => "directory cloud preflight is queued",
    QueuedSend => "directory upload dispatch is queued",
    QueuedRefresh => "directory result refresh is queued",
    NativeContext => "directory native context verification did not finish",
    NativeParentPin => "directory parent pinning did not finish",
    DirectoryIntentAdmission => "directory intent and dispatch admission did not finish",
    DirectoryPreflight => "directory cloud preflight did not finish",
    DirectorySend => "directory cloud creation did not finish",
    DirectoryRefresh => "directory result refresh did not finish",
    DirectoryResultPersistence => "directory result persistence did not finish",
    NativeDirectoryPublication => "directory native publication did not finish",
    LocalCompletionPersistence => "directory completion persistence did not finish",
    NativeCreateInspection => "original create native custody inspection failed",
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Failure {
    stage: Stage,
    category: Category,
}
impl Failure {
    #[cfg(windows)]
    pub(crate) fn is_recovery_quota_busy(self) -> bool {
        self.category == Category::Busy
            && matches!(
                self.stage,
                Stage::RecoveryQuotaOpen | Stage::RecoveryQuotaLock
            )
    }
}

/// Wait only for exact pre-capture quota contention, then rerun the original
/// health query with all of its checks. The caller shares one allowance across
/// both health queries and owner deferrals of this original Prepare. This
/// schedules work only; no retained evidence, failed check or pending result
/// becomes authority.
#[cfg(windows)]
pub(crate) fn wait_for_recovery_health<T>(
    job: &crate::StreamedRecoveryJob,
    trace: &Trace,
    wait_budget: &mut Option<crate::CancellationToken>,
    mut operation: impl FnMut() -> Result<T, BackendError>,
) -> Result<T, BackendError> {
    let original_error = match operation() {
        Ok(value) => return Ok(value),
        Err(error) if trace.failure().is_recovery_quota_busy() => error,
        Err(error) => return Err(error),
    };
    let original_failure = trace.failure();
    let quota_error = || {
        trace.enter(original_failure.stage);
        trace.category(original_failure.category);
        original_error
    };
    let budget = wait_budget.get_or_insert_with(|| job.cancellation().bounded_request());
    let stopped = || job.is_stopped() || budget.is_cancelled() || budget.is_expired();
    loop {
        if stopped() {
            return Err(quota_error());
        }
        let Some(remaining) = budget.remaining() else {
            return Err(quota_error());
        };
        std::thread::sleep(remaining.min(std::time::Duration::from_millis(10)));
        if stopped() {
            return Err(quota_error());
        }
        match operation() {
            Ok(value) => {
                if stopped() {
                    return Err(quota_error());
                }
                return Ok(value);
            }
            Err(error) if !trace.failure().is_recovery_quota_busy() => return Err(error),
            Err(_) => (),
        }
    }
}

pub(crate) struct Trace {
    detail: AtomicU32,
}
impl Trace {
    pub(crate) fn new() -> Self {
        Self {
            detail: AtomicU32::new(0),
        }
    }
    pub(crate) fn enter(&self, stage: Stage) {
        self.detail.store((stage as u32) << 16, Ordering::Release);
    }
    /// Preserve a more specific SDK/store category when an outer layer maps
    /// its error to BackendError::Unavailable. Classification may defer fresh
    /// preparation; it never waives a health, custody or currentness check.
    pub(crate) fn category(&self, category: Category) {
        let mut current = self.detail.load(Ordering::Acquire);
        loop {
            if current & 0xffff != 0 {
                return;
            }
            match self.detail.compare_exchange_weak(
                current,
                current | category as u32,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }
    pub(crate) fn backend(&self, error: BackendError) {
        self.category(match error {
            BackendError::NotFound => Category::NotFound,
            BackendError::Cancelled => Category::Cancelled,
            BackendError::InvalidRange => Category::InvalidRange,
            BackendError::Unavailable => Category::Unavailable,
        });
    }
    pub(crate) fn cloud(&self, kind: raiun_core::backend::ErrorKind) {
        use raiun_core::backend::ErrorKind;
        self.category(match kind {
            ErrorKind::Unauthorized => Category::Unauthorized,
            ErrorKind::Forbidden => Category::Forbidden,
            ErrorKind::NotFound => Category::NotFound,
            ErrorKind::Conflict => Category::Conflict,
            ErrorKind::Offline => Category::Offline,
            ErrorKind::InvalidResponse => Category::InvalidResponse,
            ErrorKind::Unsupported => Category::Unsupported,
            ErrorKind::Io => Category::Io,
        });
    }
    #[cfg(any(windows, test))]
    pub(crate) fn store(&self, error: crate::streamed_store::StoreError) {
        use crate::streamed_store::StoreError;
        self.category(match error {
            StoreError::Io => Category::Io,
            StoreError::Busy => Category::Busy,
            StoreError::Invalid => Category::Invalid,
            StoreError::Quota => Category::Quota,
            StoreError::ScanLimit => Category::ScanLimit,
            StoreError::IncompleteEvidence => Category::IncompleteEvidence,
            StoreError::CorruptEvidence => Category::CorruptEvidence,
            StoreError::PublicationUncertain => Category::PublicationUncertain,
            StoreError::Snapshot(_) => Category::Snapshot,
        });
    }
    pub(crate) fn failure(&self) -> Failure {
        let value = self.detail.load(Ordering::Acquire);
        Failure {
            stage: Stage::from_code((value >> 16) as u16),
            category: Category::from_code(value as u16),
        }
    }
    /// Read-only current boundary when the original owner has independently
    /// observed expiry. This reports no elapsed-phase timing or cause.
    #[cfg(windows)]
    pub(crate) fn deadline_message(&self, prefix: &'static str) -> &'static str {
        Failure {
            stage: self.failure().stage,
            category: Category::DeadlineElapsed,
        }
        .message(prefix)
    }
}

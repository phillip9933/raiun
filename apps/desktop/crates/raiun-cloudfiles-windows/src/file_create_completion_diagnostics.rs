//! Original-attempt diagnostic facts only. No paths, identities, revisions,
//! credentials or native-completion authority are retained in this annotation.
use std::sync::atomic::{AtomicU32, Ordering};

macro_rules! stages {
    ($($name:ident => $description:literal),+ $(,)?) => {
        #[derive(Clone, Copy)]
        #[repr(u32)]
        pub(crate) enum Stage { $($name),+ }
        impl Stage {
            fn code(self) -> u32 { self as u32 + 1 }
            fn context(code: u32) -> Option<&'static str> {
                $(if code == Self::$name.code() {
                    return Some(concat!("File creation paused: ", $description,
                        ". Recovery files have been kept."));
                })+
                None
            }
        }
    };
}
stages! {
    OriginalContext => "the original completion owner or context could not be verified",
    Publication => "the verified file identity could not enter local publication",
    SourceReference => "the original protected file handle could not be referenced",
    RootIdentity => "the original drive identity check failed before completion",
    RootRegistration => "the original drive registration check failed before completion",
    SourceSnapshot => "the original file metadata or revision could not be verified before conversion",
    ParentIdentity => "the original file parent identity check failed before conversion",
    SourcePath => "the original file parent identity or path check failed before conversion",
    SourceHashBeforeConvert => "local file bytes could not be verified before conversion",
    SourceSnapshotAfterHash => "the file metadata or revision could not be verified after the pre-conversion hash",
    Convert => "Windows refused conversion of the verified file into a placeholder",
    ConvertedUsn => "Windows returned no positive file revision after conversion",
    PlaceholderIdentity => "the converted placeholder identity could not be verified",
    SourceHashAfterConvert => "local file bytes could not be verified after conversion",
    ConvertedUsnRead => "the converted file revision could not be read",
    ConvertedUsnCompare => "the converted file revision did not match the conversion result",
    ConvertedShape => "the converted file metadata, path or placeholder state did not match",
    CompletionClaim => "the original file completion claim was no longer available",
    SetInSync => "Windows refused the revision-checked in-sync update",
    InSyncShape => "Windows file metadata or in-sync state could not be verified",
    SourceHashAfterSync => "local file bytes could not be verified after the in-sync update",
    InSyncUsnRead => "the in-sync file revision could not be read",
    InSyncUsnCompare => "the in-sync file revision did not match the update result",
    FinalRootIdentity => "the drive identity could not be verified after the in-sync update",
    FinalRootRegistration => "the drive registration could not be verified after the in-sync update",
    FinalCurrent => "the original owner could not be verified after the in-sync update",
    PostPublicationCurrent => "the original recovery context could not be verified after local publication",
    CompletionReport => "the original verified completion report did not match its intent",
    SnapshotLease => "the original protected snapshot could not enter completion recording",
    SnapshotAck => "the original protected snapshot acknowledgement could not be recorded",
    JoinCompletion => "the original file completion record could not be appended",
    CustodyCurrent => "the original recovery context could not be verified during completion recording",
}

pub(crate) struct Trace {
    current: AtomicU32,
    failed: AtomicU32,
}
impl Trace {
    pub(crate) fn new() -> Self {
        Self {
            current: AtomicU32::new(Stage::OriginalContext.code()),
            failed: AtomicU32::new(0),
        }
    }
    pub(crate) fn enter(&self, stage: Stage) {
        self.current.store(stage.code(), Ordering::Release);
    }
    pub(crate) fn fail(&self) {
        self.latch(self.current.load(Ordering::Acquire));
    }
    pub(crate) fn fail_at(&self, stage: Stage) {
        self.latch(stage.code());
    }
    fn latch(&self, code: u32) {
        let _ = self
            .failed
            .compare_exchange(0, code, Ordering::AcqRel, Ordering::Acquire);
    }
    pub(crate) fn failure_context(&self) -> Option<&'static str> {
        Stage::context(self.failed.load(Ordering::Acquire))
    }
}

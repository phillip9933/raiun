//! One owner-thread observer and ordered, volatile routing. Names/counters are
//! metadata only; existing consumers independently admit every mutation.
// A work item consumes at least one already-validated kernel hint. Keep the
// volatile plan bounded by that same full-batch limit rather than refusing a
// valid bulk copy before any independent native create admission can run.
#[cfg(windows)]
const MAX_WORK: usize = raiun_control_windows::directory_notifications::MAX_NOTIFICATION_HINTS;
// The planner is also compiled by existing host-only regressions, where the
// Windows adapter dependency is absent. Production uses the shared limit above.
#[cfg(not(windows))]
const MAX_WORK: usize = 1024;
const MAX_PAIRS: usize = 32;
/// Held until a typed non-admitting directory classifier and native evidence
/// distinguish provider-created placeholders from new ordinary directories.
pub(crate) const DIRECTORY_ROUTING_READY: bool = false;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateKind {
    File,
    Directory,
}
pub(crate) fn matching_create_completion(
    expected: CreateKind,
    flight: u64,
    actual: CreateKind,
    reply: u64,
) -> bool {
    flight != 0 && flight == reply && expected == actual
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    Added,
    Modified,
    Removed,
    Old,
    New,
}
struct Hint<'a> {
    action: Action,
    components: &'a [String],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Work {
    Directory(usize),
    Rename(usize),
}

fn personal(parts: &[String]) -> bool {
    parts.first().map(String::as_str) == Some("Personal") && parts.len() >= 2
}
// Volatile observation planning only. The CF reader independently validates
// every component/path byte and pins the original live root/ancestry.
fn observation_namespace(parts: &[String]) -> bool {
    (1..=256).contains(&parts.len())
        && matches!(
            parts.first().map(String::as_str),
            Some("Personal" | "Spaces")
        )
}
fn rename_file_path(parts: &[String]) -> bool {
    parts.len() <= 256
        && match parts.first().map(String::as_str) {
            Some("Personal") => parts.len() >= 2,
            Some("Spaces") => parts.len() >= 3,
            _ => false,
        }
}
fn create_personal(parts: &[String]) -> bool {
    parts.len() <= 256
        && match parts.first().map(String::as_str) {
            Some("Personal") => parts.len() >= 2,
            Some("Spaces") => parts.len() >= 3,
            _ => false,
        }
}
#[derive(Clone, Copy)]
enum ObservedShape {
    PlainFile,
    PlainDirectory,
    Cloud,
}
#[derive(Debug, Eq, PartialEq)]
enum Selection {
    SkipCloud,
    CreateFile,
    OfferDirectory,
}
/// Physical shape is not ownership, health, continuity or publication proof.
/// Failed/missing observation is None; mutation consumers admit independently.
fn select_observed(
    parts: &[String],
    shape: Option<ObservedShape>,
    directories: bool,
    creates: bool,
) -> Result<Selection, &'static str> {
    if !(if creates {
        observation_namespace(parts)
    } else {
        directories && personal(parts)
    }) {
        return Err("Unsupported observed namespace");
    }
    match shape {
        Some(ObservedShape::Cloud) => Ok(Selection::SkipCloud),
        Some(ObservedShape::PlainFile) if creates && create_personal(parts) => {
            Ok(Selection::CreateFile)
        }
        Some(ObservedShape::PlainDirectory) if directories && personal(parts) => {
            Ok(Selection::OfferDirectory)
        }
        _ => Err("Observed entry needs attention"),
    }
}
/// Separate permissions for the owner-phase route. Legacy diagnostics keep
/// their existing selector; no file/mixed-fixture flag admits directory work.
fn select_create_observed(
    parts: &[String],
    shape: Option<ObservedShape>,
    allow_file: bool,
    allow_directory: bool,
    added: bool,
) -> Result<Selection, &'static str> {
    if !(allow_file || allow_directory) || !observation_namespace(parts) {
        return Err("Unsupported create namespace");
    }
    match shape {
        Some(ObservedShape::Cloud) => Ok(Selection::SkipCloud),
        Some(ObservedShape::PlainFile) if allow_file && create_personal(parts) => {
            Ok(Selection::CreateFile)
        }
        Some(ObservedShape::PlainDirectory)
            if allow_directory && added && create_personal(parts) =>
        {
            Ok(Selection::OfferDirectory)
        }
        _ => Err("Observed entry needs attention"),
    }
}
fn aliases(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(a, b)| a.eq_ignore_ascii_case(b))
}
/// Called only after whole-batch CF pairing validation. No prefix truncation:
/// one ambiguous/unsupported item refuses the plan before any side effect.
/// Keep every planned endpoint, including future cloud-shaped skips, through
/// the whole-batch alias/rename checks; classification happens only afterward.
#[cfg(test)]
fn route(hints: &[Hint<'_>], directories: bool, creates: bool) -> Result<Vec<Work>, &'static str> {
    route_accounted(hints, directories, creates, &[])
}
fn route_accounted(
    hints: &[Hint<'_>],
    directories: bool,
    creates: bool,
    accounted: &[bool],
) -> Result<Vec<Work>, &'static str> {
    if hints.len() > MAX_WORK {
        return Err("Namespace batch limit");
    }
    let mut result = Vec::new();
    let mut endpoints: Vec<&[String]> = Vec::new();
    let mut pair = 0;
    let mut index = 0;
    while index < hints.len() {
        let hint = &hints[index];
        if accounted.get(index).copied().unwrap_or(false) {
            if hint.action == Action::Old {
                if !hints
                    .get(index + 1)
                    .is_some_and(|next| next.action == Action::New)
                    || !accounted.get(index + 1).copied().unwrap_or(false)
                    || pair == MAX_PAIRS
                {
                    return Err("Unpaired completed replacement hint");
                }
                pair += 1;
                index += 1;
            } else if hint.action == Action::New {
                return Err("Unpaired completed replacement hint");
            }
            index += 1;
            continue;
        }
        if hints.iter().enumerate().any(|(i, other)| {
            accounted.get(i).copied().unwrap_or(false) && aliases(hint.components, other.components)
        }) {
            return Err("Ambiguous completed replacement endpoints");
        }

        if creates
            && !observation_namespace(hint.components)
            && matches!(
                hint.action,
                Action::Added | Action::Modified | Action::Removed
            )
        {
            return Err("Unsupported create namespace");
        }
        let mut names = Vec::new();
        let work = match hint.action {
            Action::Old => {
                let next = hints
                    .get(index + 1)
                    .filter(|h| h.action == Action::New)
                    .ok_or("Unpaired namespace notification")?;
                if pair == MAX_PAIRS
                    || !rename_file_path(hint.components)
                    || !rename_file_path(next.components)
                {
                    return Err("Unsupported namespace rename");
                }
                names.push(hint.components);
                names.push(next.components);
                let work = Work::Rename(pair);
                pair += 1;
                index += 1;
                Some(work)
            }
            Action::New => return Err("Unpaired namespace notification"),
            Action::Added | Action::Modified
                if (creates && observation_namespace(hint.components))
                    || (directories
                        && hint.action == Action::Added
                        && personal(hint.components)) =>
            {
                if result.iter().any(|work| matches!(work, Work::Directory(index) if hints[*index].components == hint.components)) { index += 1; continue; }
                names.push(hint.components);
                Some(Work::Directory(index))
            }
            // Removal observations are not cloud-delete or completion authority.
            // Modern create mode keeps them only as whole-batch alias fences.
            Action::Removed if creates => None,
            Action::Removed if directories && personal(hint.components) => {
                return Err("Unsupported namespace removal");
            }
            // File-only mode preserves existing ignore behavior for non-rename
            // notifications. Ignoring an unsupported request proves no health.
            Action::Added | Action::Modified | Action::Removed => None,
        };
        if let Some(work) = work {
            if result.len() == MAX_WORK {
                return Err("Namespace batch limit");
            }
            for name in names {
                if endpoints.iter().any(|old| aliases(old, name))
                    || (creates
                        && hints.iter().enumerate().any(|(i, hint)| {
                            !accounted.get(i).copied().unwrap_or(false)
                                && hint.action == Action::Removed
                                && aliases(hint.components, name)
                        }))
                {
                    return Err("Ambiguous namespace endpoints");
                }
                endpoints.push(name);
            }
            result.push(work);
        }
        index += 1;
    }
    Ok(result)
}

#[derive(Default)]
struct Cursor {
    work: Vec<Work>,
    index: usize,
    assigned: Option<u64>,
    directory_started: bool,
    counter: u64,
    held: bool,
}
impl Cursor {
    fn pending(&self) -> bool {
        self.index < self.work.len()
    }
    fn admit(&mut self, work: Vec<Work>) -> Result<(), &'static str> {
        if work.len() > MAX_WORK {
            return Err("Namespace batch limit");
        }
        if self.held || self.pending() {
            return Err("Namespace cursor unavailable");
        }
        self.work = work;
        self.index = 0;
        self.assigned = None;
        self.directory_started = false;
        Ok(())
    }
    fn front(&self) -> Option<Work> {
        (!self.held)
            .then(|| self.work.get(self.index).copied())
            .flatten()
    }
    fn generation(&mut self) -> Result<u64, &'static str> {
        if self.held || !self.pending() {
            return Err("Namespace cursor unavailable");
        }
        if let Some(value) = self.assigned {
            return Ok(value);
        }
        let next = self
            .counter
            .checked_add(1)
            .filter(|n| *n != 0)
            .ok_or("Namespace generation exhausted")?;
        self.counter = next;
        self.assigned = Some(next);
        Ok(next)
    }
    fn complete(&mut self) -> Result<(), &'static str> {
        if self.held || !self.pending() || self.assigned.is_none() {
            return Err("Namespace cursor unavailable");
        }
        self.index += 1;
        self.assigned = None;
        self.directory_started = false;
        Ok(())
    }
    fn hold(&mut self) {
        self.held = true;
        self.work.clear();
        self.index = 0;
        self.assigned = None;
        self.directory_started = false;
    }
}

#[cfg(windows)]
mod connected {
    use super::super::{
        windows_file_create_producer as create, windows_file_rename_producer as rename,
        windows_namespace_producer as mkdir,
    };
    use super::*;
    use raiun_cloudfiles_windows::{
        ConfiguredRootConnection, ConfiguredRootIdentity, NamespaceEntryKind,
        OpenCloudPlaceholderBackend,
    };
    use raiun_control_windows::directory_notifications::{
        DirectoryAction, NotificationBatch, ObserverPoll, RescanReason,
        directory_rename_hints::{RenameHintBatch, RenameHintReason, pair_move_hints},
    };
    use std::{sync::Arc, time::Duration};

    pub(crate) const HOLD: &str =
        "File namespace sync needs attention. Existing recovery files have been kept.";
    const BATCH_LIMIT: &str =
        "File namespace sync paused: notification batch limit. Recovery files have been kept.";
    const RENAME_LIMIT: &str =
        "File namespace sync paused: rename batch limit. Recovery files have been kept.";
    const OBSERVER_LOSS: &str =
        "File namespace sync paused: notification continuity lost. Recovery files have been kept.";
    const OBSERVER_INVALID: &str =
        "File namespace sync paused: malformed notification batch. Recovery files have been kept.";
    const OBSERVER_STOPPED: &str =
        "File namespace sync paused: observer stopped. Recovery files have been kept.";
    const OBSERVER_UNAVAILABLE: &str =
        "File namespace sync paused: observer unavailable. Recovery files have been kept.";
    const CONTEXT_CHANGED: &str =
        "File namespace sync paused: observer context changed. Recovery files have been kept.";
    const PLAN_PAIRING: &str =
        "File namespace sync paused: incomplete rename plan. Recovery files have been kept.";
    const PLAN_AMBIGUOUS: &str =
        "File namespace sync paused: ambiguous namespace plan. Recovery files have been kept.";
    const PLAN_UNSUPPORTED: &str =
        "File namespace sync paused: unsupported namespace plan. Recovery files have been kept.";
    const PLAN_STATE: &str =
        "File namespace sync paused: planner state unavailable. Recovery files have been kept.";
    const OWNER_HOLD: &str = "File namespace sync paused: native owner preflight needs attention. Recovery files have been kept.";

    // Only fixed, nonsecret reasons cross the existing status boundary. Never
    // format native error values, notification names, paths or server text.
    fn plan_hold(reason: &'static str) -> &'static str {
        match reason {
            "Namespace batch limit" => BATCH_LIMIT,
            "Unpaired completed replacement hint" | "Unpaired namespace notification" => {
                PLAN_PAIRING
            }
            "Ambiguous completed replacement endpoints" | "Ambiguous namespace endpoints" => {
                PLAN_AMBIGUOUS
            }
            "Unsupported create namespace"
            | "Unsupported observed namespace"
            | "Unsupported namespace rename"
            | "Unsupported namespace removal" => PLAN_UNSUPPORTED,
            "Namespace cursor unavailable" | "Namespace generation exhausted" => PLAN_STATE,
            "Observed entry needs attention" => OWNER_HOLD,
            _ => HOLD,
        }
    }
    fn observer_hold(reason: RescanReason) -> &'static str {
        match reason {
            RescanReason::Limit => BATCH_LIMIT,
            RescanReason::EmptyCompletion => OBSERVER_LOSS,
            RescanReason::MalformedBuffer => OBSERVER_INVALID,
            RescanReason::NativeError(_) => OBSERVER_UNAVAILABLE,
            RescanReason::RootChanged => CONTEXT_CHANGED,
            RescanReason::Cancelled => OBSERVER_STOPPED,
        }
    }
    fn pairing_hold(reason: RenameHintReason) -> &'static str {
        match reason {
            RenameHintReason::SourceRescan(reason) => observer_hold(reason),
            RenameHintReason::Limit => BATCH_LIMIT,
            RenameHintReason::UnpairedOldName
            | RenameHintReason::UnpairedNewName
            | RenameHintReason::InterleavedRename => PLAN_PAIRING,
            RenameHintReason::DifferentParent | RenameHintReason::UnsupportedName => {
                PLAN_UNSUPPORTED
            }
            RenameHintReason::CaseOnlyRename
            | RenameHintReason::DuplicateEndpoint
            | RenameHintReason::RenameChain
            | RenameHintReason::CaseAmbiguousEndpoint => PLAN_AMBIGUOUS,
        }
    }
    #[cfg(all(test, debug_assertions))]
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct Observation {
        pub(crate) attached: bool,
        pub(crate) instance: Option<u64>,
        pub(crate) held: bool,
        pub(crate) cloud_directories_skipped: u64,
        pub(crate) cloud_files_skipped: u64,
        pub(crate) directory_offers: u64,
        pub(crate) provider_directory_skipped: bool,
    }
    pub(crate) struct Dispatcher {
        rename: Option<Box<rename::Producer>>,
        mkdir: Option<mkdir::Producer>,
        create: Option<create::Producer>,
        attached: bool,
        instance: Option<u64>,
        batch: Option<NotificationBatch>,
        cursor: Cursor,
        hold_reason: Option<&'static str>,
        pending_files: Vec<(Vec<String>, u64)>,
        file_wave_started: bool,
        #[cfg(all(test, debug_assertions))]
        fixture_directory: bool,
        #[cfg(all(test, debug_assertions))]
        fixture_counts: [u64; 3],
        #[cfg(all(test, debug_assertions))]
        fixture_provider_directory_skipped: bool,
    }
    impl Dispatcher {
        pub(crate) fn new(
            rename: Option<Box<rename::Producer>>,
            mkdir: Option<mkdir::Producer>,
        ) -> Result<Self, &'static str> {
            if mkdir.is_some() && !DIRECTORY_ROUTING_READY {
                return Err("Shared directory routing is not admitted");
            }
            Self::build(rename, mkdir, None)
        }
        // Test admission changes routing only; original shared/authorization
        // checks and every actual consumer/native guard remain mandatory.
        #[cfg(all(test, debug_assertions))]
        pub(crate) fn new_mixed_fixture(
            rename: Option<Box<rename::Producer>>,
            mkdir: mkdir::Producer,
        ) -> Result<Self, &'static str> {
            let mut value = Self::build(rename, Some(mkdir), None)?;
            value.fixture_directory = true;
            Ok(value)
        }
        pub(crate) fn new_create(
            rename: Option<Box<rename::Producer>>,
            create: create::Producer,
        ) -> Result<Self, &'static str> {
            Self::build(rename, None, Some(create))
        }
        fn build(
            rename: Option<Box<rename::Producer>>,
            mkdir: Option<mkdir::Producer>,
            create: Option<create::Producer>,
        ) -> Result<Self, &'static str> {
            if rename.is_none() && mkdir.is_none() && create.is_none() {
                return Err(rename::UNAVAILABLE);
            }
            if let Some(directory) = &mkdir {
                if !directory.is_shared() {
                    return Err("Shared directory routing is not admitted");
                }
                if rename
                    .as_ref()
                    .is_some_and(|file| file.authorization() != directory.authorization())
                {
                    return Err(HOLD);
                }
            }
            Ok(Self {
                rename,
                mkdir,
                create,
                attached: false,
                instance: None,
                batch: None,
                cursor: Cursor::default(),
                hold_reason: None,
                pending_files: Vec::new(),
                file_wave_started: false,
                #[cfg(all(test, debug_assertions))]
                fixture_directory: false,
                #[cfg(all(test, debug_assertions))]
                fixture_counts: [0; 3],
                #[cfg(all(test, debug_assertions))]
                fixture_provider_directory_skipped: false,
            })
        }
        pub(crate) fn with_create(mut self, producer: create::Producer) -> Self {
            self.create = Some(producer);
            self
        }
        pub(crate) fn stop_create(&mut self, connection: &ConfiguredRootConnection) {
            if let Some(create) = &mut self.create {
                create.stop(connection);
            }
        }
        pub(crate) fn drain_create(
            &mut self,
            connection: &ConfiguredRootConnection,
            workers: &mut create::Workers,
        ) {
            if let Some(create) = &mut self.create {
                if self.cursor.held {
                    create.stop(connection);
                }
                create.drain_held(connection, workers);
            }
        }
        #[cfg(all(test, debug_assertions))]
        pub(crate) fn observation(&self) -> Observation {
            Observation {
                attached: self.attached,
                instance: self.instance,
                held: self.cursor.held,
                cloud_directories_skipped: self.fixture_counts[0],
                cloud_files_skipped: self.fixture_counts[1],
                directory_offers: self.fixture_counts[2],
                provider_directory_skipped: self.fixture_provider_directory_skipped,
            }
        }
        /// Immutable borrow for the existing fixed-path read-only fixture only;
        /// this does not expose a connection/store/native completion capability.
        #[cfg(all(test, debug_assertions))]
        pub(crate) fn rename_for_observation(&self) -> Option<&rename::Producer> {
            self.rename.as_deref()
        }
        pub(crate) fn hold(&mut self) {
            self.hold_reason.get_or_insert(HOLD);
            self.cursor.hold();
            self.batch = None;
            self.pending_files.clear();
            if let Some(file) = &mut self.rename {
                file.hold();
            }
            if let Some(directory) = &mut self.mkdir {
                directory.hold_shared();
            }
        }
        fn current(
            &self,
            backend: &Arc<OpenCloudPlaceholderBackend>,
            root: ConfiguredRootIdentity,
        ) -> bool {
            !self.cursor.held
                && (self.rename.is_some() || self.mkdir.is_some() || self.create.is_some())
                && self
                    .create
                    .as_ref()
                    .is_none_or(|create| create.is_current(backend, root))
                && self
                    .rename
                    .as_ref()
                    .is_none_or(|file| file.is_current(backend, root))
                && self
                    .mkdir
                    .as_ref()
                    .is_none_or(|directory| directory.is_current(backend, root))
        }
        pub(crate) fn tick(
            &mut self,
            connection: &mut ConfiguredRootConnection,
            backend: &Arc<OpenCloudPlaceholderBackend>,
            root: ConfiguredRootIdentity,
            save_or_command_active: bool,
        ) -> Result<(), &'static str> {
            self.tick_with_create(connection, backend, root, save_or_command_active, None)
        }
        pub(crate) fn tick_with_create(
            &mut self,
            connection: &mut ConfiguredRootConnection,
            backend: &Arc<OpenCloudPlaceholderBackend>,
            root: ConfiguredRootIdentity,
            save_or_command_active: bool,
            workers: Option<&mut create::Workers>,
        ) -> Result<(), &'static str> {
            // A held owner is never polled or replayed. Preserve its original
            // fixed reason instead of replacing it with generic HOLD next tick.
            if let Some(reason) = self.hold_reason {
                return Err(reason);
            }
            let result =
                self.tick_inner(connection, backend, root, save_or_command_active, workers);
            if let Err(reason) = result {
                self.hold_reason = Some(reason);
                self.stop_create(connection);
                self.hold();
            }
            result
        }
        fn tick_inner(
            &mut self,
            connection: &mut ConfiguredRootConnection,
            backend: &Arc<OpenCloudPlaceholderBackend>,
            root: ConfiguredRootIdentity,
            save_or_command_active: bool,
            mut workers: Option<&mut create::Workers>,
        ) -> Result<(), &'static str> {
            if !self.current(backend, root) {
                return Err(HOLD);
            }
            if connection.namespace_file_operation_pending() {
                return Ok(());
            }
            if save_or_command_active || self.mkdir.as_ref().is_some_and(mkdir::Producer::is_paused)
            {
                return Ok(());
            }
            if let (Some(create), Some(workers)) = (&mut self.create, workers.as_deref_mut()) {
                create.begin_round(workers);
            }
            if !self.pending_files.is_empty() {
                // Gather only contiguous, same-parent ordinary file hints. This
                // classification controls scheduling; each native create still
                // independently proves its root, parent, encryption and custody.
                let extend = !self.file_wave_started
                    && self.pending_files.len() < super::super::windows_create_executor::WORKERS
                    && self.cursor.front().is_some_and(|work| {
                        let Work::Directory(index) = work else {
                            return false;
                        };
                        let Some(NotificationBatch::Hints(hints)) = self.batch.as_ref() else {
                            return false;
                        };
                        let Some(hint) = hints.get(index) else {
                            return false;
                        };
                        let components = hint.components();
                        if !self
                            .create
                            .as_ref()
                            .is_some_and(|create| create.can_join(components))
                        {
                            return false;
                        }
                        let refs = components.iter().map(String::as_str).collect::<Vec<_>>();
                        connection
                            .observe_namespace_entry(&refs)
                            .is_ok_and(|entry| entry.kind == NamespaceEntryKind::PlainFile)
                    });
                if !extend {
                    self.file_wave_started = true;
                    let create = self.create.as_mut().ok_or(HOLD)?;
                    let workers = workers.as_deref_mut().ok_or(HOLD)?;
                    let pending = std::mem::take(&mut self.pending_files);
                    for (components, generation) in pending {
                        if !create.step(
                            connection,
                            backend,
                            root,
                            &components,
                            generation,
                            CreateKind::File,
                            workers,
                        )? {
                            self.pending_files.push((components, generation));
                        }
                    }
                    // A directory, rename, parent change, or next batch cannot
                    // overtake unfinished original captures from this wave.
                    if !self.pending_files.is_empty() {
                        return Ok(());
                    }
                    self.file_wave_started = false;
                }
            }
            if !self.cursor.pending() && self.batch.is_some() {
                self.batch = None;
            }
            if self.batch.is_none() {
                // Exactly ONE attach OR poll; both methods preserve connection-
                // owned kernel storage. Never reattach a held/stopped instance.
                let value = if self.attached {
                    connection.poll_namespace_observer(Duration::ZERO)
                } else {
                    connection.attach_namespace_observer()
                }
                .map_err(|_| OBSERVER_UNAVAILABLE)?;
                if value.root_identity() != root
                    || value.provider_scope() != backend.scope()
                    || value.instance() == 0
                    || self.instance.is_some_and(|id| id != value.instance())
                    || !self.current(backend, root)
                {
                    return Err(CONTEXT_CHANGED);
                }
                self.attached = true;
                self.instance = Some(value.instance());
                match value.poll() {
                    ObserverPoll::Idle | ObserverPoll::Pending => return Ok(()),
                    ObserverPoll::Stopped => return Err(OBSERVER_STOPPED),
                    ObserverPoll::Batch(batch) => {
                        let pairs = match pair_move_hints(batch) {
                            RenameHintBatch::Pairs(pairs) => pairs,
                            RenameHintBatch::RescanRequired(reason) => {
                                return Err(pairing_hold(reason));
                            }
                        };
                        if pairs.len() > MAX_PAIRS {
                            return Err(RENAME_LIMIT);
                        }
                        let NotificationBatch::Hints(hints) = batch else {
                            return Err(PLAN_STATE);
                        };
                        let inputs = hints
                            .iter()
                            .map(|hint| Hint {
                                action: match hint.action() {
                                    DirectoryAction::Added => Action::Added,
                                    DirectoryAction::Modified => Action::Modified,
                                    DirectoryAction::Removed => Action::Removed,
                                    DirectoryAction::RenamedOldName => Action::Old,
                                    DirectoryAction::RenamedNewName => Action::New,
                                },
                                components: hint.components(),
                            })
                            .collect::<Vec<_>>();
                        let mut accounted = inputs
                            .iter()
                            .map(|hint| {
                                let refs = hint
                                    .components
                                    .iter()
                                    .map(String::as_str)
                                    .collect::<Vec<_>>();
                                connection
                                    .completed_file_replacement(&refs)
                                    .map_err(|_| OWNER_HOLD)
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        // A published replacement may arrive as temp->target.
                        // Suppress both pair endpoints only when the actual new
                        // target still matches that ORIGINAL completed receipt.
                        let mut retired_sources = Vec::new();
                        for i in 0..inputs.len().saturating_sub(1) {
                            if inputs[i].action == Action::Old
                                && inputs[i + 1].action == Action::New
                                && accounted[i + 1]
                                && inputs[i].components.len() == inputs[i + 1].components.len()
                                && inputs[i].components[..inputs[i].components.len() - 1]
                                    == inputs[i + 1].components
                                        [..inputs[i + 1].components.len() - 1]
                            {
                                let old = inputs[i]
                                    .components
                                    .iter()
                                    .map(String::as_str)
                                    .collect::<Vec<_>>();
                                let new = inputs[i + 1]
                                    .components
                                    .iter()
                                    .map(String::as_str)
                                    .collect::<Vec<_>>();
                                if !connection
                                    .completed_replacement_source_absent(&old, &new)
                                    .map_err(|_| OWNER_HOLD)?
                                {
                                    return Err(OWNER_HOLD);
                                }
                                accounted[i] = true;
                                retired_sources.push(inputs[i].components);
                            }
                        }
                        for (i, hint) in inputs.iter().enumerate() {
                            if retired_sources.iter().any(|old| *old == hint.components) {
                                accounted[i] = true;
                            }
                        }
                        let work = route_accounted(
                            &inputs,
                            self.mkdir.is_some()
                                || self
                                    .create
                                    .as_ref()
                                    .is_some_and(create::Producer::allows_directory),
                            self.create.is_some(),
                            &accounted,
                        )
                        .map_err(plan_hold)?;
                        if work.is_empty() {
                            return Ok(());
                        }
                        self.cursor.admit(work).map_err(plan_hold)?;
                        // Only untrusted notification data is cloned, not any
                        // admission, publication receipt, store or native lease.
                        self.batch = Some(batch.clone());
                    }
                }
            }
            if !self.current(backend, root) {
                return Err(HOLD);
            }
            let work = self.cursor.front().ok_or(HOLD)?;
            let generation = self.cursor.generation().map_err(plan_hold)?;
            match work {
                Work::Rename(index) => {
                    let pairs = match pair_move_hints(self.batch.as_ref().ok_or(HOLD)?) {
                        RenameHintBatch::Pairs(pairs) => pairs,
                        RenameHintBatch::RescanRequired(reason) => {
                            return Err(pairing_hold(reason));
                        }
                    };
                    let pair = pairs.get(index).cloned().ok_or(HOLD)?;
                    let components = pair.new_components().to_vec();
                    let refs = components.iter().map(String::as_str).collect::<Vec<_>>();
                    let plain = connection
                        .observe_namespace_entry(&refs)
                        .map_err(|_| OWNER_HOLD)?
                        .kind
                        == NamespaceEntryKind::PlainFile;
                    if plain
                        && self
                            .create
                            .as_ref()
                            .is_some_and(create::Producer::allows_file)
                    {
                        // A plain destination has no original cloud MOVE
                        // admission. Reuse fresh create-only/If-None-Match;
                        // neither hint nor this path deletes the source.
                        if self.create.as_mut().ok_or(HOLD)?.step(
                            connection,
                            backend,
                            root,
                            &components,
                            generation,
                            CreateKind::File,
                            workers.ok_or(HOLD)?,
                        )? {
                            self.cursor.complete().map_err(plan_hold)?;
                        }
                    } else {
                        self.rename
                            .as_mut()
                            .ok_or(HOLD)?
                            .dispatch_pair(connection, backend, root, pair, generation)?;
                        self.cursor.complete().map_err(plan_hold)?;
                    }
                }
                Work::Directory(index) => {
                    let directory_ready = DIRECTORY_ROUTING_READY
                        || self
                            .create
                            .as_ref()
                            .is_some_and(create::Producer::allows_directory);
                    #[cfg(all(test, debug_assertions))]
                    let directory_ready = directory_ready || self.fixture_directory;
                    if !directory_ready && self.create.is_none() {
                        return Err(HOLD);
                    }
                    if self
                        .create
                        .as_ref()
                        .is_some_and(|create| create.active_kind_for(generation).is_some())
                    {
                        let NotificationBatch::Hints(hints) = self.batch.as_ref().ok_or(HOLD)?
                        else {
                            return Err(HOLD);
                        };
                        let components = hints.get(index).ok_or(HOLD)?.components();
                        if !create_personal(components) {
                            return Err(HOLD);
                        }
                        let kind = self
                            .create
                            .as_ref()
                            .and_then(|create| create.active_kind_for(generation))
                            .ok_or(HOLD)?;
                        if self.create.as_mut().ok_or(HOLD)?.step(
                            connection,
                            backend,
                            root,
                            components,
                            generation,
                            kind,
                            workers.as_deref_mut().ok_or(HOLD)?,
                        )? {
                            self.cursor.complete().map_err(plan_hold)?;
                        } else if self
                            .create
                            .as_ref()
                            .is_some_and(|create| create.pipeline_ready(generation))
                        {
                            self.pending_files.push((components.to_vec(), generation));
                            self.cursor.complete().map_err(plan_hold)?;
                        }
                    } else if !self.cursor.directory_started {
                        let NotificationBatch::Hints(hints) = self.batch.as_ref().ok_or(HOLD)?
                        else {
                            return Err(HOLD);
                        };
                        let components = hints.get(index).ok_or(HOLD)?.components().to_vec();
                        let refs = components.iter().map(String::as_str).collect::<Vec<_>>();
                        if !self.current(backend, root) {
                            return Err(HOLD);
                        }
                        let observed = connection.observe_namespace_entry(&refs);
                        if !self.current(backend, root) {
                            return Err(HOLD);
                        }
                        let shape = observed.as_ref().ok().map(|entry| match entry.kind {
                            NamespaceEntryKind::PlainFile => ObservedShape::PlainFile,
                            NamespaceEntryKind::PlainDirectory => ObservedShape::PlainDirectory,
                            NamespaceEntryKind::CloudFile | NamespaceEntryKind::CloudDirectory => {
                                ObservedShape::Cloud
                            }
                        });
                        let selection = if self.create.is_some() && self.mkdir.is_none() {
                            let create = self.create.as_ref().ok_or(HOLD)?;
                            select_create_observed(
                                &components,
                                shape,
                                create.allows_file(),
                                create.allows_directory(),
                                hints.get(index).ok_or(HOLD)?.action() == DirectoryAction::Added,
                            )
                        } else {
                            select_observed(
                                &components,
                                shape,
                                directory_ready,
                                self.create
                                    .as_ref()
                                    .is_some_and(create::Producer::allows_file),
                            )
                        };
                        match selection.map_err(plan_hold)? {
                            Selection::OfferDirectory => {
                                if self
                                    .create
                                    .as_ref()
                                    .is_some_and(create::Producer::allows_directory)
                                {
                                    if self.create.as_mut().ok_or(HOLD)?.step(
                                        connection,
                                        backend,
                                        root,
                                        &components,
                                        generation,
                                        CreateKind::Directory,
                                        workers.ok_or(HOLD)?,
                                    )? {
                                        self.cursor.complete().map_err(plan_hold)?;
                                    }
                                } else {
                                    // Kind/FileID are hints only. The original consumer
                                    // independently reacquires all pins and admission.
                                    self.mkdir
                                        .as_mut()
                                        .ok_or(HOLD)?
                                        .offer_added(components, generation)
                                        .map_err(|_| HOLD)?;
                                    self.cursor.directory_started = true;
                                    #[cfg(all(test, debug_assertions))]
                                    {
                                        self.fixture_counts[2] =
                                            self.fixture_counts[2].checked_add(1).ok_or(HOLD)?;
                                    }
                                }
                            }
                            Selection::SkipCloud => {
                                // complete() advances ONLY this volatile cursor item.
                                // No directory writer/offer/session, status completion,
                                // ownership, clean-content or upload claim is made.
                                #[cfg(all(test, debug_assertions))]
                                {
                                    let observed = observed.map_err(|_| OWNER_HOLD)?;
                                    let index =
                                        if observed.kind == NamespaceEntryKind::CloudDirectory {
                                            0
                                        } else {
                                            1
                                        };
                                    if index == 0
                                        && components == ["Personal", "provider-directory"]
                                    {
                                        self.fixture_provider_directory_skipped = true;
                                    }
                                    self.fixture_counts[index] =
                                        self.fixture_counts[index].checked_add(1).ok_or(HOLD)?;
                                }
                                self.cursor.complete().map_err(plan_hold)?;
                            }
                            Selection::CreateFile => {
                                let create = self.create.as_mut().ok_or(HOLD)?;
                                let workers = workers.as_deref_mut().ok_or(HOLD)?;
                                if create.step(
                                    connection,
                                    backend,
                                    root,
                                    &components,
                                    generation,
                                    CreateKind::File,
                                    workers,
                                )? {
                                    self.cursor.complete().map_err(plan_hold)?;
                                } else if create.pipeline_ready(generation) {
                                    self.pending_files.push((components, generation));
                                    self.cursor.complete().map_err(plan_hold)?;
                                }
                            }
                        }
                    }
                    // A deferred/started head keeps its original generation,
                    // FileID and publication selector; never filter it afresh.
                    if self.cursor.directory_started {
                        match self
                            .mkdir
                            .as_mut()
                            .ok_or(HOLD)?
                            .step_shared(connection, backend, root)
                        {
                            mkdir::SharedStep::Completed => {
                                self.cursor.complete().map_err(plan_hold)?
                            }
                            mkdir::SharedStep::Waiting | mkdir::SharedStep::DeferredPristine => (),
                            mkdir::SharedStep::Held => return Err(HOLD),
                        }
                    }
                }
            }
            if !self.current(backend, root) {
                return Err(HOLD);
            }
            if !self.cursor.pending() && self.pending_files.is_empty() {
                self.batch = None;
            }
            Ok(())
        }
    }
}
#[cfg(windows)]
pub(crate) use connected::*;

#[cfg(test)]
mod tests {
    use super::*;
    fn parts(path: &str) -> Vec<String> {
        path.split('/').map(str::to_owned).collect()
    }
    #[test]
    fn phase_permissions_are_independent_and_directories_require_added_personal() {
        let path = parts("Personal/new");
        for file in [false, true] {
            for directory in [false, true] {
                assert_eq!(
                    select_create_observed(
                        &path,
                        Some(ObservedShape::PlainFile),
                        file,
                        directory,
                        true
                    )
                    .is_ok(),
                    file
                );
                assert_eq!(
                    select_create_observed(
                        &path,
                        Some(ObservedShape::PlainDirectory),
                        file,
                        directory,
                        true
                    )
                    .is_ok(),
                    directory
                );
                assert!(
                    select_create_observed(
                        &path,
                        Some(ObservedShape::PlainDirectory),
                        file,
                        directory,
                        false
                    )
                    .is_err()
                );
                assert!(select_create_observed(&path, None, file, directory, true).is_err());
                for unsupported in ["Personal", "Spaces", "Spaces/team"] {
                    for shape in [ObservedShape::PlainDirectory, ObservedShape::PlainFile] {
                        assert!(
                            select_create_observed(
                                &parts(unsupported),
                                Some(shape),
                                file,
                                directory,
                                true
                            )
                            .is_err()
                        );
                    }
                }
            }
        }
        assert_eq!(
            select_create_observed(&path, Some(ObservedShape::Cloud), false, true, true),
            Ok(Selection::SkipCloud)
        );
        assert!(
            select_create_observed(&path, Some(ObservedShape::Cloud), false, false, true).is_err()
        );
        // The legacy selector remains separately admitted, including old mixed fixtures.
        assert_eq!(
            select_observed(&path, Some(ObservedShape::PlainDirectory), true, false),
            Ok(Selection::OfferDirectory)
        );
    }
    #[test]
    fn completion_requires_original_kind_and_nonzero_executor_id() {
        for expected in [CreateKind::File, CreateKind::Directory] {
            for actual in [CreateKind::File, CreateKind::Directory] {
                for (flight, reply) in [(0, 0), (0, 1), (4, 3), (4, 4), (4, 5)] {
                    assert_eq!(
                        matching_create_completion(expected, flight, actual, reply),
                        expected == actual && flight == 4 && reply == 4
                    );
                }
            }
        }
    }
    #[test]
    fn optin_routes_navigation_and_space_hints_only_for_live_classification() {
        for path in [
            "Personal",
            "Spaces",
            "Spaces/team",
            "Spaces/team/file.bin",
            "Personal/new.bin",
        ] {
            let components = parts(path);
            for action in [Action::Added, Action::Modified] {
                let hints = [Hint {
                    action,
                    components: &components,
                }];
                assert_eq!(route(&hints, false, true), Ok(vec![Work::Directory(0)]));
                assert_eq!(route(&hints, false, false), Ok(vec![]));
            }
            // Observing removal grants no delete/root authority; the native
            // delete owner rejects roots and original physical pins remain.
            assert_eq!(
                route(
                    &[Hint {
                        action: Action::Removed,
                        components: &components
                    }],
                    false,
                    true
                ),
                Ok(vec![])
            );
        }
        for components in [
            vec![],
            parts("Other/file"),
            parts("spaces/team"),
            vec!["Spaces".into(); 257],
        ] {
            assert!(
                route(
                    &[Hint {
                        action: Action::Added,
                        components: &components
                    }],
                    false,
                    true
                )
                .is_err()
            );
        }
    }
    #[test]
    fn live_selection_skips_only_cloud_shape_and_never_admits_unsupported_plain() {
        for path in ["Personal", "Spaces", "Spaces/team"] {
            let components = parts(path);
            assert_eq!(
                select_observed(&components, Some(ObservedShape::Cloud), true, true),
                Ok(Selection::SkipCloud)
            );
            for shape in [
                None,
                Some(ObservedShape::PlainFile),
                Some(ObservedShape::PlainDirectory),
            ] {
                assert!(select_observed(&components, shape, true, true).is_err());
            }
        }
        let direct = parts("Personal/new.bin");
        assert_eq!(
            select_observed(&direct, Some(ObservedShape::PlainFile), false, true),
            Ok(Selection::CreateFile)
        );
        assert!(select_observed(&direct, Some(ObservedShape::PlainFile), true, false).is_err());
        let directory = parts("Personal/new-directory");
        assert_eq!(
            select_observed(&directory, Some(ObservedShape::PlainDirectory), true, true),
            Ok(Selection::OfferDirectory)
        );
        assert!(
            select_observed(&directory, Some(ObservedShape::PlainDirectory), false, true).is_err()
        );
        assert_eq!(
            select_observed(
                &parts("Personal/Courses & CEUs #1/nested/file.bin"),
                Some(ObservedShape::PlainFile),
                true,
                true
            ),
            Ok(Selection::CreateFile)
        );
        // A Space child is eligible; namespace/Space roots remain excluded.
        assert!(create_personal(&parts("Spaces/team/file.bin")));
        assert!(!create_personal(&parts("Personal")));
        assert!(!create_personal(&vec!["Personal".into(); 257]));
        // A later Skip must never erase an endpoint from the raw batch plan.
        assert_eq!(
            select_observed(&direct, Some(ObservedShape::Cloud), false, true),
            Ok(Selection::SkipCloud)
        );
        let destination = parts("Personal/renamed.bin");
        assert!(
            route(
                &[
                    Hint {
                        action: Action::Added,
                        components: &direct
                    },
                    Hint {
                        action: Action::Old,
                        components: &direct
                    },
                    Hint {
                        action: Action::New,
                        components: &destination
                    }
                ],
                false,
                true
            )
            .is_err()
        );
    }
    #[test]
    fn file_only_provider_notifications_do_not_create_work_or_health() {
        let file = parts("Personal/source.bin");
        assert_eq!(
            route(
                &[
                    Hint {
                        action: Action::Added,
                        components: &file
                    },
                    Hint {
                        action: Action::Modified,
                        components: &file
                    }
                ],
                false,
                false
            ),
            Ok(vec![])
        );
        assert_eq!(
            route(
                &[Hint {
                    action: Action::Added,
                    components: &file
                }],
                true,
                false
            ),
            Ok(vec![Work::Directory(0)])
        );
        assert!(!std::hint::black_box(DIRECTORY_ROUTING_READY));
    }
    #[test]
    fn create_coalesces_repeated_exact_hints_but_never_aliases_or_rename_overlap() {
        let path = parts("Personal/new.bin");
        let unsupported = parts("Unknown/team/new.bin");
        for action in [Action::Added, Action::Modified, Action::Removed] {
            assert!(
                route(
                    &[Hint {
                        action,
                        components: &unsupported
                    }],
                    false,
                    true
                )
                .is_err()
            );
            assert_eq!(
                route(
                    &[Hint {
                        action,
                        components: &unsupported
                    }],
                    false,
                    false
                ),
                Ok(vec![])
            );
        }
        // A removal alone is healthy empty work, never cloud deletion or
        // completion authority. Same-batch work still checks every removal alias.
        assert_eq!(
            route(
                &[Hint {
                    action: Action::Removed,
                    components: &path
                }],
                false,
                true
            ),
            Ok(vec![])
        );
        let alias = parts("Personal/NEW.bin");
        let hints = [
            Hint {
                action: Action::Added,
                components: &path,
            },
            Hint {
                action: Action::Modified,
                components: &path,
            },
        ];
        assert_eq!(route(&hints, false, true), Ok(vec![Work::Directory(0)]));
        assert!(
            route(
                &[
                    Hint {
                        action: Action::Added,
                        components: &path
                    },
                    Hint {
                        action: Action::Modified,
                        components: &alias
                    }
                ],
                false,
                true
            )
            .is_err()
        );
        let other = parts("Personal/other.bin");
        assert!(
            route(
                &[
                    Hint {
                        action: Action::Added,
                        components: &path
                    },
                    Hint {
                        action: Action::Old,
                        components: &path
                    },
                    Hint {
                        action: Action::New,
                        components: &other
                    }
                ],
                false,
                true
            )
            .is_err()
        );
        let mut cursor = Cursor::default();
        cursor
            .admit(vec![Work::Directory(0), Work::Directory(1)])
            .unwrap();
        let original = cursor.generation().unwrap();
        assert_eq!(cursor.generation().unwrap(), original);
        assert_eq!(cursor.front(), Some(Work::Directory(0)));
        cursor.complete().unwrap();
        assert_eq!(cursor.front(), Some(Work::Directory(1)));
        assert!(cursor.generation().unwrap() > original);
    }
    #[test]
    fn mixed_order_never_routes_rename_destination_as_mkdir() {
        let added = parts("Personal/new");
        let old = parts("Personal/a");
        let new = parts("Personal/b");
        let hints = [
            Hint {
                action: Action::Added,
                components: &added,
            },
            Hint {
                action: Action::Old,
                components: &old,
            },
            Hint {
                action: Action::New,
                components: &new,
            },
        ];
        assert_eq!(
            route(&hints, true, false),
            Ok(vec![Work::Directory(0), Work::Rename(0)])
        );
        assert_eq!(route(&hints, false, false), Ok(vec![Work::Rename(0)]));
    }
    #[test]
    fn ambiguous_or_overflow_batch_has_no_partial_plan() {
        let old = parts("Personal/a");
        let new = parts("Personal/b");
        assert!(
            route(
                &[
                    Hint {
                        action: Action::Added,
                        components: &old
                    },
                    Hint {
                        action: Action::Old,
                        components: &old
                    },
                    Hint {
                        action: Action::New,
                        components: &new
                    }
                ],
                true,
                false
            )
            .is_err()
        );
        assert!(
            route(
                &[
                    Hint {
                        action: Action::Old,
                        components: &old
                    },
                    Hint {
                        action: Action::Modified,
                        components: &new
                    },
                    Hint {
                        action: Action::New,
                        components: &new
                    }
                ],
                true,
                false
            )
            .is_err()
        );
        let paths = (0..65)
            .map(|n| parts(&format!("Personal/{n}")))
            .collect::<Vec<_>>();
        assert!(
            route(
                &paths
                    .iter()
                    .map(|p| Hint {
                        action: Action::Added,
                        components: p
                    })
                    .collect::<Vec<_>>(),
                true,
                false
            )
            .is_err()
        );
    }
    #[test]
    fn unsupported_scope_and_removal_do_not_expand_features() {
        let a = parts("Spaces/a");
        let b = parts("Spaces/b");
        let local = parts("Personal/a");
        assert!(
            route(
                &[
                    Hint {
                        action: Action::Old,
                        components: &a
                    },
                    Hint {
                        action: Action::New,
                        components: &b
                    }
                ],
                false,
                false
            )
            .is_err()
        );
        assert!(
            route(
                &[Hint {
                    action: Action::Removed,
                    components: &local
                }],
                true,
                false
            )
            .is_err()
        );
        assert_eq!(
            route(
                &[Hint {
                    action: Action::Removed,
                    components: &local
                }],
                false,
                false
            ),
            Ok(vec![])
        );
    }
    #[test]
    fn shared_generation_stays_original_during_defer_then_increases() {
        let mut cursor = Cursor::default();
        cursor
            .admit(vec![Work::Directory(0), Work::Rename(0)])
            .unwrap();
        assert_eq!(cursor.front(), Some(Work::Directory(0)));
        assert_eq!(cursor.generation(), Ok(1));
        cursor.directory_started = true;
        assert_eq!(cursor.generation(), Ok(1));
        assert!(cursor.directory_started);
        cursor.complete().unwrap();
        assert_eq!(cursor.front(), Some(Work::Rename(0)));
        assert_eq!(cursor.generation(), Ok(2));
        cursor.complete().unwrap();
        assert!(!cursor.pending());
        cursor.admit(vec![Work::Rename(0)]).unwrap();
        assert_eq!(cursor.generation(), Ok(3));
    }
    #[test]
    fn hold_drops_volatile_work_without_rearming_or_counter_reset() {
        let mut cursor = Cursor::default();
        cursor.admit(vec![Work::Rename(0)]).unwrap();
        cursor.generation().unwrap();
        cursor.hold();
        assert_eq!(cursor.counter, 1);
        assert_eq!(cursor.front(), None);
        assert!(cursor.generation().is_err());
        assert!(cursor.admit(vec![Work::Rename(0)]).is_err());
    }
    #[test]
    fn counter_exhaustion_never_wraps_or_assigns_new_authority() {
        let mut cursor = Cursor {
            counter: u64::MAX,
            ..Cursor::default()
        };
        cursor.admit(vec![Work::Rename(0)]).unwrap();
        assert!(cursor.generation().is_err());
        assert_eq!(cursor.counter, u64::MAX);
        assert_eq!(cursor.assigned, None);
    }
}

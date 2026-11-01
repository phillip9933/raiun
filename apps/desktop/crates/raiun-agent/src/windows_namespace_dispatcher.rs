//! One owner-thread observer and ordered, volatile routing. Names/counters are
//! metadata only; existing consumers independently admit every mutation.
const MAX_WORK: usize = 64;
const MAX_PAIRS: usize = 32;
/// Held until a typed non-admitting directory classifier and native evidence
/// distinguish provider-created placeholders from new ordinary directories.
pub(crate) const DIRECTORY_ROUTING_READY: bool = false;

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
fn aliases(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(a, b)| a.eq_ignore_ascii_case(b))
}
/// Called only after whole-batch CF pairing validation. No prefix truncation:
/// one ambiguous/unsupported item refuses the plan before any side effect.
fn route(hints: &[Hint<'_>], directories: bool) -> Result<Vec<Work>, &'static str> {
    let mut result = Vec::new();
    let mut endpoints: Vec<&[String]> = Vec::new();
    let mut pair = 0;
    let mut index = 0;
    while index < hints.len() {
        let hint = &hints[index];
        let mut names = Vec::new();
        let work = match hint.action {
            Action::Old => {
                let next = hints
                    .get(index + 1)
                    .filter(|h| h.action == Action::New)
                    .ok_or("Unpaired namespace notification")?;
                if pair == MAX_PAIRS || !personal(hint.components) || !personal(next.components) {
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
            Action::Added if directories && personal(hint.components) => {
                names.push(hint.components);
                Some(Work::Directory(index))
            }
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
                if endpoints.iter().any(|old| aliases(old, name)) {
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
        if self.held || self.pending() || work.len() > MAX_WORK {
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
        windows_file_rename_producer as rename, windows_namespace_producer as mkdir,
    };
    use super::*;
    use raiun_cloudfiles_windows::{
        ConfiguredRootConnection, ConfiguredRootIdentity, OpenCloudPlaceholderBackend,
    };
    use raiun_control_windows::directory_notifications::{
        DirectoryAction, NotificationBatch, ObserverPoll,
        directory_rename_hints::{RenameHintBatch, pair_rename_hints},
    };
    use std::{sync::Arc, time::Duration};

    pub(crate) const HOLD: &str =
        "File namespace sync needs attention. Existing recovery files have been kept.";
    #[cfg(all(test, debug_assertions))]
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct Observation {
        pub(crate) attached: bool,
        pub(crate) instance: Option<u64>,
        pub(crate) held: bool,
    }
    pub(crate) struct Dispatcher {
        rename: Option<Box<rename::Producer>>,
        mkdir: Option<mkdir::Producer>,
        attached: bool,
        instance: Option<u64>,
        batch: Option<NotificationBatch>,
        cursor: Cursor,
    }
    impl Dispatcher {
        pub(crate) fn new(
            rename: Option<Box<rename::Producer>>,
            mkdir: Option<mkdir::Producer>,
        ) -> Result<Self, &'static str> {
            if rename.is_none() && mkdir.is_none() {
                return Err(rename::UNAVAILABLE);
            }
            if let Some(directory) = &mkdir {
                if !DIRECTORY_ROUTING_READY || !directory.is_shared() {
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
                attached: false,
                instance: None,
                batch: None,
                cursor: Cursor::default(),
            })
        }
        #[cfg(all(test, debug_assertions))]
        pub(crate) fn observation(&self) -> Observation {
            Observation {
                attached: self.attached,
                instance: self.instance,
                held: self.cursor.held,
            }
        }
        /// Immutable borrow for the existing fixed-path read-only fixture only;
        /// this does not expose a connection/store/native completion capability.
        #[cfg(all(test, debug_assertions))]
        pub(crate) fn rename_for_observation(&self) -> Option<&rename::Producer> {
            self.rename.as_deref()
        }
        pub(crate) fn hold(&mut self) {
            self.cursor.hold();
            self.batch = None;
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
                && (self.rename.is_some() || self.mkdir.is_some())
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
            let result = self.tick_inner(connection, backend, root, save_or_command_active);
            if result.is_err() {
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
        ) -> Result<(), &'static str> {
            if !self.current(backend, root) {
                return Err(HOLD);
            }
            if save_or_command_active || self.mkdir.as_ref().is_some_and(mkdir::Producer::is_paused)
            {
                return Ok(());
            }
            if self.batch.is_none() {
                // Exactly ONE attach OR poll; both methods preserve connection-
                // owned kernel storage. Never reattach a held/stopped instance.
                let value = if self.attached {
                    connection.poll_namespace_observer(Duration::ZERO)
                } else {
                    connection.attach_namespace_observer()
                }
                .map_err(|_| HOLD)?;
                if value.root_identity() != root
                    || value.provider_scope() != backend.scope()
                    || value.instance() == 0
                    || self.instance.is_some_and(|id| id != value.instance())
                    || !self.current(backend, root)
                {
                    return Err(HOLD);
                }
                self.attached = true;
                self.instance = Some(value.instance());
                match value.poll() {
                    ObserverPoll::Idle | ObserverPoll::Pending => return Ok(()),
                    ObserverPoll::Stopped => return Err(HOLD),
                    ObserverPoll::Batch(batch) => {
                        let RenameHintBatch::Pairs(pairs) = pair_rename_hints(batch) else {
                            return Err(HOLD);
                        };
                        if pairs.len() > MAX_PAIRS {
                            return Err(HOLD);
                        }
                        let NotificationBatch::Hints(hints) = batch else {
                            return Err(HOLD);
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
                        let work = route(&inputs, self.mkdir.is_some()).map_err(|_| HOLD)?;
                        if work.is_empty() {
                            return Ok(());
                        }
                        self.cursor.admit(work).map_err(|_| HOLD)?;
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
            let generation = self.cursor.generation().map_err(|_| HOLD)?;
            match work {
                Work::Rename(index) => {
                    let RenameHintBatch::Pairs(pairs) =
                        pair_rename_hints(self.batch.as_ref().ok_or(HOLD)?)
                    else {
                        return Err(HOLD);
                    };
                    let pair = pairs.get(index).cloned().ok_or(HOLD)?;
                    self.rename
                        .as_mut()
                        .ok_or(HOLD)?
                        .dispatch_pair(connection, backend, root, pair, generation)?;
                    self.cursor.complete().map_err(|_| HOLD)?;
                }
                Work::Directory(index) => {
                    if !DIRECTORY_ROUTING_READY {
                        return Err(HOLD);
                    }
                    let directory = self.mkdir.as_mut().ok_or(HOLD)?;
                    if !self.cursor.directory_started {
                        let NotificationBatch::Hints(hints) = self.batch.as_ref().ok_or(HOLD)?
                        else {
                            return Err(HOLD);
                        };
                        directory
                            .offer_added(
                                hints.get(index).ok_or(HOLD)?.components().to_vec(),
                                generation,
                            )
                            .map_err(|_| HOLD)?;
                        self.cursor.directory_started = true;
                    }
                    match directory.step_shared(connection, backend, root) {
                        mkdir::SharedStep::Completed => self.cursor.complete().map_err(|_| HOLD)?,
                        mkdir::SharedStep::Waiting | mkdir::SharedStep::DeferredPristine => (),
                        mkdir::SharedStep::Held => return Err(HOLD),
                    }
                }
            }
            if !self.current(backend, root) {
                return Err(HOLD);
            }
            if !self.cursor.pending() {
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
                true
            ),
            Ok(vec![Work::Directory(0)])
        );
        assert!(!std::hint::black_box(DIRECTORY_ROUTING_READY));
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
            route(&hints, true),
            Ok(vec![Work::Directory(0), Work::Rename(0)])
        );
        assert_eq!(route(&hints, false), Ok(vec![Work::Rename(0)]));
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
                true
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
                true
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
                true
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
                true
            )
            .is_err()
        );
        assert_eq!(
            route(
                &[Hint {
                    action: Action::Removed,
                    components: &local
                }],
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

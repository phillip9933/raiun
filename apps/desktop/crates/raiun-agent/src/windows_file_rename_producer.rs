//! Single-owner, fresh same-batch Personal file rename dispatch. Hints and the
//! catalog join are partial evidence; only the live guarded CF entry admits IO.
const MAX_PAIRS: usize = 32;

/// Generation-bound notice only, never an activation or admission capability.
#[derive(Default)]
pub(crate) struct Notice(Option<(u64, &'static str)>);
impl Notice {
    pub(crate) fn record(&mut self, original: u64, current: u64, message: &'static str) {
        if original != 0 && original == current {
            self.0 = Some((original, message));
        }
    }
    pub(crate) fn get(&self, current: u64, connected: bool) -> Option<&'static str> {
        self.0
            .filter(|(generation, _)| connected && current != 0 && *generation == current)
            .map(|(_, text)| text)
    }
}

struct CatalogHint<'a, T> {
    file: bool,
    space: &'a str,
    root: &'a str,
    path: &'a str,
    identity: T,
}
fn catalog_pair<'a, T: Copy>(
    entries: impl IntoIterator<Item = CatalogHint<'a, T>>,
    space: &str,
    root: &str,
    source_path: &str,
    parent_path: &str,
) -> Option<(T, T)> {
    let mut source = None;
    let mut parent = None;
    for entry in entries {
        if entry.space != space || entry.root != root {
            continue;
        }
        if entry.file && entry.path == source_path {
            if source.replace(entry.identity).is_some() {
                return None;
            }
        } else if !entry.file
            && entry.path == parent_path
            && parent.replace(entry.identity).is_some()
        {
            return None;
        }
    }
    Some((source?, parent?))
}

fn eligible(old: &[String], new: &[String]) -> bool {
    old.len() >= 2
        && old.len() <= 256
        && old.len() == new.len()
        && old[0] == "Personal"
        && old[..old.len() - 1] == new[..new.len() - 1]
        && !old
            .last()
            .unwrap()
            .eq_ignore_ascii_case(new.last().unwrap())
}

/// A batch is consumed once; a failed dispatch is never requeued. This cursor
/// cannot join hints from different batches or recreate a mutation capability.
#[derive(Default)]
struct BatchCursor {
    remaining: std::ops::Range<usize>,
}
impl BatchCursor {
    fn admit(&mut self, pairs: usize) -> bool {
        self.remaining = 0..0;
        if pairs == 0 || pairs > MAX_PAIRS {
            return false;
        }
        self.remaining = 0..pairs;
        true
    }
    fn next(&mut self, current: bool, initial_save: bool) -> Option<usize> {
        if !current {
            self.remaining = 0..0;
            return None;
        }
        if initial_save {
            return None;
        }
        self.remaining.next()
    }
}

#[cfg(windows)]
mod connected {
    use super::*;
    use raiun_cloudfiles_windows::{
        ConfiguredRootConnection, ConfiguredRootIdentity, OpenCloudPlaceholderBackend,
        PlaceholderBackend, ProviderIdentityBinding, ProviderIdentityCatalog,
        ProviderIdentityCatalogScope, namespace_intent::CapturedAuthorization,
    };
    use raiun_control_windows::{
        directory_notifications::directory_rename_hints::{RenameHintBatch, pair_rename_hints},
        directory_notifications::{NotificationBatch, ObserverPoll},
    };
    use std::sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    };
    use std::time::Duration;

    pub(crate) const UNAVAILABLE: &str =
        "File rename sync is unavailable for this drive. Existing recovery files have been kept.";
    pub(crate) const HOLD: &str =
        "File rename sync needs attention. Existing recovery files have been kept.";

    pub(crate) struct Producer {
        backend: Weak<OpenCloudPlaceholderBackend>,
        generation: Arc<AtomicU64>,
        auth: CapturedAuthorization,
        root: ConfiguredRootIdentity,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
        catalog: Arc<dyn ProviderIdentityCatalog>,
        scope: ProviderIdentityCatalogScope,
        attached: bool,
        instance: Option<u64>,
        batch: Option<NotificationBatch>,
        cursor: BatchCursor,
        record_generation: u64,
        held: bool,
    }
    impl Producer {
        pub(crate) fn capture(
            backend: &Arc<OpenCloudPlaceholderBackend>,
            catalog: Arc<dyn ProviderIdentityCatalog>,
            generation: &Arc<AtomicU64>,
            expected: u64,
            root: ConfiguredRootIdentity,
            personal_space: &str,
            personal_root: &str,
        ) -> Result<Self, &'static str> {
            let value = Self {
                backend: Arc::downgrade(backend),
                generation: generation.clone(),
                auth: CapturedAuthorization {
                    agent_generation: expected,
                    token_generation: backend.scope().token_generation(),
                },
                root,
                cancelled: backend
                    .recovery_transfer_cancellation()
                    .ok_or(UNAVAILABLE)?,
                catalog,
                scope: ProviderIdentityCatalogScope::new(
                    backend.scope(),
                    root,
                    personal_space,
                    personal_root,
                )
                .map_err(|_| UNAVAILABLE)?,
                attached: false,
                instance: None,
                batch: None,
                cursor: BatchCursor::default(),
                record_generation: 0,
                held: false,
            };
            if !value.current(value.auth, backend, root) {
                return Err(UNAVAILABLE);
            }
            Ok(value)
        }
        // Values only. This cannot attach/poll, dispatch, clear HOLD or mint custody.
        #[cfg(all(test, debug_assertions))]
        pub(crate) fn native_fixture_snapshot(&self) -> serde_json::Value {
            serde_json::json!({"attached":self.attached,"instance":self.instance,
                "held":self.held,"record_generation":self.record_generation,
                "agent_generation":self.auth.agent_generation,
                "token_generation":self.auth.token_generation,"root_volume_serial":self.root.volume_serial,"root_file_index":self.root.file_index})
        }
        #[cfg(all(test, debug_assertions))]
        pub(crate) fn native_fixture_catalog(&self) -> Result<serde_json::Value, &'static str> {
            let entries = self
                .catalog
                .load(&self.scope)
                .map_err(|_| "Original catalog unavailable")?;
            let mut source = None;
            let mut destination = None;
            for entry in entries {
                if let ProviderIdentityBinding::File {
                    ref space_id,
                    ref root_resource_id,
                    ref path,
                    ..
                } = entry
                {
                    if space_id != &self.scope.personal_space_id
                        || root_resource_id != &self.scope.personal_root_resource_id
                    {
                        continue;
                    }
                    let slot = match path.as_str() {
                        "/source.bin" => &mut source,
                        "/renamed.bin" => &mut destination,
                        _ => continue,
                    };
                    if slot.replace(*entry.identity().as_bytes()).is_some() {
                        return Err("Duplicate original catalog binding");
                    }
                }
            }
            Ok(serde_json::json!({"source":source,"destination":destination}))
        }
        fn current(
            &self,
            auth: CapturedAuthorization,
            backend: &Arc<OpenCloudPlaceholderBackend>,
            root: ConfiguredRootIdentity,
        ) -> bool {
            auth == self.auth
                && auth.agent_generation != 0
                && auth.token_generation != 0
                && self.generation.load(Ordering::Acquire) == auth.agent_generation
                && root == self.root
                && !backend.recovery_job_revoked()
                && !(self.cancelled)()
                && self
                    .backend
                    .upgrade()
                    .is_some_and(|original| Arc::ptr_eq(&original, backend))
        }
        pub(crate) fn tick(
            &mut self,
            connection: &mut ConfiguredRootConnection,
            backend: &Arc<OpenCloudPlaceholderBackend>,
            root: ConfiguredRootIdentity,
        ) -> Result<(), &'static str> {
            if !self.current(self.auth, backend, root) || self.held {
                self.batch = None;
                self.cursor.next(false, false);
                return Err(HOLD);
            }
            if self.batch.is_none() {
                let observation = match if self.attached {
                    connection.poll_namespace_observer(Duration::ZERO)
                } else {
                    self.attached = true;
                    connection.attach_namespace_observer()
                } {
                    Ok(observation) => observation,
                    Err(_) => {
                        self.held = true;
                        self.batch = None;
                        self.cursor.next(false, false);
                        return Err(HOLD);
                    }
                };
                if observation.root_identity() != root
                    || observation.provider_scope() != backend.scope()
                    || self.instance.is_some_and(|id| id != observation.instance())
                {
                    self.held = true;
                    return Err(HOLD);
                }
                self.instance = Some(observation.instance());
                match observation.poll() {
                    ObserverPoll::Batch(batch) => {
                        let RenameHintBatch::Pairs(pairs) = pair_rename_hints(batch) else {
                            self.held = true;
                            return Err(HOLD);
                        };
                        // Empty batches contain no rename work. Initial attach
                        // remains inventory-unknown and grants no rescan authority.
                        if pairs.is_empty() {
                            return Ok(());
                        }
                        if !self.cursor.admit(pairs.len()) {
                            self.held = true;
                            return Err(HOLD);
                        }
                        self.batch = Some(batch.clone());
                    }
                    ObserverPoll::Stopped => {
                        self.held = true;
                        return Err(HOLD);
                    }
                    ObserverPoll::Idle | ObserverPoll::Pending => return Ok(()),
                }
            }
            let Some(index) = self
                .cursor
                .next(self.current(self.auth, backend, root), false)
            else {
                self.batch = None;
                return Ok(());
            };
            let result = self.dispatch(connection, backend, root, index);
            if self.cursor.remaining.is_empty() {
                self.batch = None;
            }
            // Never replay a failed/pre-send/uncertain observation. Hold this
            // producer until a new explicitly connected owner is established.
            if result.is_err() {
                self.batch = None;
                self.held = true;
            }
            result
        }
        fn dispatch(
            &mut self,
            connection: &ConfiguredRootConnection,
            backend: &Arc<OpenCloudPlaceholderBackend>,
            root: ConfiguredRootIdentity,
            index: usize,
        ) -> Result<(), &'static str> {
            let RenameHintBatch::Pairs(pairs) = pair_rename_hints(self.batch.as_ref().ok_or(HOLD)?)
            else {
                return Err(HOLD);
            };
            let pair = pairs.get(index).ok_or(HOLD)?.clone();
            let old = pair.old_components();
            let new = pair.new_components();
            if !eligible(old, new) {
                return Err(HOLD);
            }
            let old_path = format!("/{}", old[1..].join("/"));
            let parent_path = if old.len() == 2 {
                "/".to_owned()
            } else {
                format!("/{}", old[1..old.len() - 1].join("/"))
            };
            let entries = self.catalog.load(&self.scope).map_err(|_| HOLD)?;
            let hints = entries.iter().filter_map(|entry| {
                let identity = entry.identity();
                match entry {
                    ProviderIdentityBinding::File {
                        space_id,
                        root_resource_id,
                        path,
                        ..
                    } => Some(CatalogHint {
                        file: true,
                        space: space_id,
                        root: root_resource_id,
                        path,
                        identity,
                    }),
                    ProviderIdentityBinding::Directory {
                        space_id,
                        root_resource_id,
                        path,
                        ..
                    } => Some(CatalogHint {
                        file: false,
                        space: space_id,
                        root: root_resource_id,
                        path,
                        identity,
                    }),
                    _ => None,
                }
            });
            let (source, parent) = catalog_pair(
                hints,
                &self.scope.personal_space_id,
                &self.scope.personal_root_resource_id,
                &old_path,
                &parent_path,
            )
            .ok_or(HOLD)?;
            let parts = new.iter().map(String::as_str).collect::<Vec<_>>();
            let observed = connection
                .observe_namespace_file(&parts)
                .map_err(|_| HOLD)?;
            self.record_generation = self.record_generation.checked_add(1).ok_or(HOLD)?;
            let current = |auth| self.current(auth, backend, root);
            let candidate = backend
                .file_rename_binding_candidate(
                    source,
                    parent,
                    pair,
                    self.auth,
                    observed.local_file,
                    &current,
                )
                .map_err(|_| HOLD)?;
            let outcome = connection
                .reconcile_fresh_file_rename_candidate(
                    backend,
                    &candidate,
                    self.record_generation,
                    &current,
                )
                .map_err(|_| HOLD)?;
            if !current(self.auth)
                || outcome
                    != raiun_cloudfiles_windows::namespace_file_rename::FileRenameOutcome::Completed
            {
                return Err(HOLD);
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
    fn pair_scope_excludes_cross_parent_case_only_and_spaces() {
        assert!(eligible(&parts("Personal/a"), &parts("Personal/b")));
        for (a, b) in [
            ("Personal/a", "Personal/A"),
            ("Personal/x/a", "Personal/y/b"),
            ("Spaces/a", "Spaces/b"),
            ("Personal", "Personal"),
        ] {
            assert!(!eligible(&parts(a), &parts(b)));
        }
    }
    #[test]
    fn command_epoch_and_initial_save_prevent_consumption() {
        let mut cursor = BatchCursor::default();
        assert!(cursor.admit(2));
        assert_eq!(cursor.next(true, true), None);
        assert_eq!(cursor.next(true, false), Some(0));
        assert_eq!(cursor.next(false, false), None);
        assert_eq!(cursor.next(true, false), None);
    }
    #[test]
    fn consumed_failure_is_not_retried_and_batch_bounds_fail_closed() {
        let mut cursor = BatchCursor::default();
        assert!(cursor.admit(1));
        assert_eq!(cursor.next(true, false), Some(0));
        assert_eq!(cursor.next(true, false), None);
        assert!(!cursor.admit(MAX_PAIRS + 1));
        assert_eq!(cursor.next(true, false), None);
    }
    #[test]
    fn catalog_join_requires_unique_exact_original_root_and_real_parent() {
        let entry = |file, space, root, path, id| CatalogHint {
            file,
            space,
            root,
            path,
            identity: [id; 16],
        };
        assert_eq!(
            catalog_pair(
                [
                    entry(true, "s", "r", "/a", 1),
                    entry(false, "s", "r", "/", 2)
                ],
                "s",
                "r",
                "/a",
                "/"
            ),
            Some(([1; 16], [2; 16]))
        );
        assert!(
            catalog_pair(
                [
                    entry(true, "s", "other", "/a", 1),
                    entry(false, "s", "r", "/", 2)
                ],
                "s",
                "r",
                "/a",
                "/"
            )
            .is_none()
        );
        assert!(
            catalog_pair(
                [
                    entry(true, "s", "r", "/a", 1),
                    entry(true, "s", "r", "/a", 3),
                    entry(false, "s", "r", "/", 2)
                ],
                "s",
                "r",
                "/a",
                "/"
            )
            .is_none()
        );
        assert!(catalog_pair([entry(true, "s", "r", "/a", 1)], "s", "r", "/a", "/").is_none());
    }
    #[test]
    fn retired_owner_cannot_publish_or_clear_new_generation_notice() {
        let mut notice = Notice::default();
        notice.record(7, 7, "old");
        assert_eq!(notice.get(8, true), None);
        notice.record(8, 8, "current");
        notice.record(7, 8, "stale");
        assert_eq!(notice.get(8, true), Some("current"));
        assert_eq!(notice.get(8, false), None);
        assert_eq!(notice.get(0, true), None);
    }
}

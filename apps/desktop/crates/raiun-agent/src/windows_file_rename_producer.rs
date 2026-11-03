//! Single-owner, fresh same-batch Personal or writable Space file rename dispatch. Hints and the
//! catalog join are partial evidence; only the live guarded CF entry admits IO.

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

fn eligible(old: &[String], new: &[String]) -> bool {
    fn file_path(parts: &[String]) -> bool {
        (2..=256).contains(&parts.len())
            && match parts[0].as_str() {
                "Personal" => true,
                "Spaces" => parts.len() >= 3,
                _ => false,
            }
    }
    file_path(old)
        && file_path(new)
        && old[0] == new[0]
        && !(old.len() == new.len() && old.iter().zip(new).all(|(a, b)| a.eq_ignore_ascii_case(b)))
}

#[cfg(windows)]
mod connected {
    use super::*;
    #[cfg(all(test, debug_assertions))]
    use raiun_cloudfiles_windows::ProviderIdentityBinding;
    use raiun_cloudfiles_windows::{
        ConfiguredRootConnection, ConfiguredRootIdentity, OpenCloudPlaceholderBackend,
        PlaceholderBackend, ProviderIdentityCatalog, ProviderIdentityCatalogScope,
        namespace_intent::CapturedAuthorization,
    };
    use raiun_control_windows::directory_notifications::directory_rename_hints::RenameHintPair;
    use std::sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    };

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
            serde_json::json!({"held":self.held,"record_generation":self.record_generation,
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
        pub(crate) fn is_current(
            &self,
            backend: &Arc<OpenCloudPlaceholderBackend>,
            root: ConfiguredRootIdentity,
        ) -> bool {
            !self.held && self.current(self.auth, backend, root)
        }
        pub(crate) fn authorization(&self) -> CapturedAuthorization {
            self.auth
        }
        pub(crate) fn hold(&mut self) {
            self.held = true;
        }
        /// One already-paired hint, not admission or replay authority. Only the
        /// original guarded candidate/public entry may authorize the operation.
        pub(crate) fn dispatch_pair(
            &mut self,
            connection: &ConfiguredRootConnection,
            backend: &Arc<OpenCloudPlaceholderBackend>,
            root: ConfiguredRootIdentity,
            pair: RenameHintPair<'_>,
            record_generation: u64,
        ) -> Result<(), &'static str> {
            if !self.is_current(backend, root)
                || record_generation == 0
                || record_generation <= self.record_generation
            {
                self.held = true;
                return Err(HOLD);
            }
            self.record_generation = record_generation;
            let result = self.dispatch(connection, backend, root, pair, record_generation);
            if result.is_err() {
                self.held = true;
            }
            result
        }
        fn dispatch(
            &mut self,
            connection: &ConfiguredRootConnection,
            backend: &Arc<OpenCloudPlaceholderBackend>,
            root: ConfiguredRootIdentity,
            pair: RenameHintPair<'_>,
            record_generation: u64,
        ) -> Result<(), &'static str> {
            let old = pair.old_components();
            let new = pair.new_components();
            if !eligible(old, new) {
                return Err(HOLD);
            }
            // Keep the original admitted catalog available. Target IDs are
            // resolved through fresh authenticated namespace traversal below;
            // a displayed Space label is never used as a remote identifier.
            self.catalog.load(&self.scope).map_err(|_| HOLD)?;
            let parts = new.iter().map(String::as_str).collect::<Vec<_>>();
            let observed = connection
                .observe_namespace_entry(&parts)
                .map_err(|_| HOLD)?;
            let current = |auth| self.current(auth, backend, root);
            if observed.kind == raiun_cloudfiles_windows::NamespaceEntryKind::CloudDirectory {
                let outcome = connection
                    .reconcile_fresh_directory_rename(
                        backend,
                        pair,
                        observed.local_file,
                        self.auth,
                        record_generation,
                        &current,
                    )
                    .map_err(|_| HOLD)?;
                if !current(self.auth) || outcome != raiun_cloudfiles_windows::namespace_file_rename::FileRenameOutcome::Completed {
                    return Err(HOLD);
                }
                return Ok(());
            }
            if observed.kind != raiun_cloudfiles_windows::NamespaceEntryKind::CloudFile {
                return Err(HOLD);
            }
            if old[..old.len() - 1] != new[..new.len() - 1] {
                let outcome = connection
                    .reconcile_fresh_file_move(
                        backend,
                        pair,
                        observed.local_file,
                        self.auth,
                        record_generation,
                        &current,
                    )
                    .map_err(|_| HOLD)?;
                if !current(self.auth) || outcome!=raiun_cloudfiles_windows::namespace_file_rename::FileRenameOutcome::Completed {
                    return Err(HOLD);
                }
                return Ok(());
            }
            let weak = self.backend.clone();
            let generation = self.generation.clone();
            let expected = self.auth;
            let cancelled = self.cancelled.clone();
            let original_root = self.root;
            let vault_current: Arc<dyn Fn(CapturedAuthorization) -> bool + Send + Sync> =
                Arc::new(move |auth| {
                    auth == expected
                        && generation.load(Ordering::Acquire) == auth.agent_generation
                        && !(cancelled)()
                        && root == original_root
                        && weak.upgrade().is_some_and(|b| {
                            !b.recovery_job_revoked()
                                && b.scope().token_generation() == auth.token_generation
                        })
                });
            if connection
                .try_reconcile_fresh_vault_file_rename(
                    backend,
                    old,
                    new,
                    observed.local_file,
                    self.auth,
                    self.generation.clone(),
                    vault_current,
                )
                .map_err(|_| HOLD)?
            {
                return Ok(());
            }
            let candidate = backend
                .file_rename_binding_candidate_from_hint(
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
                    record_generation,
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
    fn pair_scope_excludes_case_only_and_namespace_roots() {
        assert!(eligible(&parts("Personal/a"), &parts("Personal/b")));
        for (a, b) in [
            ("Personal/a", "Personal/A"),
            ("Spaces/a", "Spaces/b"),
            ("Personal", "Personal"),
        ] {
            assert!(!eligible(&parts(a), &parts(b)));
        }
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

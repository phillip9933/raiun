//! Explicit storage opt-in for namespace rename history. This does not enable
//! native rename admission or completion publication.
use super::{
    DurableEditRecoveryProvider, DurablePreparedEditRecovery, ScopeCatalog, StreamedRecoveryContext,
};
use crate::{BackendError, EditJournalScope, namespace_intent::CapturedAuthorization};
use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
use std::{path::Path, sync::Arc};

#[derive(Clone)]
pub(super) struct NamespaceRenameStoreContext {
    pub(super) state: Arc<crate::recovery_state::RecoveryStateRoot>,
    pub(super) admission: Arc<crate::recovery_admission::RecoveryAdmission>,
    pub(super) policy: crate::streamed_store::StorePolicy,
}

/// Read authenticated namespace metadata only. An unconfigured writer must
/// not mistake retained namespace history for an empty legacy journal.
pub(super) fn has_unresolved_namespace(
    namespace: Option<&NamespaceRenameStoreContext>,
    streamed: Option<&StreamedRecoveryContext>,
    catalog: &ScopeCatalog,
    provider: &crate::ProviderScope,
    physical_root: crate::ConfiguredRootIdentity,
) -> Result<bool, BackendError> {
    let summary = namespace_history_summary(namespace, streamed, catalog, provider, physical_root)?;
    crate::streamed_store::namespace_rename_store::history_unresolved(&summary, namespace.is_some())
}

/// Same bounded authenticated metadata query; no body or mutation authority.
pub(super) fn namespace_history_summary(
    namespace: Option<&NamespaceRenameStoreContext>,
    streamed: Option<&StreamedRecoveryContext>,
    catalog: &ScopeCatalog,
    provider: &crate::ProviderScope,
    physical_root: crate::ConfiguredRootIdentity,
) -> Result<crate::streamed_store::namespace_rename_store::NamespaceHistorySummary, BackendError> {
    if !super::valid_scope_binding(provider, physical_root) {
        return Err(BackendError::Unavailable);
    }
    let (state, policy) = if let Some(context) = namespace {
        if context.admission.state_identity() != context.state.identity()
            || context.state.path() != catalog.state_directory
        {
            return Err(BackendError::Unavailable);
        }
        (Arc::clone(&context.state), context.policy)
    } else if let Some(context) = streamed {
        if context.admission.state_identity() != context.state.identity()
            || context.state.path() != catalog.state_directory
        {
            return Err(BackendError::Unavailable);
        }
        (Arc::clone(&context.state), context.policy)
    } else {
        // The path was captured by the provider's protector, never selected
        // from an event or environment lookup here. Compatibility attestation
        // grants metadata access only; the existing-child reader below cannot
        // create a v2 root, quota file, catalog or writer context.
        let state = match crate::recovery_state::RecoveryStateRoot::existing_gui(
            &catalog.state_directory,
        ) {
            Ok(state) => state,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return match std::fs::symlink_metadata(&catalog.state_directory) {
                    Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => {
                        Ok(Default::default())
                    }
                    _ => Err(BackendError::Unavailable),
                };
            }
            Err(_) => return Err(BackendError::Unavailable),
        };
        // These existing defaults bound metadata discovery only. No content
        // body is opened and no storage/capture quota is admitted or changed.
        let defaults = raiun_core::WindowsRecoveryPolicy::default();
        let policy = crate::streamed_store::StorePolicy {
            max_content_bytes: defaults.max_file_bytes,
            max_state_bytes: defaults.max_state_bytes,
            max_entries: defaults.max_state_entries,
            max_metadata_bytes_per_scan: defaults.max_scan_metadata_bytes,
        };
        (state, policy)
    };
    let summary = crate::streamed_store::SnapshotStore::namespace_history_summary_existing(
        state,
        Arc::clone(&catalog.protector),
        policy,
        provider,
        physical_root,
    )
    .map_err(|_| BackendError::Unavailable)?;
    Ok(summary)
}

pub(super) fn prepared_store(
    prepared: &DurablePreparedEditRecovery,
    scope: &EditJournalScope,
    authorization: CapturedAuthorization,
) -> Result<Option<Arc<crate::streamed_store::namespace_rename_store::FileRenameStore>>, BackendError>
{
    let Some(context) = &prepared.namespace_rename else {
        return Ok(None);
    };
    super::validate_catalog_scope(scope).map_err(|_| BackendError::Unavailable)?;
    if !super::valid_scope_binding(&prepared.scope, prepared.root_identity)
        || !super::scope_matches_provider(scope, &prepared.scope, prepared.root_identity)
        || scope.root_volume_serial != prepared.root_identity.volume_serial
        || scope.root_file_index != prepared.root_identity.file_index
        || authorization.agent_generation == 0
        || authorization.token_generation != prepared.scope.token_generation()
    {
        return Err(BackendError::Unavailable);
    }
    for part in [&scope.space_id, &scope.root_resource_id] {
        if part.is_empty() || part.len() > 4096 || part.chars().any(char::is_control) {
            return Err(BackendError::Unavailable);
        }
    }
    let Some((scheme, authority)) = scope.server_origin.split_once("://") else {
        return Err(BackendError::Unavailable);
    };
    if !matches!(scheme, "http" | "https")
        || authority.is_empty()
        || authority
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@') || byte.is_ascii_whitespace())
    {
        return Err(BackendError::Unavailable);
    }
    context
        .state
        .verify_path()
        .map_err(|_| BackendError::Unavailable)?;
    if context.admission.state_identity() != context.state.identity() {
        return Err(BackendError::Unavailable);
    }
    let base = crate::streamed_store::SnapshotStore::create_or_open_admitted(
        Arc::clone(&context.state),
        scope.clone(),
        Arc::clone(&prepared.catalog.protector),
        context.policy,
    )
    .map_err(|_| BackendError::Unavailable)?;
    let store = crate::streamed_store::namespace_rename_store::FileRenameStore::new(base)
        .map_err(|_| BackendError::Unavailable)?;
    Ok(Some(store))
}

pub(super) fn prepared_directory_store(
    prepared: &DurablePreparedEditRecovery,
    scope: &EditJournalScope,
    authorization: CapturedAuthorization,
) -> Result<Option<Arc<crate::streamed_store::namespace_store::DirectoryIntentStore>>, BackendError>
{
    let Some(context) = &prepared.namespace_rename else {
        return Ok(None);
    };
    super::validate_catalog_scope(scope).map_err(|_| BackendError::Unavailable)?;
    if !super::valid_scope_binding(&prepared.scope, prepared.root_identity)
        || !super::scope_matches_provider(scope, &prepared.scope, prepared.root_identity)
        || scope.root_volume_serial != prepared.root_identity.volume_serial
        || scope.root_file_index != prepared.root_identity.file_index
        || authorization.agent_generation == 0
        || authorization.token_generation != prepared.scope.token_generation()
    {
        return Err(BackendError::Unavailable);
    }
    for part in [&scope.space_id, &scope.root_resource_id] {
        if part.is_empty() || part.len() > 4096 || part.chars().any(char::is_control) {
            return Err(BackendError::Unavailable);
        }
    }
    let Some((scheme, authority)) = scope.server_origin.split_once("://") else {
        return Err(BackendError::Unavailable);
    };
    if !matches!(scheme, "http" | "https")
        || authority.is_empty()
        || authority
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@') || byte.is_ascii_whitespace())
    {
        return Err(BackendError::Unavailable);
    }
    context
        .state
        .verify_path()
        .map_err(|_| BackendError::Unavailable)?;
    if context.admission.state_identity() != context.state.identity() {
        return Err(BackendError::Unavailable);
    }
    // Constructed only from the ORIGINAL prepared namespace context; no
    // current_user/default state/protector/caller policy is rediscovered.
    let store =
        crate::streamed_store::namespace_store::DirectoryIntentStore::create_or_open_admitted(
            Arc::clone(&context.state),
            scope.clone(),
            Arc::clone(&prepared.catalog.protector),
            context.policy,
        )
        .map_err(|_| BackendError::Unavailable)?;
    Ok(Some(store))
}

impl DurableEditRecoveryProvider {
    /// Explicit modern private-state opt-in. Call after any streamed setup.
    #[cfg(windows)]
    pub fn with_modern_namespace_file_rename(
        mut self,
        policy: crate::streamed_store::StorePolicy,
    ) -> Result<Self, crate::JournalError> {
        self.try_enable_modern_namespace_file_rename(policy)?;
        Ok(self)
    }

    /// Admit namespace storage without consuming the existing recovery owner
    /// on failure. No failed admission grants a namespace writer or discards
    /// the provider's original streamed/legacy recovery context.
    #[cfg(windows)]
    pub fn try_enable_modern_namespace_file_rename(
        &mut self,
        policy: crate::streamed_store::StorePolicy,
    ) -> Result<(), crate::JournalError> {
        if self.namespace_rename.is_some() {
            return Err(crate::JournalError::InvalidState);
        }
        let state = if let Some(streamed) = &self.streamed {
            if !same_policy(streamed.policy, policy)
                || streamed.state.path() != self.state_directory
            {
                return Err(crate::JournalError::InvalidState);
            }
            Arc::clone(&streamed.state)
        } else {
            open_modern_state(&self.state_directory)?
        };
        self.attach_namespace_rename(Some(state), policy)
    }

    /// Explicit GUI compatibility opt-in at the existing DPAPI state root.
    /// Call after any streamed setup; this does not change GUI ACLs.
    #[cfg(windows)]
    pub fn with_gui_namespace_file_rename(
        mut self,
        policy: crate::streamed_store::StorePolicy,
    ) -> Result<Self, crate::JournalError> {
        self.try_enable_gui_namespace_file_rename(policy)?;
        Ok(self)
    }

    /// Preserve the same GUI recovery owner when optional namespace admission
    /// is unavailable. Existing ACLs and retained recovery evidence are never
    /// repaired, removed or reinterpreted by this operation.
    #[cfg(windows)]
    pub fn try_enable_gui_namespace_file_rename(
        &mut self,
        policy: crate::streamed_store::StorePolicy,
    ) -> Result<(), crate::JournalError> {
        if self.namespace_rename.is_some() {
            return Err(crate::JournalError::InvalidState);
        }
        let state = if let Some(streamed) = &self.streamed {
            if !same_policy(streamed.policy, policy)
                || streamed.state.path() != self.state_directory
            {
                return Err(crate::JournalError::InvalidState);
            }
            Arc::clone(&streamed.state)
        } else {
            crate::recovery_state::RecoveryStateRoot::existing_gui(&self.state_directory)
                .map_err(|_| crate::JournalError::ProtectionFailed)?
        };
        self.attach_namespace_rename(Some(state), policy)
    }

    /// Scheduler information only; live prepared-store and native admission
    /// checks remain required for every attempted rename.
    #[cfg(windows)]
    pub fn namespace_file_rename_configured(&self) -> bool {
        self.namespace_rename.is_some()
    }

    fn attach_namespace_rename(
        &mut self,
        state: Option<Arc<crate::recovery_state::RecoveryStateRoot>>,
        policy: crate::streamed_store::StorePolicy,
    ) -> Result<(), crate::JournalError> {
        if self.namespace_rename.is_some() {
            return Err(crate::JournalError::InvalidState);
        }
        let (state, admission) = if let Some(streamed) = &self.streamed {
            if !same_policy(streamed.policy, policy)
                || streamed.state.path() != self.state_directory
                || state
                    .as_ref()
                    .is_some_and(|candidate| candidate.identity() != streamed.state.identity())
            {
                return Err(crate::JournalError::InvalidState);
            }
            (Arc::clone(&streamed.state), Arc::clone(&streamed.admission))
        } else {
            let state = state.ok_or(crate::JournalError::InvalidState)?;
            let admission = Arc::new(
                crate::recovery_admission::RecoveryAdmission::new_admitted(
                    Arc::clone(&state),
                    Arc::clone(&self.protector),
                    policy,
                )
                .map_err(crate::edit_journal::admission_error)?,
            );
            (state, admission)
        };
        self.namespace_rename = Some(NamespaceRenameStoreContext {
            state,
            admission,
            policy,
        });
        Ok(())
    }
}

fn open_modern_state(
    path: &Path,
) -> Result<Arc<crate::recovery_state::RecoveryStateRoot>, crate::JournalError> {
    let parent_path = path.parent().ok_or(crate::JournalError::InvalidScope)?;
    let name = path.file_name().ok_or(crate::JournalError::InvalidScope)?;
    let parent =
        PinnedDirectory::open(parent_path).map_err(|_| crate::JournalError::ProtectionFailed)?;
    let state = PrivateDirectory::open_under(&parent, name)
        .map_err(|_| crate::JournalError::ProtectionFailed)?;
    Ok(crate::recovery_state::RecoveryStateRoot::modern(Arc::new(
        state,
    )))
}

fn same_policy(
    a: crate::streamed_store::StorePolicy,
    b: crate::streamed_store::StorePolicy,
) -> bool {
    a.max_content_bytes == b.max_content_bytes
        && a.max_state_bytes == b.max_state_bytes
        && a.max_entries == b.max_entries
        && a.max_metadata_bytes_per_scan == b.max_metadata_bytes_per_scan
}

#[cfg(test)]
#[path = "recovery_namespace_store_tests.rs"]
mod tests;

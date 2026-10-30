//! Explicit ordinary edit recovery. No path derived from remote metadata is
//! accepted as a local capability, and no background journal replay is added.
use super::*;

pub(super) struct CachedStatus {
    pub binding: ActiveProviderBinding,
    pub source: Arc<dyn raiun_cloudfiles_windows::OrdinaryEditStatusSource>,
    pub last_outcome: Option<&'static str>,
}

fn outcome_name(outcome: &raiun_cloudfiles_windows::ReconciliationOutcome) -> &'static str {
    use raiun_cloudfiles_windows::ReconciliationOutcome;
    match outcome {
        ReconciliationOutcome::VerifiedApplied { .. } => "verified_applied",
        ReconciliationOutcome::Conflict(_) => "conflict",
        ReconciliationOutcome::Ambiguous => "outcome_unknown",
        ReconciliationOutcome::Deferred => "not_completed",
    }
}

fn update_last(
    cache: &Mutex<Option<CachedStatus>>,
    binding: Option<&ActiveProviderBinding>,
    outcome: &'static str,
) {
    if let Ok(mut cache) = cache.lock()
        && let Some(status) = cache.as_mut()
        && Some(&status.binding) == binding
    {
        status.last_outcome = Some(outcome);
    }
}

pub(super) fn record_initial_outcome(
    cache: &Mutex<Option<CachedStatus>>,
    binding: Option<&ActiveProviderBinding>,
    result: &Result<Option<raiun_cloudfiles_windows::ReconciliationOutcome>, String>,
) {
    let name = match result {
        Ok(Some(outcome)) => outcome_name(outcome),
        Ok(None) => return,
        Err(_) => "error",
    };
    update_last(cache, binding, name);
}
pub(super) fn record_completion_outcome(
    cache: &Mutex<Option<CachedStatus>>,
    binding: Option<&ActiveProviderBinding>,
    result: &Result<RecoveryCompletion, String>,
) {
    let name = match result {
        Ok(value) if value.local_completion == "completed" => "completed",
        Ok(value) if value.remote_verified => value.local_completion,
        Ok(value) => outcome_name(&value.outcome),
        Err(_) => "error",
    };
    update_last(cache, binding, name);
}

pub(super) fn status(agent: &WindowsAgent, state: &AccountState) -> Value {
    let unknown = || {
        json!({"state":"unknown","pending_count":null,"last_outcome":null,
        "attention_required":true,"scope":"captured_closed_ordinary_edits"})
    };
    let Ok(preference) = agent.provider.mount_preference.try_lock() else {
        return unknown();
    };
    if !*preference
        || !agent.provider.is_connected()
        || state.session.is_none()
        || state.active_generation == 0
        || state.active_generation != agent.generation.load(Ordering::Acquire)
        || state.active_generation != agent.provider.authorized_generation.load(Ordering::Acquire)
        || state.authenticating
        || state.refreshing
        || state.logout_pending
        || state.retiring
        || state.session_cleanup_uncertain
    {
        return unknown();
    }
    let Some(root) = state.root_configuration.as_ref().filter(|root| root.valid) else {
        return unknown();
    };
    let Some(session) = state.session.as_ref() else {
        return unknown();
    };
    if root.profile_scope != agent.profile_scope
        || root.server != session.server
        || root.client_id != session.client_id
    {
        return unknown();
    }
    let Ok(cache) = agent.provider.ordinary_edits.try_lock() else {
        return unknown();
    };
    let Some(cache) = cache.as_ref() else {
        return unknown();
    };
    if cache.binding.generation != state.active_generation
        || cache.binding.path != Path::new(&root.path)
        || cache.binding.identity.volume_serial != root.volume_serial
        || cache.binding.identity.file_index != root.file_index
        || root.registration_ownership.as_ref().is_none_or(|owner| {
            owner.state != "registered"
                || owner.personal_drive_id != cache.binding.personal_space_id
                || owner.personal_root_resource_id.as_deref()
                    != Some(cache.binding.personal_root_resource_id.as_str())
        })
    {
        return unknown();
    }
    let pending = if matches!(
        cache.last_outcome,
        Some("error" | "unavailable" | "uncertain")
    ) {
        None
    } else {
        cache.source.cached_pending_count()
    };
    json!({"state":if pending.is_some(){"known"}else{"unknown"},"pending_count":pending,
        "last_outcome":cache.last_outcome,"attention_required":pending.is_none_or(|count| count!=0),
        "scope":"captured_closed_ordinary_edits"})
}

impl WindowsAgent {
    pub(super) fn invalidate_headless_edit_status(&self) {
        if mount_only()
            && let Ok(mut cache) = self.provider.ordinary_edits.lock()
            && let Some(cache) = cache.as_mut()
        {
            cache.last_outcome = Some("error");
        }
    }
    /// Headless stale-request rejection must precede refresh/discovery or any
    /// remote mutation. The existing Desktop RPC contract remains unchanged.
    pub(super) fn check_headless_recovery_request(&self, request: &Value) -> Result<(), String> {
        if !mount_only() {
            return Ok(());
        }
        let expected = request
            .get("expected_generation")
            .and_then(Value::as_u64)
            .filter(|value| *value != 0)
            .ok_or("Refresh drive status before saved-edit recovery")?;
        let token = request
            .get("expected_recovery_scope_token")
            .and_then(Value::as_str)
            .filter(|token| {
                token.len() == 64
                    && token
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or("Refresh the exact Windows drive recovery scope")?;
        let configuration = {
            let state = self
                .state
                .lock()
                .map_err(|_| "Account state is unavailable")?;
            if state.active_generation != expected
                || self.generation.load(Ordering::Acquire) != expected
                || self.provider.authorized_generation.load(Ordering::Acquire) != expected
                || !state.online_authenticated
                || state.authenticating
                || state.refreshing
                || state.logout_pending
                || state.retiring
                || state.session_cleanup_uncertain
                || state.session.is_none()
            {
                return Err("The account changed; refresh saved edits before retrying".into());
            }
            let configuration = state
                .root_configuration
                .as_ref()
                .ok_or("The Windows drive is unavailable")?;
            if self
                .provider
                .configuration_recovery_scope_token(configuration, expected)
                .as_deref()
                != Ok(token)
            {
                return Err("The Windows drive recovery scope changed; refresh saved edits".into());
            }
            configuration.clone()
        };
        let identity = raiun_cloudfiles_windows::ConfiguredRootIdentity {
            volume_serial: configuration.volume_serial,
            file_index: configuration.file_index,
        };
        pin_registered_configured_root(Path::new(&configuration.path), identity)
            .map_err(|_| "The registered Windows drive changed")?;
        Ok(())
    }
}

pub(super) struct RecoveryCompletion {
    pub outcome: raiun_cloudfiles_windows::ReconciliationOutcome,
    pub remote_verified: bool,
    pub local_completion: &'static str,
}

pub(super) fn local_components(request: &Value) -> Result<Option<Vec<String>>, String> {
    let Some(value) = request.get("local_components") else {
        return Ok(None);
    };
    let components = value
        .as_array()
        .filter(|parts| !parts.is_empty() && parts.len() <= 256)
        .ok_or("Choose a bounded root-relative local path")?;
    let mut bytes = 0usize;
    let mut output = Vec::new();
    for part in components {
        let part = part
            .as_str()
            .filter(|part| {
                !part.is_empty()
                    && part.len() <= 255
                    && *part != "."
                    && *part != ".."
                    && !part.ends_with(['.', ' '])
                    && !part.chars().any(|ch| {
                        ch.is_control()
                            || matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
                    })
            })
            .ok_or("Local path components must be plain relative names")?;
        let stem = part
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        {
            return Err("Local path components cannot use Windows device names".into());
        }
        bytes = bytes
            .checked_add(part.len() + 1)
            .ok_or("Local path exceeds bound")?;
        if bytes > 32 * 1024 {
            return Err("Local path exceeds bound".into());
        }
        output.push(part.to_owned());
    }
    Ok(Some(output))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch_and_complete(
    connection: Option<&raiun_cloudfiles_windows::ConfiguredRootConnection>,
    backend: Option<&Arc<raiun_cloudfiles_windows::OpenCloudPlaceholderBackend>>,
    binding: Option<&ActiveProviderBinding>,
    generation: &AtomicU64,
    expected_generation: u64,
    recovery: &dyn raiun_cloudfiles_windows::PreparedEditRecovery,
    record_id: &str,
    record_generation: u64,
    remote: &dyn raiun_cloudfiles_windows::RecoveryRemote,
    local_components: &[String],
) -> Result<RecoveryCompletion, String> {
    let (Some(connection), Some(backend), Some(binding)) = (connection, backend, binding) else {
        return Err("Mount the exact Windows drive before completing a saved edit".into());
    };
    if expected_generation == 0
        || generation.load(Ordering::Acquire) != expected_generation
        || binding.generation != expected_generation
        || backend.is_revoked()
        || recovery.provider_scope() != backend.scope()
        || recovery.root_identity() != binding.identity
    {
        return Err("The account or Windows drive changed before saved-edit recovery".into());
    }
    let root = pin_registered_configured_root(&binding.path, binding.identity)
        .map_err(|_| "The registered Windows drive changed")?;
    if root.identity() != binding.identity {
        return Err("The registered Windows drive changed".into());
    }
    let (outcome, proof) = recovery
        .dispatch_recovered_edit_verified(
            record_id,
            record_generation,
            remote,
            raiun_cloudfiles_windows::ExplicitRecoveryApproval::user_reviewed(),
        )
        .map_err(|_| "Could not safely verify the selected recovery attempt")?;
    let Some(proof) = proof else {
        return Ok(RecoveryCompletion {
            outcome,
            remote_verified: false,
            local_completion: "unavailable",
        });
    };
    if proof.metadata().record_id != record_id
        || proof.metadata().generation != record_generation
        || generation.load(Ordering::Acquire) != expected_generation
    {
        return Err("The selected edit or account changed during recovery".into());
    }
    let scope = proof.metadata().scope.clone();
    let completed =
        backend.with_initial_edit_session_for_job(&scope, proof.recovery_job(), |session| {
            let publication = session
                .prepare_recovered_edit(&proof)
                .map_err(|_| "unavailable")?;
            if generation.load(Ordering::Acquire) != expected_generation {
                return Err("unavailable");
            }
            let components = local_components
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            connection
                .acknowledge_verified_edit(&components, &publication)
                .map_err(|_| "uncertain")?;
            if generation.load(Ordering::Acquire) != expected_generation {
                return Err("uncertain");
            }
            Ok(())
        });
    let local_completion = match completed {
        Ok(Ok(())) => "completed",
        Ok(Err("uncertain")) => "uncertain",
        _ => "unavailable",
    };
    Ok(RecoveryCompletion {
        outcome,
        remote_verified: true,
        local_completion,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_path_is_explicit_and_bounded_without_remote_path_derivation() {
        assert!(local_components(&json!({})).unwrap().is_none());
        assert_eq!(
            local_components(&json!({"local_components":["Spaces","Project","file.txt"]}))
                .unwrap()
                .unwrap(),
            ["Spaces", "Project", "file.txt"]
        );
        for invalid in [
            json!([]),
            json!([".."]),
            json!(["a/b"]),
            json!(["C:"]),
            json!(["CON.txt"]),
            json!(["name."]),
            json!(["name "]),
            json!(["a\\b"]),
            json!([1]),
        ] {
            assert!(local_components(&json!({"local_components":invalid})).is_err());
        }
    }
}

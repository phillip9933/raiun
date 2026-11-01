//! GUI-owned ordinary recovery wiring. No CLI state override or credentials.
use super::*;
use raiun_cloudfiles_windows::{
    ConfiguredRootIdentity, DurableEditRecoveryProvider, JournalError, ProviderScope,
    ReconciliationOutcome, StreamedRecoveryPolicy, streamed_store::StorePolicy,
};

pub(super) fn current_user(
    scope: ProviderScope,
    root: ConfiguredRootIdentity,
    policy: Option<&raiun_core::WindowsRecoveryPolicy>,
) -> Result<DurableEditRecoveryProvider, JournalError> {
    let (storage, transfer) = policies(policy)?;
    let mut provider = DurableEditRecoveryProvider::current_user(scope, root)?
        .with_gui_streamed_recovery_policy(storage, transfer)?;
    // Namespace admission is optional. Preserve this exact GUI provider and
    // all existing evidence if admission fails; browsing remains available.
    let _ = provider.try_enable_gui_namespace_file_rename(storage);
    Ok(provider)
}

fn policies(
    policy: Option<&raiun_core::WindowsRecoveryPolicy>,
) -> Result<(StorePolicy, StreamedRecoveryPolicy), JournalError> {
    let defaults = raiun_core::WindowsRecoveryPolicy::default();
    let policy = policy.unwrap_or(&defaults);
    policy.validate().map_err(|_| JournalError::LimitExceeded)?;
    let transfer = StreamedRecoveryPolicy::new(Duration::from_secs(policy.total_timeout_seconds))
        .map_err(|_| JournalError::LimitExceeded)?;
    Ok((
        StorePolicy {
            max_content_bytes: policy.max_file_bytes,
            max_state_bytes: policy.max_state_bytes,
            max_entries: policy.max_state_entries,
            max_metadata_bytes_per_scan: policy.max_scan_metadata_bytes,
        },
        transfer,
    ))
}

#[derive(Debug)]
pub(super) struct RecoveryCompletion {
    pub(super) outcome: ReconciliationOutcome,
    pub(super) remote_verified: bool,
    pub(super) local_completion: &'static str,
}

pub(super) struct CompletionContext<'a> {
    pub(super) connection: Option<&'a raiun_cloudfiles_windows::ConfiguredRootConnection>,
    pub(super) backend: Option<&'a Arc<raiun_cloudfiles_windows::OpenCloudPlaceholderBackend>>,
    pub(super) binding: Option<&'a ActiveProviderBinding>,
    pub(super) generation: &'a AtomicU64,
    pub(super) expected_generation: u64,
}

pub(super) fn dispatch_and_complete(
    context: CompletionContext<'_>,
    recovery: &dyn raiun_cloudfiles_windows::PreparedEditRecovery,
    record_id: &str,
    record_generation: u64,
    remote: &dyn raiun_cloudfiles_windows::RecoveryRemote,
) -> Result<RecoveryCompletion, String> {
    if context.expected_generation == 0
        || context.generation.load(Ordering::Acquire) != context.expected_generation
    {
        return Err("The account changed before recovery could start".into());
    }
    // Preserve explicit remote-only recovery when the native drive is not
    // connected. A cloud outcome alone never becomes local completion.
    let (outcome, proof) = recovery
        .dispatch_recovered_edit_verified(
            record_id,
            record_generation,
            remote,
            raiun_cloudfiles_windows::ExplicitRecoveryApproval::user_reviewed(),
        )
        .map_err(|_| "Could not safely verify the selected recovery attempt")?;
    let Some(proof) =
        proof.filter(|_| matches!(outcome, ReconciliationOutcome::VerifiedApplied { .. }))
    else {
        return Ok(RecoveryCompletion {
            outcome,
            remote_verified: false,
            local_completion: "unavailable",
        });
    };
    if proof.metadata().record_id != record_id
        || proof.metadata().generation != record_generation
        || context.generation.load(Ordering::Acquire) != context.expected_generation
    {
        return Err("The selected edit or account changed during recovery".into());
    }
    let mut result = RecoveryCompletion {
        outcome,
        remote_verified: true,
        local_completion: "unavailable",
    };
    let (Some(connection), Some(backend), Some(binding)) =
        (context.connection, context.backend, context.binding)
    else {
        return Ok(result);
    };
    if binding.generation != context.expected_generation
        || backend.is_revoked()
        || recovery.provider_scope() != backend.scope()
        || recovery.root_identity() != binding.identity
    {
        return Ok(result);
    }
    let root = pin_registered_configured_root(&binding.path, binding.identity)
        .map_err(|_| "The registered Windows drive changed")?;
    if root.identity() != binding.identity {
        return Err("The registered Windows drive changed".into());
    }
    let components = local_components(&proof.metadata().relative_path)?;
    let scope = proof.metadata().scope.clone();
    let completed =
        backend.with_initial_edit_session_for_job(&scope, proof.recovery_job(), |session| {
            let publication = session
                .prepare_recovered_edit(&proof)
                .map_err(|_| "unavailable")?;
            if context.generation.load(Ordering::Acquire) != context.expected_generation {
                return Err("unavailable");
            }
            connection
                .acknowledge_verified_edit(&components, &publication)
                .map_err(|_| "uncertain")?;
            if context.generation.load(Ordering::Acquire) != context.expected_generation {
                return Err("uncertain");
            }
            Ok(())
        });
    result.local_completion = match completed {
        Ok(Ok(())) => "completed",
        Ok(Err("uncertain")) => "uncertain",
        _ => "unavailable",
    };
    Ok(result)
}

fn local_components(path: &str) -> Result<Vec<&str>, String> {
    if path.is_empty() || path.len() > 32 * 1024 || path.contains('\\') {
        return Err("The retained local edit path is invalid".into());
    }
    let parts = path.split('/').collect::<Vec<_>>();
    if parts.len() > 256
        || parts.iter().any(|part| {
            part.is_empty()
                || matches!(*part, "." | "..")
                || part.ends_with([' ', '.'])
                || part.chars().any(|ch| {
                    ch.is_control() || matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*')
                })
                || {
                    let stem = part
                        .split('.')
                        .next()
                        .unwrap_or_default()
                        .to_ascii_uppercase();
                    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                        || (stem.len() == 4
                            && (stem.starts_with("COM") || stem.starts_with("LPT"))
                            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
                }
        })
    {
        return Err("The retained local edit path is invalid".into());
    }
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "explicit fresh-owned GUI factory fixture; no original state, accounts, mount or network"]
    fn gui_current_user_factory_isolated() {
        use raiun_cloudfiles_windows::EditRecoveryProvider;
        const TEST: &str =
            "agent_windows::windows_gui_recovery::tests::gui_current_user_factory_isolated";
        const MARKER: &[u8] = b"raiun GUI factory fixture v1\n";
        if std::env::var_os("RAIUN_GUI_FACTORY_CHILD").is_none() {
            assert_eq!(
                std::env::var("RAIUN_RUN_GUI_FACTORY").as_deref(),
                Ok("fresh-owned-state")
            );
            let mut nonce = [0u8; 16];
            getrandom::fill(&mut nonce).unwrap();
            let nonce = nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let base = std::env::temp_dir().join(format!("raiun-gui-factory-{nonce}"));
            std::fs::create_dir(&base).unwrap();
            raiun_control_windows::PinnedDirectory::open(&base).unwrap();
            let appdata = base.join("appdata");
            std::fs::create_dir(&appdata).unwrap();
            std::fs::write(base.join("fixture.marker"), MARKER).unwrap();
            for role in ["prepare", "reopen"] {
                let result = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        TEST,
                        "--ignored",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env("RAIUN_GUI_FACTORY_CHILD", role)
                    .env("RAIUN_GUI_FACTORY_BASE", &base)
                    .env("LOCALAPPDATA", &appdata)
                    .output()
                    .unwrap();
                std::fs::write(base.join(format!("{role}.stdout")), &result.stdout).unwrap();
                std::fs::write(base.join(format!("{role}.stderr")), &result.stderr).unwrap();
                assert!(
                    result.status.success(),
                    "isolated GUI factory role failed; evidence retained"
                );
                let receipt: Value = serde_json::from_slice(
                    &std::fs::read(base.join(format!("{role}.json"))).unwrap(),
                )
                .unwrap();
                assert_eq!(
                    receipt["passed"], true,
                    "child must execute and produce its scoped receipt"
                );
                assert_eq!(receipt["separate_process"], role == "reopen");
            }
            println!("gui_factory=prepare_reopen_streaming_admission_passed");
            return;
        }
        let role = std::env::var("RAIUN_GUI_FACTORY_CHILD").unwrap();
        assert!(matches!(role.as_str(), "prepare" | "reopen"));
        let base = PathBuf::from(std::env::var_os("RAIUN_GUI_FACTORY_BASE").unwrap());
        assert!(
            base.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("raiun-gui-factory-")
        );
        assert_eq!(
            base.parent().unwrap().canonicalize().unwrap(),
            std::env::temp_dir().canonicalize().unwrap()
        );
        raiun_control_windows::PinnedDirectory::open(&base).unwrap();
        assert_eq!(std::fs::read(base.join("fixture.marker")).unwrap(), MARKER);
        let appdata = base.join("appdata");
        raiun_control_windows::PinnedDirectory::open(&appdata).unwrap();
        assert_eq!(
            std::env::var_os("LOCALAPPDATA").unwrap(),
            appdata.as_os_str()
        );
        if role == "prepare" {
            assert!(!appdata.join("Raiun").exists());
        }
        let client =
            OpenCloudClient::new("https://synthetic.invalid", "synthetic-token".into()).unwrap();
        let scope = ProviderScope::new(
            &client,
            "default".into(),
            "synthetic-subject".into(),
            "https://synthetic.invalid".into(),
        )
        .unwrap();
        let root = ConfiguredRootIdentity {
            volume_serial: 1,
            file_index: 2,
        };
        let provider = current_user(scope.clone(), root, None).unwrap();
        let prepared = provider.prepare(&scope, root).unwrap();
        assert!(prepared.supports_streamed_capture());
        let job = prepared.begin_streamed_job().unwrap();
        assert!(!job.is_stopped());
        assert!(provider.unresolved_edits().unwrap().is_empty());
        let sessions = appdata.join("Raiun").join("sessions");
        let parent = raiun_control_windows::PinnedDirectory::open(&sessions).unwrap();
        raiun_control_windows::PrivateDirectory::open_under(
            &parent,
            std::ffi::OsStr::new("cloud-files-edit-journal-v2"),
        )
        .unwrap();
        std::fs::write(
            base.join(format!("{role}.json")),
            serde_json::to_vec(&json!({
                "passed":true,"streamed_capture_admitted":true,"pending_edits":0,
                "strict_v2_child":true,"separate_process":role=="reopen",
                "no_original_state_accounts_network_mount":true
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn gui_policy_preserves_validated_limits_and_rejects_invalid_before_storage() {
        let policy = raiun_core::WindowsRecoveryPolicy::default();
        let (storage, transfer) = policies(Some(&policy)).unwrap();
        assert_eq!(storage.max_content_bytes, policy.max_file_bytes);
        assert_eq!(storage.max_state_bytes, policy.max_state_bytes);
        assert_eq!(
            transfer.total_timeout().as_secs(),
            policy.total_timeout_seconds
        );
        let mut invalid = policy;
        invalid.total_timeout_seconds = 0;
        assert!(matches!(
            policies(Some(&invalid)),
            Err(JournalError::LimitExceeded)
        ));
        invalid.total_timeout_seconds = 120;
        invalid.max_file_bytes = 0;
        assert!(matches!(
            policies(Some(&invalid)),
            Err(JournalError::LimitExceeded)
        ));
    }

    #[test]
    fn retained_local_completion_paths_cannot_escape_or_use_windows_devices() {
        assert_eq!(
            local_components("Personal/notes/file.txt").unwrap(),
            ["Personal", "notes", "file.txt"]
        );
        for path in [
            "",
            "/file",
            "../file",
            "Personal//file",
            "Personal/../file",
            "C:/file",
            "Personal\\file",
            "Personal/CON.txt",
            "Personal/LPT9",
            "Personal/file.",
            "Personal/file ",
        ] {
            assert!(
                local_components(path).is_err(),
                "invalid synthetic path accepted"
            );
        }
    }
}

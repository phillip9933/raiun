//! One policy mapping for fresh mounts and restored recovery contexts.
use raiun_cloudfiles_windows::{
    ConfiguredRootIdentity, DurableEditRecoveryProvider, ProviderScope, StreamedRecoveryPolicy,
    streamed_store::StorePolicy,
};
use raiun_core::WindowsRecoveryPolicy;
use std::time::Duration;

// Keep production activation separate from parsing settings and native
// diagnostic opt-ins until the shared pipeline/deployment gates are accepted.
const WINDOWS_STREAMED_RECOVERY_ENABLED: bool = false;

struct Settings {
    storage: StorePolicy,
    transfer: StreamedRecoveryPolicy,
}

fn map_settings(policy: &WindowsRecoveryPolicy) -> Result<Settings, String> {
    policy.validate().map_err(str::to_owned)?;
    Ok(Settings {
        storage: StorePolicy {
            max_content_bytes: policy.max_file_bytes,
            max_state_bytes: policy.max_state_bytes,
            max_entries: policy.max_state_entries,
            max_metadata_bytes_per_scan: policy.max_scan_metadata_bytes,
        },
        transfer: StreamedRecoveryPolicy::new(Duration::from_secs(policy.total_timeout_seconds))
            .map_err(|_| "The Windows recovery transfer allowance is invalid".to_owned())?,
    })
}

fn configured_settings(headless: bool) -> Result<Settings, String> {
    // Desktop never reads the separate headless configuration or environment.
    let policy = if headless {
        crate::headless_runtime::config()?
            .and_then(|config| config.windows_recovery.clone())
            .unwrap_or_default()
    } else {
        WindowsRecoveryPolicy::default()
    };
    map_settings(&policy)
}

pub(super) fn directory_storage_policy() -> Result<StorePolicy, String> {
    Ok(configured_settings(super::mount_only())?.storage)
}

pub(super) fn provider(
    scope: ProviderScope,
    root: ConfiguredRootIdentity,
) -> Result<DurableEditRecoveryProvider, String> {
    let headless = super::mount_only();
    let settings = configured_settings(headless)?;
    let provider = DurableEditRecoveryProvider::current_user(scope, root)
        .map_err(|_| "Protected recovery storage is unavailable".to_owned())?;
    let storage = settings.storage;
    let mut provider = if WINDOWS_STREAMED_RECOVERY_ENABLED {
        activate(provider, settings, headless)
            .map_err(|_| "Configured Windows recovery storage could not be admitted".to_owned())?
    } else {
        provider
    };
    // Optional namespace support never replaces the original provider after a
    // refusal. The mount caller surfaces unavailable without declaring clean.
    let _ = if headless {
        provider.try_enable_modern_namespace_file_rename(storage)
    } else {
        provider.try_enable_gui_namespace_file_rename(storage)
    };
    Ok(provider)
}

fn activate(
    provider: DurableEditRecoveryProvider,
    settings: Settings,
    headless: bool,
) -> Result<DurableEditRecoveryProvider, raiun_cloudfiles_windows::JournalError> {
    if headless {
        provider.with_streamed_recovery_policy(settings.storage, settings.transfer)
    } else {
        provider.with_gui_streamed_recovery_policy(settings.storage, settings.transfer)
    }
}

// Only the separately guarded native fixture calls this. Configuration cannot
// enable this entry point in a production agent.
#[cfg(all(test, debug_assertions))]
pub(super) fn activate_for_diagnostic(
    provider: DurableEditRecoveryProvider,
) -> Result<DurableEditRecoveryProvider, raiun_cloudfiles_windows::JournalError> {
    let headless = super::mount_only();
    let settings = configured_settings(headless)
        .map_err(|_| raiun_cloudfiles_windows::JournalError::InvalidScope)?;
    activate(provider, settings, headless)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_maps_storage_and_total_budget_without_starting_a_job() {
        let policy = WindowsRecoveryPolicy {
            max_file_bytes: 2 * 1024 * 1024 * 1024,
            max_state_bytes: 16 * 1024 * 1024 * 1024,
            max_state_entries: 4000,
            max_scan_metadata_bytes: 8 * 1024 * 1024,
            total_timeout_seconds: 86_400,
        };
        let settings = map_settings(&policy).unwrap();
        assert_eq!(settings.storage.max_content_bytes, policy.max_file_bytes);
        assert_eq!(settings.storage.max_state_bytes, policy.max_state_bytes);
        assert_eq!(settings.storage.max_entries, policy.max_state_entries);
        assert_eq!(
            settings.storage.max_metadata_bytes_per_scan,
            policy.max_scan_metadata_bytes
        );
        assert_eq!(
            settings.transfer.total_timeout(),
            Duration::from_secs(86_400)
        );
        let invalid = WindowsRecoveryPolicy {
            total_timeout_seconds: 0,
            ..policy
        };
        assert!(map_settings(&invalid).is_err());
    }
}

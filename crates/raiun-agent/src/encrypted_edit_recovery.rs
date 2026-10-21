//! Redacted, read-only inventory of local encrypted-file working copies.
//!
//! This module never opens working-copy bytes, replays records, or removes them.

use raiun_fuse::vault_write::{PendingVaultWrite, VaultWriteLifecycle, VaultWriteSpool};
use serde::Serialize;
use std::path::Path;

const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 100;
const MAX_SCAN: usize = 10_000;

pub(super) fn empty_page(limit: Option<usize>) -> Result<Page, String> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    if limit == 0 {
        return Err("limit must be between 1 and 100".into());
    }
    Ok(Page {
        items: Vec::new(),
        next_after: None,
        scanned_entries: 0,
        warning_count: 0,
        truncated: false,
        counts: Counts::default(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LocalState {
    Building,
    Pending,
    Uncertain,
    Committed,
    Clean,
    Corrupt,
}

#[derive(Debug, Clone, Serialize)]
struct Item {
    record_id: Option<String>,
    bytes: Option<u64>,
    state: LocalState,
    warning: Option<&'static str>,
}

#[derive(Debug, Default, Clone, Serialize)]
struct Counts {
    building: usize,
    pending: usize,
    uncertain: usize,
    committed: usize,
    clean: usize,
    corrupt: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct Page {
    items: Vec<Item>,
    next_after: Option<String>,
    scanned_entries: usize,
    warning_count: usize,
    truncated: bool,
    counts: Counts,
}

fn safe_record_id(id: &str) -> Option<String> {
    let suffix = id.strip_prefix("raiun-vault-write-")?;
    if id.len() <= 128
        && !suffix.is_empty()
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        Some(id.to_owned())
    } else {
        None
    }
}

fn project(entry: PendingVaultWrite, profile_id: &str, server_origin: Option<&str>) -> Item {
    let mut warning = None;
    let state = match (
        entry.warning,
        entry.scope.as_ref(),
        entry.target.as_ref(),
        entry.lifecycle.as_ref(),
    ) {
        (None, Some(scope), Some(_), Some(lifecycle)) => {
            if scope.account_id() != profile_id
                || server_origin.is_none_or(|origin| scope.server_origin() != origin)
            {
                warning = Some("This saved copy does not match the selected account and server.");
                LocalState::Uncertain
            } else {
                match lifecycle {
                    VaultWriteLifecycle::Initializing => {
                        warning = Some("This saved copy may still be active or may need review.");
                        LocalState::Uncertain
                    }
                    VaultWriteLifecycle::CleanBaseline { .. } => LocalState::Clean,
                    VaultWriteLifecycle::Dirty => {
                        warning =
                            Some("Editing or awaiting upload; this copy may still be active.");
                        LocalState::Pending
                    }
                    VaultWriteLifecycle::BuildingCreate { .. } => {
                        warning = Some(
                            "A new encrypted file is reserved; its first content revision is not published yet.",
                        );
                        LocalState::Building
                    }
                    VaultWriteLifecycle::DirtyBuildingCreate { .. } => {
                        warning = Some(
                            "A new encrypted file has local edits that are not yet published as a retryable revision.",
                        );
                        LocalState::Pending
                    }
                    VaultWriteLifecycle::RetargetingCreate { .. } => {
                        warning = Some(
                            "A queued encrypted file rename was interrupted; the local copy is retained pending exact operation verification.",
                        );
                        LocalState::Uncertain
                    }
                    VaultWriteLifecycle::CancelPendingCreate { .. } => {
                        warning = Some(
                            "A queued encrypted file cancellation is awaiting exact journal confirmation; the local copy is retained.",
                        );
                        LocalState::Uncertain
                    }
                    VaultWriteLifecycle::DirtyQueued { uncertain, .. } => {
                        warning = Some(if *uncertain {
                            "Encrypted edit changed after a queued revision; the server may have received the earlier update."
                        } else {
                            "Encrypted edit changed locally after a queued revision and awaits upload."
                        });
                        if *uncertain {
                            LocalState::Uncertain
                        } else {
                            LocalState::Pending
                        }
                    }
                    VaultWriteLifecycle::Committed { .. } => {
                        warning =
                            Some("Upload previously recorded. Server status has not been checked.");
                        LocalState::Committed
                    }
                    VaultWriteLifecycle::Queued { uncertain, .. } => {
                        warning = Some(if *uncertain {
                            "Encrypted edit is queued; the server may have received an update."
                        } else {
                            "Encrypted edit is saved locally and awaiting explicit reconciliation."
                        });
                        if *uncertain {
                            LocalState::Uncertain
                        } else {
                            LocalState::Pending
                        }
                    }
                }
            }
        }
        _ => {
            warning = Some("This saved copy needs review; its metadata could not be verified.");
            LocalState::Corrupt
        }
    };
    Item {
        record_id: safe_record_id(&entry.record_id),
        bytes: entry.bytes,
        state,
        warning,
    }
}

pub(super) fn list(
    profile_state_dir: &Path,
    profile_id: &str,
    server_origin: Option<&str>,
    after: Option<&str>,
    limit: Option<usize>,
) -> Result<Page, String> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    if limit == 0 {
        return Err("limit must be between 1 and 100".into());
    }
    let spool = VaultWriteSpool::open_existing(profile_state_dir)
        .map_err(|_| "Could not safely inspect saved encrypted-file edits".to_owned())?;
    let Some(spool) = spool else {
        return empty_page(Some(limit));
    };
    let (records, truncated) = spool
        .list_pending()
        .map_err(|_| "Could not safely inspect saved encrypted-file edits".to_owned())?;
    let offset = match after {
        None | Some("") => 0,
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| "after must be a numeric cursor")?,
    };
    if offset > records.len() || offset > MAX_SCAN {
        return Err("after cursor is outside the saved-copy list".into());
    }
    let projected: Vec<_> = records
        .into_iter()
        .map(|entry| project(entry, profile_id, server_origin))
        .collect();
    let mut counts = Counts::default();
    let mut warning_count = 0;
    for item in &projected {
        match item.state {
            LocalState::Building => counts.building += 1,
            LocalState::Pending => counts.pending += 1,
            LocalState::Uncertain => counts.uncertain += 1,
            LocalState::Committed => counts.committed += 1,
            LocalState::Clean => counts.clean += 1,
            LocalState::Corrupt => counts.corrupt += 1,
        }
        if item.warning.is_some() || item.record_id.is_none() {
            warning_count += 1;
        }
    }
    let end = offset.saturating_add(limit).min(projected.len());
    let items = projected[offset..end].to_vec();
    let next_after = (end < projected.len()).then(|| end.to_string());
    Ok(Page {
        items,
        next_after,
        scanned_entries: projected.len(),
        warning_count,
        truncated,
        counts,
    })
}

pub(super) fn existing_root(
    profile_state_dir: &Path,
) -> Result<Option<std::path::PathBuf>, String> {
    let spool = VaultWriteSpool::open_existing(profile_state_dir)
        .map_err(|_| "Could not safely open the saved encrypted-file edits folder".to_owned())?;
    Ok(spool.map(|spool| spool.root().to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use raiun_core::backend::WriteCondition;
    use raiun_fuse::vault_write::{VaultParentRef, VaultWriteScope, VaultWriteTarget};
    use serde_json::json;

    fn record(account: &str, origin: &str, lifecycle: VaultWriteLifecycle) -> PendingVaultWrite {
        PendingVaultWrite {
            record_id: "raiun-vault-write-test-record".into(),
            scope: Some(
                VaultWriteScope::new(account, origin, "space-secret", "root-secret").unwrap(),
            ),
            target: Some(
                VaultWriteTarget::new("opaque/secret-name", WriteCondition::Absent).unwrap(),
            ),
            bytes: Some(12),
            lifecycle: Some(lifecycle),
            warning: None,
        }
    }

    #[test]
    fn profile_or_origin_mismatch_is_uncertain_and_never_exposes_remote_metadata() {
        let item = project(
            record(
                "account-a",
                "https://cloud.example",
                VaultWriteLifecycle::Dirty,
            ),
            "account-b",
            Some("https://cloud.example"),
        );
        assert_eq!(item.state, LocalState::Uncertain);
        let text = serde_json::to_string(&item).unwrap();
        assert!(!text.contains("cloud.example"));
        assert!(!text.contains("space-secret"));
        assert!(!text.contains("root-secret"));
        assert!(!text.contains("opaque/secret-name"));
    }

    #[test]
    fn committed_means_only_local_upload_recorded_evidence() {
        let item = project(
            record(
                "account-a",
                "https://cloud.example",
                VaultWriteLifecycle::Committed {
                    bytes: 12,
                    sha256: "secret-hash".into(),
                    etag: "secret-etag".into(),
                },
            ),
            "account-a",
            Some("https://cloud.example"),
        );
        assert_eq!(item.state, LocalState::Committed);
        assert!(
            item.warning
                .unwrap()
                .contains("Server status has not been checked")
        );
        let value = json!(item).to_string();
        assert!(!value.contains("secret-hash"));
        assert!(!value.contains("secret-etag"));
    }

    #[test]
    fn interrupted_retarget_is_visible_as_unresolved_recovery() {
        let item = project(
            record(
                "account-a",
                "https://cloud.example",
                VaultWriteLifecycle::RetargetingCreate {
                    write_id: "a".repeat(32),
                    previous_revision: 4,
                    destination_path: "/folder/renamed.txt".into(),
                    destination: VaultWriteTarget::new_with_parent(
                        "opaque/new-name",
                        WriteCondition::Absent,
                        VaultParentRef::pending_create("b".repeat(32), 2).unwrap(),
                    )
                    .unwrap(),
                    bytes: 12,
                    sha256: "a".repeat(64),
                },
            ),
            "account-a",
            Some("https://cloud.example"),
        );
        assert_eq!(item.state, LocalState::Uncertain);
        assert!(item.warning.unwrap().contains("rename was interrupted"));
    }

    #[test]
    fn missing_spool_is_reported_empty_without_creating_local_state() {
        let state = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let page = list(state.path(), "account-a", None, None, None).unwrap();
        assert!(page.items.is_empty());
        assert_eq!(page.scanned_entries, 0);
        assert!(!state.path().join("raiun-vault-write").exists());
    }
}

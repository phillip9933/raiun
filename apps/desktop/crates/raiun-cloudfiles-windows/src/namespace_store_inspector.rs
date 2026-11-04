#![cfg(windows)]

use crate::{
    DpapiEditRecordProtector,
    namespace_intent::{NamespaceAttention, NamespacePhase},
    namespace_store::{NamespaceHistoryReader, StoredDirectoryIntent},
    streamed_store::StorePolicy,
};
use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashSet},
    ffi::OsStr,
    fs,
    io::Read,
    os::windows::fs::MetadataExt,
    path::Path,
    sync::Arc,
};

const OWNER: &[u8] = b"raiun-headless-automatic-directory-v1\n";
const V2_ROOT: &str = "cloud-files-edit-journal-v2";
const QUOTA_LOCK: &str = "quota.lock";
const NAMESPACE_ROOT: &str = "namespace-v1";
const MAX_ENTRIES: usize = 4096;
const MAX_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Default)]
struct Budget {
    entries: usize,
    bytes: u64,
}

/// Inspect one exact, already-retained headless fixture through existing-only
/// directory capabilities. The returned value contains no paths or identifiers.
pub(super) fn inspect_existing_fixture(fixture: &Path) -> Result<Value, &'static str> {
    let fixture_pin = PinnedDirectory::open(fixture).map_err(|_| "fixture_unavailable")?;
    let (mut owner_file, _) = fixture_pin
        .open_immutable_regular_file(OsStr::new("OWNER.txt"))
        .map_err(|_| "owner_unavailable")?;
    let mut owner = Vec::new();
    owner_file
        .by_ref()
        .take((OWNER.len() + 1) as u64)
        .read_to_end(&mut owner)
        .map_err(|_| "owner_read_failed")?;
    if owner != OWNER {
        return Err("owner_marker_mismatch");
    }

    let state = Arc::new(
        PrivateDirectory::open_under(&fixture_pin, OsStr::new("state"))
            .map_err(|_| "state_unavailable")?,
    );
    let state_pin = PinnedDirectory::open(state.path()).map_err(|_| "state_pin_failed")?;
    let sessions = Arc::new(
        PrivateDirectory::open_under(&state_pin, OsStr::new("sessions"))
            .map_err(|_| "sessions_unavailable")?,
    );
    state.verify_path().map_err(|_| "state_pin_changed")?;
    sessions.verify_path().map_err(|_| "sessions_pin_changed")?;

    let protector = Arc::new(
        DpapiEditRecordProtector::from_existing_private_directory(Arc::clone(&sessions))
            .map_err(|_| "dpapi_unavailable")?,
    );
    let reader = NamespaceHistoryReader::open_existing(
        Arc::clone(&sessions),
        protector,
        StorePolicy {
            max_content_bytes: 32 * 1024 * 1024,
            max_state_bytes: 64 * 1024 * 1024,
            max_entries: 2000,
            max_metadata_bytes_per_scan: 8 * 1024 * 1024,
        },
    )
    .map_err(|error| store_error_class(&error))?;

    let cloud_root =
        PinnedDirectory::open(&fixture.join("cloud-root")).map_err(|_| "cloud_root_unavailable")?;
    let cloud_identity = cloud_root.identity();
    let v2 = Arc::new(
        PrivateDirectory::open_under(
            &PinnedDirectory::open(sessions.path()).map_err(|_| "sessions_pin_failed")?,
            OsStr::new(V2_ROOT),
        )
        .map_err(|_| "v2_root_unavailable")?,
    );
    let before = digest_namespace_tree(&v2)?;

    let scopes = match reader.discover_scopes() {
        Ok(scopes) => scopes,
        Err(error) => {
            return failure_observation(
                "scope_discovery",
                store_error_class(&error),
                None,
                None,
                &v2,
                before,
                &state,
                &sessions,
                &cloud_root,
            );
        }
    };
    let matching: Vec<_> = scopes
        .iter()
        .filter(|scope| {
            scope.profile_id == "default"
                && scope.root_volume_serial == cloud_identity.volume_serial
                && scope.root_file_index == cloud_identity.file_index
        })
        .collect();
    let groups: HashSet<_> = matching
        .iter()
        .map(|scope| {
            (
                scope.profile_id.as_str(),
                scope.server_origin.as_str(),
                scope.account_subject.as_str(),
                scope.root_volume_serial,
                scope.root_file_index,
            )
        })
        .collect();
    if groups.len() != 1 {
        return observation(
            if groups.is_empty() {
                "scope_not_found"
            } else {
                "scope_ambiguous"
            },
            Some(scopes.len()),
            Some(groups.len()),
            before,
            &v2,
            &state,
            &sessions,
            &cloud_root,
            None,
        );
    }
    let seed = matching.first().ok_or("scope_not_found")?;
    let records = match reader.discover_account_root(seed) {
        Ok(records) => records,
        Err(error) => {
            return failure_observation(
                "history_discovery",
                store_error_class(&error),
                Some(scopes.len()),
                Some(groups.len()),
                &v2,
                before,
                &state,
                &sessions,
                &cloud_root,
            );
        }
    };
    observation(
        "observed",
        Some(scopes.len()),
        Some(groups.len()),
        before,
        &v2,
        &state,
        &sessions,
        &cloud_root,
        Some(&records),
    )
}

#[allow(clippy::too_many_arguments)] // Explicit retained pins; this test-only helper has no authority.
fn observation(
    status: &'static str,
    scope_count: Option<usize>,
    matching_group_count: Option<usize>,
    before: [u8; 32],
    v2: &Arc<PrivateDirectory>,
    state: &Arc<PrivateDirectory>,
    sessions: &Arc<PrivateDirectory>,
    cloud_root: &PinnedDirectory,
    records: Option<&[StoredDirectoryIntent]>,
) -> Result<Value, &'static str> {
    let after = digest_namespace_tree(v2)?;
    let state_pin_valid = state.verify_path().is_ok();
    let sessions_pin_valid = sessions.verify_path().is_ok();
    let cloud_root_pin_valid = cloud_root.verify_path().is_ok();
    if !state_pin_valid || !sessions_pin_valid || !cloud_root_pin_valid || before != after {
        return Err("evidence_changed");
    }
    let progress = records.map(|records| {
        records
            .iter()
            .map(|record| {
                json!({
                    "sequence": record.progress.sequence,
                    "remote": phase_name(record.progress.remote),
                    "attention": attention_name(record.progress.attention),
                    "local_completed": record.progress.local_completed,
                    "recorded_complete": record.progress.recorded_complete,
                    "source_removal": record.progress.source_removal.map(phase_name),
                })
            })
            .collect::<Vec<_>>()
    });
    Ok(json!({
        "fixture": "headless-automatic-directory-v1",
        "status": status,
        "read_only": true,
        "owner_marker_valid": true,
        "existing_state_sessions_pinned": state_pin_valid && sessions_pin_valid,
        "scope_count": scope_count,
        "matching_account_root_group_count": matching_group_count,
        "root_identity_matches": matching_group_count.map(|count| count == 1 && cloud_root_pin_valid),
        "runtime_config_path_reverified": false,
        "record_count": records.map(|records| records.len()),
        "progress": progress,
        "v2_metadata_unchanged": before == after,
        "cloud_root_reverified_without_enumeration": cloud_root_pin_valid,
        "network_used": false,
        "provider_used": false,
        "limitations": ["runtime root-config selection was not independently revalidated"]
    }))
}

#[allow(clippy::too_many_arguments)] // Keep failure observations tied to the same explicit pins.
fn failure_observation(
    stage: &'static str,
    class: &'static str,
    scope_count: Option<usize>,
    matching_group_count: Option<usize>,
    v2: &Arc<PrivateDirectory>,
    before: [u8; 32],
    state: &Arc<PrivateDirectory>,
    sessions: &Arc<PrivateDirectory>,
    cloud_root: &PinnedDirectory,
) -> Result<Value, &'static str> {
    let mut value = observation(
        "history_unavailable",
        scope_count,
        matching_group_count,
        before,
        v2,
        state,
        sessions,
        cloud_root,
        None,
    )?;
    value["failure_stage"] = json!(stage);
    value["failure_class"] = json!(class);
    Ok(value)
}

fn phase_name(phase: NamespacePhase) -> &'static str {
    match phase {
        NamespacePhase::Pending => "pending",
        NamespacePhase::Submitted => "submitted",
        NamespacePhase::Verified => "verified",
    }
}

fn attention_name(attention: Option<NamespaceAttention>) -> &'static str {
    match attention {
        None => "none",
        Some(NamespaceAttention::Conflict) => "conflict",
        Some(NamespaceAttention::Deferred) => "deferred",
        Some(NamespaceAttention::Uncertain) => "uncertain",
    }
}

fn store_error_class(error: &crate::streamed_store::StoreError) -> &'static str {
    use crate::streamed_store::StoreError;
    match error {
        StoreError::Busy => "busy",
        StoreError::IncompleteEvidence => "incomplete_evidence",
        StoreError::Io => "io",
        StoreError::Invalid => "invalid",
        StoreError::Quota => "quota",
        StoreError::ScanLimit => "scan_limit",
        StoreError::CorruptEvidence => "corrupt_evidence",
        StoreError::PublicationUncertain => "publication_uncertain",
        StoreError::Snapshot(_) => "snapshot",
    }
}

fn digest_namespace_tree(root: &Arc<PrivateDirectory>) -> Result<[u8; 32], &'static str> {
    let mut budget = Budget::default();
    let mut hash = Sha256::new();
    let names = list_names(root, &mut budget)?;
    if names
        .iter()
        .any(|name| name != QUOTA_LOCK && name != NAMESPACE_ROOT)
    {
        return Err("unsupported_layout");
    }
    for name in names {
        match name.as_str() {
            QUOTA_LOCK => hash_file(root, &name, &mut budget, &mut hash)?,
            NAMESPACE_ROOT => {
                let child = open_private_child(root, &name)?;
                hash.update(b"D\0namespace-v1\0");
                hash_namespace(&child, &mut budget, &mut hash)?;
            }
            _ => return Err("unsupported_layout"),
        }
    }
    root.verify_path().map_err(|_| "pin_changed")?;
    Ok(hash.finalize().into())
}

fn hash_namespace(
    namespace: &Arc<PrivateDirectory>,
    budget: &mut Budget,
    hash: &mut Sha256,
) -> Result<(), &'static str> {
    let names = list_names(namespace, budget)?;
    let set: HashSet<_> = names.iter().map(String::as_str).collect();
    let mut keys = BTreeSet::new();
    for name in &names {
        if let Some(key) = name.strip_suffix(".scope") {
            if !valid_key(key) || !set.contains(key) {
                return Err("unsupported_layout");
            }
            keys.insert(key.to_owned());
            hash_file(namespace, name, budget, hash)?;
        } else if valid_key(name) {
            if !set.contains(format!("{name}.scope").as_str()) {
                return Err("unsupported_layout");
            }
            keys.insert(name.clone());
            let child = open_private_child(namespace, name)?;
            hash.update(b"D\0");
            hash.update(name.as_bytes());
            hash.update(b"\0");
            hash_record_directory(&child, budget, hash)?;
        } else {
            return Err("unsupported_layout");
        }
    }
    if keys.len() > 256 {
        return Err("scan_limit");
    }
    namespace.verify_path().map_err(|_| "pin_changed")?;
    Ok(())
}

fn hash_record_directory(
    directory: &Arc<PrivateDirectory>,
    budget: &mut Budget,
    hash: &mut Sha256,
) -> Result<(), &'static str> {
    let names = list_names(directory, budget)?;
    let mut intent_ids = HashSet::new();
    let mut dependent_ids = HashSet::new();
    for name in &names {
        if let Some(id) = name.strip_suffix(".intent") {
            if !valid_id(id) {
                return Err("unsupported_layout");
            }
            intent_ids.insert(id.to_owned());
            hash_file(directory, name, budget, hash)?;
        } else if let Some(id) = name.strip_suffix(".dispatch.lock") {
            if !valid_id(id) {
                return Err("unsupported_layout");
            }
            dependent_ids.insert(id.to_owned());
            hash_file(directory, name, budget, hash)?;
        } else if let Some((id, sequence)) = name.split_once(".event.") {
            if !valid_id(id) || super::parse_event(&format!("event.{sequence}")).is_none() {
                return Err("unsupported_layout");
            }
            dependent_ids.insert(id.to_owned());
            hash_file(directory, name, budget, hash)?;
        } else {
            return Err("unsupported_layout");
        }
    }
    if dependent_ids.iter().any(|id| !intent_ids.contains(id)) {
        return Err("unsupported_layout");
    }
    directory.verify_path().map_err(|_| "pin_changed")?;
    Ok(())
}

fn list_names(
    directory: &Arc<PrivateDirectory>,
    budget: &mut Budget,
) -> Result<Vec<String>, &'static str> {
    directory.verify_path().map_err(|_| "pin_changed")?;
    let remaining = MAX_ENTRIES.saturating_sub(budget.entries);
    let mut names = fs::read_dir(directory.path())
        .map_err(|_| "metadata_io")?
        .take(remaining.saturating_add(1))
        .map(|entry| {
            entry
                .map_err(|_| "metadata_io")?
                .file_name()
                .into_string()
                .map_err(|_| "unsupported_layout")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if names.len() > remaining {
        return Err("scan_limit");
    }
    budget.entries = budget
        .entries
        .checked_add(names.len())
        .ok_or("scan_limit")?;
    names.sort();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("unsupported_layout");
    }
    directory.verify_path().map_err(|_| "pin_changed")?;
    Ok(names)
}

fn open_private_child(
    parent: &Arc<PrivateDirectory>,
    name: &str,
) -> Result<Arc<PrivateDirectory>, &'static str> {
    parent.verify_path().map_err(|_| "pin_changed")?;
    let parent_pin = PinnedDirectory::open(parent.path()).map_err(|_| "pin_changed")?;
    PrivateDirectory::open_under(&parent_pin, OsStr::new(name))
        .map(Arc::new)
        .map_err(|_| "unsupported_layout")
}

fn hash_file(
    directory: &Arc<PrivateDirectory>,
    name: &str,
    budget: &mut Budget,
    hash: &mut Sha256,
) -> Result<(), &'static str> {
    let mut file = directory
        .open_owned_immutable_file(OsStr::new(name))
        .map_err(|_| "unsupported_layout")?;
    let metadata = file.metadata().map_err(|_| "metadata_io")?;
    let length = metadata.len();
    if length > MAX_BYTES.saturating_sub(budget.bytes) {
        return Err("scan_limit");
    }
    let identity = file.identity();
    hash.update(b"F\0");
    hash.update((name.len() as u64).to_le_bytes());
    hash.update(name.as_bytes());
    hash.update(length.to_le_bytes());
    hash.update(identity.volume_serial.to_le_bytes());
    hash.update(identity.file_index.to_le_bytes());
    hash.update(metadata.file_attributes().to_le_bytes());
    hash.update(metadata.creation_time().to_le_bytes());
    hash.update(metadata.last_write_time().to_le_bytes());
    let mut bytes_read = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let count = file.read(&mut buffer).map_err(|_| "metadata_io")?;
        if count == 0 {
            break;
        }
        bytes_read = bytes_read.checked_add(count as u64).ok_or("scan_limit")?;
        budget.bytes = budget.bytes.checked_add(count as u64).ok_or("scan_limit")?;
        if bytes_read > length || budget.bytes > MAX_BYTES {
            return Err("scan_limit");
        }
        hash.update(&buffer[..count]);
    }
    if bytes_read != length {
        return Err("metadata_changed");
    }
    file.verify().map_err(|_| "pin_changed")?;
    Ok(())
}

fn valid_key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

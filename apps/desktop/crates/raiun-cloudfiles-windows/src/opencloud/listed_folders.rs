//! Bounded read-only pages of the active authenticated ordinary-directory catalog.
use super::{
    BackendError, CancellationToken, DirectoryBinding, FolderCacheBindingExpectation,
    OpaqueIdentity, OpenCloudPlaceholderBackend, check_cancel,
};
use raiun_cache::{CacheScope, ScopeProtection};
use serde::Serialize;
use std::collections::HashMap;

const PAGE_CANDIDATE_LIMIT: usize = 8;
const PAGE_SERIALIZED_BYTE_LIMIT: usize = 128 * 1024;
const SPACE_ID_BYTE_LIMIT: usize = 512;
const FOLDER_FIELD_BYTE_LIMIT: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedFolderIntentState {
    None,
    Known,
    Unknown,
    Unavailable,
    RecoveryRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SavedFolderIntent {
    pub state: SavedFolderIntentState,
    pub active_pin_id: Option<String>,
    pub staging_pin_id: Option<String>,
    pub staging_is_initial: bool,
}

impl SavedFolderIntent {
    fn empty(state: SavedFolderIntentState) -> Self {
        Self {
            state,
            active_pin_id: None,
            staging_pin_id: None,
            staging_is_initial: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ListedFolderRow {
    pub space_id: String,
    pub root_resource_id: String,
    pub path: String,
    pub resource_id: String,
    pub space_label: String,
    pub saved_intent: SavedFolderIntent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ListedFolderPage {
    pub rows: Vec<ListedFolderRow>,
    pub next_cursor: Option<String>,
    pub unavailable_rows: usize,
    pub read_only: bool,
    pub last_observed: bool,
    pub atomic_snapshot: bool,
}

impl OpenCloudPlaceholderBackend {
    // Display/reconciliation metadata only. The page's active lease/auth scope
    // and every later job's fresh binding checks still govern all operations.
    fn saved_folder_intent(&self, binding: &DirectoryBinding) -> SavedFolderIntent {
        let Some(cache) = &self.cache else {
            return SavedFolderIntent::empty(SavedFolderIntentState::Unavailable);
        };
        let Ok(scope) = CacheScope::new(
            self.scope.server_origin(),
            self.scope.account_id(),
            &binding.space_id,
            &binding.root_resource_id,
            ScopeProtection::PlaintextAllowed,
        ) else {
            return SavedFolderIntent::empty(SavedFolderIntentState::Unavailable);
        };
        let Ok(intent) = cache.folder_pin_intent(&scope, &binding.remote_id, &binding.path) else {
            return SavedFolderIntent::empty(SavedFolderIntentState::Unavailable);
        };
        if intent.has_unknown_pins {
            return SavedFolderIntent::empty(SavedFolderIntentState::Unknown);
        }
        let Some(roles) = intent.roles else {
            return SavedFolderIntent::empty(SavedFolderIntentState::None);
        };
        // Keep the public page's opaque-ID contract narrow even if local
        // metadata has been corrupted. Never publish a forged role as an action.
        if [roles.active_pin_id.as_ref(), roles.staging_pin_id.as_ref()]
            .into_iter()
            .flatten()
            .any(|id| {
                id.len() != 64
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return SavedFolderIntent::empty(SavedFolderIntentState::Unavailable);
        }
        let state = if roles.active_pin_id.is_none() && !roles.staging_is_initial {
            SavedFolderIntentState::RecoveryRequired
        } else {
            SavedFolderIntentState::Known
        };
        SavedFolderIntent {
            state,
            active_pin_id: roles.active_pin_id,
            staging_pin_id: roles.staging_pin_id,
            staging_is_initial: roles.staging_is_initial,
        }
    }

    /// Return a bounded page from this active backend's already authenticated
    /// catalog of ordinary directories. This performs no HTTP request,
    /// content read, identity creation, or namespace mutation.
    pub fn listed_folder_page(
        &self,
        cursor: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<ListedFolderPage, BackendError> {
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        check_cancel(cancellation)?;
        self.ensure_active()?;
        self.catalog_scope_snapshot()?
            .ok_or(BackendError::Unavailable)?;
        let cursor_identity = cursor.map(parse_cursor).transpose()?;

        let (candidates, more_candidates) = {
            let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
            if let Some(cursor) = cursor_identity
                && !state.directories.contains_key(&cursor)
            {
                return Err(BackendError::NotFound);
            }
            select_candidates(&state.directories, cursor_identity, cancellation)?
        };

        let mut rows = Vec::with_capacity(candidates.len());
        let mut unavailable_rows = 0usize;
        let mut last_processed: Option<OpaqueIdentity> = None;
        let mut stopped_at_budget = false;

        for (identity, snapshot) in candidates.iter() {
            check_cancel(cancellation)?;
            self.ensure_active()?;
            if !representable(snapshot) {
                unavailable_rows = unavailable_rows.saturating_add(1);
                last_processed = Some(*identity);
                continue;
            }

            // Resolve the complete tuple again so stale or ambiguous catalog
            // entries are omitted instead of exposing invented folder rows.
            let expected = FolderCacheBindingExpectation {
                space_id: &snapshot.space_id,
                root_resource_id: &snapshot.root_resource_id,
                path: &snapshot.path,
                resource_id: &snapshot.remote_id,
            };
            match self.resolve_folder_binding(&expected, cancellation) {
                Ok((resolved_identity, binding))
                    if resolved_identity == *identity && binding == *snapshot =>
                {
                    let label = self
                        .state
                        .lock()
                        .map_err(|_| BackendError::Unavailable)?
                        .location_labels
                        .get(&(binding.space_id.clone(), binding.root_resource_id.clone()))
                        .cloned();
                    let Some(label) = label else {
                        // Identity-only catalog restoration cannot invent a
                        // friendly location. Omit it until namespace discovery
                        // supplies a validated label instead of showing
                        // indistinguishable roots to the user.
                        unavailable_rows = unavailable_rows.saturating_add(1);
                        last_processed = Some(*identity);
                        continue;
                    };
                    let intent = self.saved_folder_intent(&binding);
                    let mut candidate = row_from_binding(binding, label);
                    candidate.saved_intent = intent;
                    let mut trial_rows = rows.clone();
                    trial_rows.push(candidate.clone());
                    let trial = ListedFolderPage {
                        rows: trial_rows,
                        next_cursor: Some(encode_cursor(*identity)),
                        unavailable_rows,
                        read_only: true,
                        last_observed: true,
                        atomic_snapshot: false,
                    };
                    if serialized_len(&trial)? > PAGE_SERIALIZED_BYTE_LIMIT {
                        if rows.is_empty() {
                            unavailable_rows = unavailable_rows.saturating_add(1);
                            last_processed = Some(*identity);
                            continue;
                        }
                        stopped_at_budget = true;
                        break;
                    }
                    rows.push(candidate);
                    last_processed = Some(*identity);
                }
                Ok(_) | Err(BackendError::NotFound | BackendError::Unavailable) => {
                    unavailable_rows = unavailable_rows.saturating_add(1);
                    last_processed = Some(*identity);
                }
                Err(error) => return Err(error),
            }
        }

        check_cancel(cancellation)?;
        self.ensure_active()?;
        let has_more = stopped_at_budget || (more_candidates && last_processed.is_some());
        let page = ListedFolderPage {
            rows,
            next_cursor: if has_more {
                last_processed.map(encode_cursor)
            } else {
                None
            },
            unavailable_rows,
            read_only: true,
            last_observed: true,
            atomic_snapshot: false,
        };
        if serialized_len(&page)? > PAGE_SERIALIZED_BYTE_LIMIT {
            return Err(BackendError::Unavailable);
        }
        Ok(page)
    }
}

fn parse_cursor(cursor: &str) -> Result<OpaqueIdentity, BackendError> {
    if cursor.len() != 32
        || !cursor
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BackendError::NotFound);
    }
    let mut identity = [0u8; 16];
    for (index, chunk) in cursor.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0]).ok_or(BackendError::NotFound)?;
        let low = hex_nibble(chunk[1]).ok_or(BackendError::NotFound)?;
        identity[index] = (high << 4) | low;
    }
    Ok(OpaqueIdentity(identity))
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn encode_cursor(identity: OpaqueIdentity) -> String {
    let mut encoded = String::with_capacity(32);
    for byte in identity.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

/// Retain only the eight lowest identities after the cursor, independent of
/// catalog size. The caller holds the backend read lease during this scan.
fn select_candidates(
    directories: &HashMap<OpaqueIdentity, DirectoryBinding>,
    cursor: Option<OpaqueIdentity>,
    cancellation: &CancellationToken,
) -> Result<(Vec<(OpaqueIdentity, DirectoryBinding)>, bool), BackendError> {
    let mut selected: Vec<(OpaqueIdentity, DirectoryBinding)> =
        Vec::with_capacity(PAGE_CANDIDATE_LIMIT);
    let mut more = false;
    for (identity, binding) in directories {
        check_cancel(cancellation)?;
        if cursor.is_some_and(|cursor| identity.as_bytes() <= cursor.as_bytes()) {
            continue;
        }
        let position = selected
            .binary_search_by(|(candidate, _)| candidate.as_bytes().cmp(identity.as_bytes()))
            .unwrap_or_else(|position| position);
        if position < PAGE_CANDIDATE_LIMIT {
            selected.insert(position, (*identity, binding.clone()));
            if selected.len() > PAGE_CANDIDATE_LIMIT {
                selected.pop();
                more = true;
            }
        } else {
            more = true;
        }
    }
    Ok((selected, more))
}

fn representable(binding: &DirectoryBinding) -> bool {
    !binding.space_id.trim().is_empty()
        && binding.space_id.len() <= SPACE_ID_BYTE_LIMIT
        && !binding.space_id.chars().any(char::is_control)
        && valid_folder_field(&binding.root_resource_id)
        && valid_folder_path(&binding.path)
        && valid_folder_field(&binding.remote_id)
}

fn valid_folder_field(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= FOLDER_FIELD_BYTE_LIMIT
        && !value.chars().any(char::is_control)
}

fn valid_folder_path(path: &str) -> bool {
    path.len() <= FOLDER_FIELD_BYTE_LIMIT
        && path.starts_with('/')
        && (path == "/"
            || (!path.ends_with('/')
                && !path.contains("//")
                && !path.contains('\\')
                && !path.chars().any(char::is_control)
                && !path.split('/').any(|part| matches!(part, "." | ".."))))
}

fn row_from_binding(binding: DirectoryBinding, space_label: String) -> ListedFolderRow {
    ListedFolderRow {
        space_id: binding.space_id,
        root_resource_id: binding.root_resource_id,
        path: binding.path,
        resource_id: binding.remote_id,
        space_label,
        saved_intent: SavedFolderIntent::empty(SavedFolderIntentState::Unavailable),
    }
}

fn serialized_len(page: &ListedFolderPage) -> Result<usize, BackendError> {
    serde_json::to_vec(page)
        .map(|bytes| bytes.len())
        .map_err(|_| BackendError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(first: u8) -> OpaqueIdentity {
        OpaqueIdentity([first; 16])
    }

    fn binding(path: String) -> DirectoryBinding {
        DirectoryBinding {
            space_id: "personal".into(),
            root_resource_id: "root".into(),
            path,
            remote_id: "directory".into(),
        }
    }

    #[test]
    fn cursor_is_exact_lowercase_identity_hex() {
        assert_eq!(parse_cursor(&"ab".repeat(16)).unwrap(), identity(0xab));
        for invalid in ["", &"A0".repeat(16), &"0".repeat(31), &"g0".repeat(16)] {
            assert!(parse_cursor(invalid).is_err());
        }
        assert_eq!(encode_cursor(identity(0x2f)), "2f".repeat(16));
    }

    #[test]
    fn candidates_are_sorted_after_cursor_and_bounded_to_page_window() {
        let directories = (1u8..=12)
            .rev()
            .map(|index| (identity(index), binding(format!("/{index}"))))
            .collect::<HashMap<_, _>>();
        let (first, more) =
            select_candidates(&directories, None, &CancellationToken::new()).unwrap();
        assert_eq!(first.len(), PAGE_CANDIDATE_LIMIT);
        assert!(more);
        assert_eq!(first.first().unwrap().0, identity(1));
        assert_eq!(first.last().unwrap().0, identity(8));
        let (next, more) =
            select_candidates(&directories, Some(identity(8)), &CancellationToken::new()).unwrap();
        assert!(!more);
        assert_eq!(
            next.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            vec![identity(9), identity(10), identity(11), identity(12)]
        );
    }

    #[test]
    fn root_is_a_valid_folder_path_but_malformed_paths_fail_closed() {
        for path in ["/", "/Projects"] {
            assert!(representable(&binding(path.to_owned())));
        }
        for path in ["", "Projects", "/a/", "/a//b", "/a/../b", "/a\\b"] {
            assert!(!representable(&binding(path.to_owned())), "{path:?}");
        }
    }

    #[test]
    fn page_rows_expose_folder_identity_and_display_label_and_stay_bounded() {
        let page = ListedFolderPage {
            rows: vec![row_from_binding(
                binding("/Projects".into()),
                "Spaces / Projects".into(),
            )],
            next_cursor: Some(encode_cursor(identity(7))),
            unavailable_rows: 0,
            read_only: true,
            last_observed: true,
            atomic_snapshot: false,
        };
        let json = serde_json::to_value(&page).unwrap();
        let row = json["rows"][0].as_object().unwrap();
        assert_eq!(row.len(), 6);
        assert_eq!(row["saved_intent"]["state"], "unavailable");
        assert_eq!(row["space_label"], "Spaces / Projects");
        assert!(!row.contains_key("etag"));
        assert!(!row.contains_key("size"));
        assert!(serialized_len(&page).unwrap() < PAGE_SERIALIZED_BYTE_LIMIT);
    }

    #[test]
    fn candidate_scan_observes_cancellation() {
        let directories = HashMap::from([(identity(1), binding("/Projects".into()))]);
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            select_candidates(&directories, None, &cancellation),
            Err(BackendError::Cancelled)
        ));
    }
}

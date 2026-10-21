//! Bounded read-only pages of the active authenticated ordinary-file catalog.
use super::{
    BackendError, CancellationToken, FileBinding, FileCacheBindingExpectation, OpaqueIdentity,
    OpenCloudPlaceholderBackend, check_cancel,
};
use serde::Serialize;
use std::collections::HashMap;

const PAGE_CANDIDATE_LIMIT: usize = 8;
const PAGE_SERIALIZED_BYTE_LIMIT: usize = 128 * 1024;
const SPACE_ID_BYTE_LIMIT: usize = 512;
const LISTED_FIELD_BYTE_LIMIT: usize = 16 * 1024;
// The UI/control JSON consumer represents sizes as JavaScript safe integers.
const MAX_JSON_SAFE_SIZE: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ListedFileRow {
    pub space_id: String,
    pub root_resource_id: String,
    pub path: String,
    pub resource_id: String,
    pub etag: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ListedFilePage {
    pub rows: Vec<ListedFileRow>,
    pub next_cursor: Option<String>,
    pub unavailable_rows: usize,
    pub read_only: bool,
    pub last_observed: bool,
    pub atomic_snapshot: bool,
}

impl OpenCloudPlaceholderBackend {
    /// Return a bounded page from this active backend's already authenticated
    /// ordinary-file catalog. This performs no HTTP request or content read,
    /// identity creation, or policy mutation.
    pub fn listed_file_page(
        &self,
        cursor: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<ListedFilePage, BackendError> {
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
                && !state.files.contains_key(&cursor)
            {
                return Err(BackendError::NotFound);
            }
            select_candidates(&state.files, cursor_identity, cancellation)?
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

            // Re-resolve through the shared exact-tuple resolver. It refuses a
            // stale tuple or ambiguity; no path or resource identity is inferred.
            let expected = FileCacheBindingExpectation {
                space_id: &snapshot.space_id,
                root_resource_id: &snapshot.root_resource_id,
                path: &snapshot.path,
                resource_id: &snapshot.remote_id,
                etag: &snapshot.etag,
                size: snapshot.size,
            };
            let binding = match self
                .resolve_file_cache_binding_under_lease_cancellable(&expected, cancellation)
            {
                Ok((resolved_identity, binding))
                    if resolved_identity == *identity && binding == *snapshot =>
                {
                    binding
                }
                Ok(_) | Err(BackendError::NotFound | BackendError::Unavailable) => {
                    unavailable_rows = unavailable_rows.saturating_add(1);
                    last_processed = Some(*identity);
                    continue;
                }
                Err(error) => return Err(error),
            };
            let candidate = row_from_binding(binding);

            // Include the largest cursor shape in the estimate. If this row
            // alone cannot fit, report it unavailable and advance past it. If
            // prior rows consumed the budget, leave this candidate for next time.
            let mut trial_rows = rows.clone();
            trial_rows.push(candidate.clone());
            let trial = ListedFilePage {
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

        check_cancel(cancellation)?;
        self.ensure_active()?;
        // A cursor is returned only when there are unprocessed candidates.
        // On a byte-budget stop, the current candidate was intentionally not
        // consumed, so the cursor remains at the prior processed candidate.
        let has_more = stopped_at_budget || (more_candidates && last_processed.is_some());
        let page = ListedFilePage {
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

/// Keep only the eight lexicographically smallest candidates after the cursor.
/// This scans the live map but bounds extra identity/binding memory regardless
/// of catalog size; the caller retains its read lease for this full operation.
fn select_candidates(
    files: &HashMap<OpaqueIdentity, FileBinding>,
    cursor: Option<OpaqueIdentity>,
    cancellation: &CancellationToken,
) -> Result<(Vec<(OpaqueIdentity, FileBinding)>, bool), BackendError> {
    let mut selected: Vec<(OpaqueIdentity, FileBinding)> = Vec::with_capacity(PAGE_CANDIDATE_LIMIT);
    let mut more = false;
    for (identity, binding) in files {
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

fn representable(binding: &FileBinding) -> bool {
    valid_field(&binding.space_id, SPACE_ID_BYTE_LIMIT)
        && valid_field(&binding.root_resource_id, LISTED_FIELD_BYTE_LIMIT)
        && valid_path(&binding.path)
        && valid_field(&binding.remote_id, LISTED_FIELD_BYTE_LIMIT)
        && valid_field(&binding.etag, LISTED_FIELD_BYTE_LIMIT)
        && binding.size <= MAX_JSON_SAFE_SIZE
}

fn valid_field(value: &str, max_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn valid_path(path: &str) -> bool {
    path.len() <= LISTED_FIELD_BYTE_LIMIT
        && path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains("//")
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && !path.split('/').any(|part| matches!(part, "." | ".."))
}

fn row_from_binding(binding: FileBinding) -> ListedFileRow {
    ListedFileRow {
        space_id: binding.space_id,
        root_resource_id: binding.root_resource_id,
        path: binding.path,
        resource_id: binding.remote_id,
        etag: binding.etag,
        size: binding.size,
    }
}

fn serialized_len(page: &ListedFilePage) -> Result<usize, BackendError> {
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

    fn binding(path: String) -> FileBinding {
        FileBinding {
            space_id: "personal".into(),
            root_resource_id: "root".into(),
            path,
            remote_id: "resource".into(),
            etag: "etag".into(),
            size: 4,
        }
    }

    #[test]
    fn cursor_is_exact_lowercase_identity_hex() {
        assert_eq!(parse_cursor(&"ab".repeat(16)).unwrap(), identity(0xab));
        let upper = "A0".repeat(16);
        let short = "0".repeat(31);
        let invalid_hex = "g0".repeat(16);
        for invalid in ["", upper.as_str(), short.as_str(), invalid_hex.as_str()] {
            assert!(parse_cursor(invalid).is_err());
        }
        assert_eq!(encode_cursor(identity(0x2f)), "2f".repeat(16));
    }

    #[test]
    fn candidates_are_sorted_after_cursor_with_bounded_page_window() {
        let files = (1u8..=12)
            .rev()
            .map(|index| (identity(index), binding(format!("/{index}.txt"))))
            .collect::<HashMap<_, _>>();
        let (first, more) = select_candidates(&files, None, &CancellationToken::new()).unwrap();
        assert_eq!(first.len(), PAGE_CANDIDATE_LIMIT);
        assert!(more);
        assert_eq!(first.first().unwrap().0, identity(1));
        assert_eq!(first.last().unwrap().0, identity(8));
        let (next, more) =
            select_candidates(&files, Some(identity(8)), &CancellationToken::new()).unwrap();
        assert!(!more);
        assert_eq!(
            next.iter()
                .map(|(identity, _)| *identity)
                .collect::<Vec<_>>(),
            vec![identity(9), identity(10), identity(11), identity(12)]
        );
    }

    #[test]
    fn row_admission_rejects_unrepresentable_metadata_without_truncation() {
        let mut row = binding("/ok.txt".into());
        assert!(representable(&row));
        row.etag = "x".repeat(LISTED_FIELD_BYTE_LIMIT + 1);
        assert!(!representable(&row));
        row.etag = "etag".into();
        row.path = "/a/../b".into();
        assert!(!representable(&row));
        row.path = "/ok.txt".into();
        row.size = MAX_JSON_SAFE_SIZE + 1;
        assert!(!representable(&row));
    }

    #[test]
    fn serialized_page_cap_includes_cursor_and_response_flags() {
        let row = ListedFileRow {
            space_id: "s".into(),
            root_resource_id: "r".into(),
            path: "/x".into(),
            resource_id: "f".into(),
            etag: "e".into(),
            size: 1,
        };
        let page = ListedFilePage {
            rows: vec![row],
            next_cursor: Some("a".repeat(32)),
            unavailable_rows: 0,
            read_only: true,
            last_observed: true,
            atomic_snapshot: false,
        };
        assert!(serialized_len(&page).unwrap() < PAGE_SERIALIZED_BYTE_LIMIT);
    }
}

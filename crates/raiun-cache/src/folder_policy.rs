//! Folder intent is inherited through stable, current-generation parent IDs.
//! Paths validate a chain; they never substitute for directory identity.

use super::*;

const MAX_ANCESTRY_DEPTH: usize = 64;

pub(super) fn has_intents(db: &Connection, scope: &CacheScope) -> Result<bool, CacheError> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM folder_cloud_only_intents WHERE scope_key=?1)",
        [&scope.key],
        |row| row.get(0),
    )
    .map_err(db_error)
}

pub(super) fn inherited_cloud_only(
    db: &Connection,
    scope: &CacheScope,
    resource_id: &str,
) -> Result<bool, CacheError> {
    validate_id(resource_id)?;
    validate_registered_scope(db, scope)?;
    if !has_intents(db, scope)? {
        return Ok(false);
    }
    walk_ancestry(db, scope, resource_id, false)
}

/// Validate identity-based ancestry even when no folder intent exists yet.
/// Admission needs this before installing the first inherited policy.
#[cfg(unix)]
pub(super) fn validate_ancestry(
    db: &Connection,
    scope: &CacheScope,
    resource_id: &str,
    directory: bool,
) -> Result<(), CacheError> {
    validate_id(resource_id)?;
    validate_registered_scope(db, scope)?;
    walk_ancestry(db, scope, resource_id, directory).map(|_| ())
}

fn walk_ancestry(
    db: &Connection,
    scope: &CacheScope,
    resource_id: &str,
    directory_required: bool,
) -> Result<bool, CacheError> {
    if scope.protection != ScopeProtection::PlaintextAllowed {
        return Err(CacheError::ProtectionMismatch);
    }
    let mut current = resource_id.to_owned();
    let mut visited = BTreeSet::new();
    let mut expected_path: Option<String> = None;
    let mut inherited = false;
    for depth in 0..=MAX_ANCESTRY_DEPTH {
        if !visited.insert(current.clone()) {
            return Err(CacheError::PolicyConflict);
        }
        let intent: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM folder_cloud_only_intents WHERE scope_key=?1 AND root_id=?2)",
                params![scope.key, current],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if current == scope.root_resource_id {
            if expected_path.as_deref().is_some_and(|path| path != "/") {
                return Err(CacheError::PolicyConflict);
            }
            return Ok(inherited || intent);
        }
        // LIMIT 2 deliberately detects ambiguity rather than choosing an
        // arbitrary old/new parent during a move between complete listings.
        let rows = {
            let mut statement = db.prepare(
                "SELECT e.parent_id,e.path,e.directory,e.encrypted FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=?1 AND e.resource_id=?2 AND l.complete=1 LIMIT 2",
            ).map_err(db_error)?;
            statement
                .query_map(params![scope.key, current], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })
                .map_err(db_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?
        };
        let [(parent, path, directory, encrypted)] = rows.as_slice() else {
            return Err(CacheError::PolicyConflict);
        };
        validate_id(parent)?;
        validate_path(path)?;
        if path == "/"
            || *encrypted != 0
            || !matches!(*directory, 0 | 1)
            || ((depth != 0 || intent || directory_required) && *directory != 1)
            || expected_path
                .as_deref()
                .is_some_and(|expected| expected != path)
        {
            return Err(CacheError::PolicyConflict);
        }
        inherited |= intent;
        let (parent_path, _) = path.rsplit_once('/').ok_or(CacheError::InvalidEntry)?;
        expected_path = Some(
            if parent_path.is_empty() {
                "/"
            } else {
                parent_path
            }
            .to_owned(),
        );
        current = parent.clone();
    }
    Err(CacheError::LimitExceeded)
}

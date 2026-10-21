//! Complete listing publication inside a caller-owned transaction.
//!
//! A recursive availability transition can validate all metadata and protection
//! fences before committing any listing or pin-state change.

use super::*;

pub(super) fn publish_listing_in_transaction(
    tx: &Transaction<'_>,
    scope: &CacheScope,
    parent_resource_id: &str,
    entries: &[CachedEntry],
    fetched_at_unix: i64,
) -> Result<CachedListing, CacheError> {
    if scope.protection == ScopeProtection::CiphertextOnly {
        return Err(CacheError::ProtectionMismatch);
    }
    validate_id(parent_resource_id)?;
    validate_listing(entries)?;
    if entries
        .iter()
        .any(|item| item.parent_resource_id != parent_resource_id)
    {
        return Err(CacheError::InvalidEntry);
    }
    validate_registered_scope(tx, scope)?;
    let old_generation: Option<i64> = tx
        .query_row(
            "SELECT generation FROM listings WHERE scope_key=?1 AND parent_id=?2",
            params![scope.key, parent_resource_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?;
    let prior_policy_targets = {
        let mut stmt = tx.prepare(
            "SELECT e.resource_id FROM listing_entries e JOIN policies p ON p.scope_key=e.scope_key AND p.resource_id=e.resource_id AND p.policy=1 WHERE e.scope_key=?1 AND e.parent_id=?2",
        ).map_err(db_error)?;
        stmt.query_map(params![scope.key, parent_resource_id], |row| {
            row.get::<_, String>(0)
        })
        .map_err(db_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_error)?
    };
    let prior_pin_roots = {
        let mut stmt = tx.prepare(
            "SELECT e.resource_id FROM listing_entries e JOIN pins p ON p.scope_key=e.scope_key AND p.root_id=e.resource_id WHERE e.scope_key=?1 AND e.parent_id=?2",
        ).map_err(db_error)?;
        stmt.query_map(params![scope.key, parent_resource_id], |row| {
            row.get::<_, String>(0)
        })
        .map_err(db_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_error)?
    };
    let generation = old_generation
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(CacheError::LimitExceeded)?;
    if old_generation.is_none() {
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM listings WHERE scope_key=?1",
                params![scope.key],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if count as usize >= MAX_SNAPSHOTS {
            return Err(CacheError::LimitExceeded);
        }
    }
    let existing_for_parent: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM listing_entries WHERE scope_key=?1 AND parent_id=?2",
            params![scope.key, parent_resource_id],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    let total_entries: i64 = tx
        .query_row("SELECT COUNT(*) FROM listing_entries", [], |row| row.get(0))
        .map_err(db_error)?;
    if (total_entries - existing_for_parent).max(0) as usize + entries.len()
        > MAX_TOTAL_LISTING_ENTRIES
    {
        return Err(CacheError::LimitExceeded);
    }
    tx.execute(
        "DELETE FROM listing_entries WHERE scope_key=?1 AND parent_id=?2",
        params![scope.key, parent_resource_id],
    )
    .map_err(db_error)?;
    for resource_id in prior_policy_targets {
        if !entries.iter().any(|item| item.entry.id == resource_id) {
            tx.execute(
                "UPDATE policies SET target_state=1 WHERE scope_key=?1 AND resource_id=?2 AND policy=1",
                params![scope.key, resource_id],
            ).map_err(db_error)?;
        }
    }
    for root_id in prior_pin_roots {
        if !entries.iter().any(|item| item.entry.id == root_id) {
            tx.execute(
                "UPDATE pins SET state=2 WHERE scope_key=?1 AND root_id=?2 AND state<>3",
                params![scope.key, root_id],
            )
            .map_err(db_error)?;
        }
    }
    for item in entries {
        let entry = &item.entry;
        tx.execute(
            "INSERT INTO listing_entries(scope_key,parent_id,generation,resource_id,name,path,etag,size,directory,modified,writable,encrypted) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![scope.key,parent_resource_id,generation,entry.id,leaf_name(&entry.path)?,entry.path,entry.etag,i64_from_u64(entry.size)?,entry.directory as i64,entry.modified_unix,entry.writable as i64,entry.encrypted as i64],
        ).map_err(db_error)?;
    }
    tx.execute(
        "INSERT INTO listings(scope_key,parent_id,generation,fetched_at,complete) VALUES(?1,?2,?3,?4,1) ON CONFLICT(scope_key,parent_id) DO UPDATE SET generation=excluded.generation,fetched_at=excluded.fetched_at,complete=1",
        params![scope.key,parent_resource_id,generation,fetched_at_unix],
    ).map_err(db_error)?;
    tx.execute(
        "UPDATE policies SET target_path=(SELECT e.path FROM listing_entries e WHERE e.scope_key=?1 AND e.parent_id=?2 AND e.generation=?3 AND e.resource_id=policies.resource_id),target_state=CASE WHEN target_etag<>(SELECT e.etag FROM listing_entries e WHERE e.scope_key=?1 AND e.parent_id=?2 AND e.generation=?3 AND e.resource_id=policies.resource_id) THEN 1 ELSE target_state END WHERE scope_key=?1 AND EXISTS(SELECT 1 FROM listing_entries e WHERE e.scope_key=?1 AND e.parent_id=?2 AND e.generation=?3 AND e.resource_id=policies.resource_id)",
        params![scope.key,parent_resource_id,generation],
    ).map_err(db_error)?;
    tx.execute(
        "UPDATE pins SET root_path=(SELECT e.path FROM listing_entries e WHERE e.scope_key=?1 AND e.parent_id=?2 AND e.generation=?3 AND e.resource_id=pins.root_id) WHERE scope_key=?1 AND EXISTS(SELECT 1 FROM listing_entries e WHERE e.scope_key=?1 AND e.parent_id=?2 AND e.generation=?3 AND e.resource_id=pins.root_id)",
        params![scope.key,parent_resource_id,generation],
    ).map_err(db_error)?;
    tx.execute(
        "UPDATE pins SET state=2 WHERE scope_key=?1 AND state<>3 AND (EXISTS(SELECT 1 FROM pin_items pi WHERE pi.pin_id=pins.pin_id AND pi.parent_id=?2 AND NOT EXISTS(SELECT 1 FROM listing_entries e WHERE e.scope_key=?1 AND e.parent_id=?2 AND e.generation=?3 AND e.resource_id=pi.resource_id AND e.etag=pi.etag)) OR EXISTS(SELECT 1 FROM listing_entries e WHERE e.scope_key=?1 AND e.parent_id=?2 AND e.generation=?3 AND NOT EXISTS(SELECT 1 FROM pin_items pi WHERE pi.pin_id=pins.pin_id AND pi.parent_id=?2 AND pi.resource_id=e.resource_id AND pi.etag=e.etag))) AND (pins.root_id=?2 OR EXISTS(SELECT 1 FROM pin_items root_item WHERE root_item.pin_id=pins.pin_id AND root_item.resource_id=?2 AND root_item.directory=1))",
        params![scope.key,parent_resource_id,generation],
    ).map_err(db_error)?;
    Ok(CachedListing {
        generation: generation as u64,
        fetched_at_unix,
        complete: true,
        entries: entries.to_vec(),
    })
}

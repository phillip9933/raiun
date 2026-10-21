//! Durable ordinary-folder intent; never an access grant or a legacy-pin guess.
use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderPinRoles {
    pub active_pin_id: Option<String>,
    pub staging_pin_id: Option<String>,
    /// Only a newly admitted initial stage may become active by readiness.
    /// A refresh stage whose active pin was removed remains recovery-only.
    pub staging_is_initial: bool,
}

/// A local, atomic observation of explicitly recorded roles and legacy pins.
/// Unknown pins are preserved and cannot be assigned a role by this query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderPinIntent {
    pub roles: Option<FolderPinRoles>,
    pub has_unknown_pins: bool,
}

#[derive(Clone, Copy)]
pub(super) enum PinAdmission<'a> {
    Generic,
    Initial,
    Refresh(&'a str),
}

impl Cache {
    /// Observe saved folder intent without creating a scope, hashing content,
    /// promoting readiness, or inferring roles from legacy pins. An unused
    /// exact scope with no saved objects is empty; inconsistent objects under
    /// an unregistered scope are corrupt and must not enable new work.
    pub fn folder_pin_intent(
        &self,
        scope: &CacheScope,
        root_resource_id: &str,
        root_path: &str,
    ) -> Result<FolderPinIntent, CacheError> {
        validate_id(root_resource_id)?;
        validate_path(root_path)?;
        if scope.protection != ScopeProtection::PlaintextAllowed {
            return Err(CacheError::ProtectionMismatch);
        }
        let mut db = self.lock_db()?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(db_error)?;
        let registered = match validate_registered_scope(&tx, scope) {
            Ok(()) => true,
            Err(CacheError::NotFound) => false,
            Err(error) => return Err(error),
        };
        let roles = read_roles(&tx, &scope.key, root_resource_id, root_path)?;
        let active = roles
            .as_ref()
            .and_then(|roles| roles.active_pin_id.as_deref());
        let staging = roles
            .as_ref()
            .and_then(|roles| roles.staging_pin_id.as_deref());
        let has_unknown_pins: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pins WHERE scope_key=?1 AND (root_id=?2 OR root_path=?3) AND pin_id<>COALESCE(?4,'') AND pin_id<>COALESCE(?5,''))",
            params![scope.key,root_resource_id,root_path,active,staging], |row| row.get(0),
        ).map_err(db_error)?;
        if !registered && (roles.is_some() || has_unknown_pins) {
            return Err(CacheError::Corrupt);
        }
        tx.commit().map_err(db_error)?;
        Ok(FolderPinIntent {
            roles,
            has_unknown_pins,
        })
    }

    /// Read only explicitly recorded roles for this exact account/root/folder.
    /// This performs no content I/O and grants no authority to resume or refresh;
    /// the caller must still resolve a fresh authenticated folder binding.
    /// Legacy pins deliberately return no role rather than being adopted.
    pub fn folder_pin_roles(
        &self,
        scope: &CacheScope,
        root_resource_id: &str,
        root_path: &str,
    ) -> Result<Option<FolderPinRoles>, CacheError> {
        validate_id(root_resource_id)?;
        validate_path(root_path)?;
        if scope.protection != ScopeProtection::PlaintextAllowed {
            return Err(CacheError::ProtectionMismatch);
        }
        let db = self.lock_db()?;
        validate_registered_scope(&db, scope)?;
        read_roles(&db, &scope.key, root_resource_id, root_path)
    }

    /// Admit a new refresh stage only for an explicitly journaled active pin.
    /// Insertion and role reservation share the same immediate transaction.
    /// An existing stage must be resumed by its exact known ID instead.
    pub fn begin_folder_refresh_manifest_at_cancellable(
        &self,
        scope: &CacheScope,
        active_pin_id: &str,
        root_resource_id: &str,
        root_path: &str,
        manifest: &[PinManifestEntry],
        cancelled: impl FnMut() -> bool,
    ) -> Result<PinInfo, CacheError> {
        validate_id(active_pin_id)?;
        if manifest.iter().any(|item| item.entry.encrypted) {
            return Err(CacheError::ProtectionMismatch);
        }
        self.persist_pin_manifest(
            scope,
            (
                root_resource_id,
                root_path,
                PinAdmission::Refresh(active_pin_id),
            ),
            manifest,
            cancelled,
        )
    }
}

pub(super) fn read_roles(
    db: &Connection,
    scope_key: &str,
    root: &str,
    path: &str,
) -> Result<Option<FolderPinRoles>, CacheError> {
    let roles = db.query_row(
        "SELECT active_pin_id,staging_pin_id,initial_stage FROM folder_pin_roles WHERE scope_key=?1 AND root_id=?2 AND root_path=?3",
        params![scope_key, root, path],
        |row| Ok(FolderPinRoles { active_pin_id: row.get(0)?, staging_pin_id: row.get(1)?, staging_is_initial: match row.get::<_, i64>(2)? { 0 => false, 1 => true, _ => return Err(rusqlite::Error::InvalidQuery) } }),
    ).optional().map_err(db_error)?;
    if let Some(roles) = &roles {
        if (roles.staging_is_initial
            && (roles.active_pin_id.is_some() || roles.staging_pin_id.is_none()))
            || (roles.active_pin_id.is_none() && roles.staging_pin_id.is_none())
            || (roles.active_pin_id.is_some() && roles.active_pin_id == roles.staging_pin_id)
        {
            return Err(CacheError::Corrupt);
        }
        for id in [roles.active_pin_id.as_ref(), roles.staging_pin_id.as_ref()]
            .into_iter()
            .flatten()
        {
            validate_id(id).map_err(|_| CacheError::Corrupt)?;
            let valid: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM pins p JOIN scopes s ON s.scope_key=p.scope_key WHERE p.pin_id=?1 AND p.scope_key=?2 AND p.root_id=?3 AND p.root_path=?4 AND s.protection=0 AND p.state IN (0,1,2,3) AND NOT EXISTS(SELECT 1 FROM pin_items i WHERE i.pin_id=p.pin_id AND i.encrypted<>0))",
                params![id,scope_key,root,path], |row| row.get(0),
            ).map_err(db_error)?;
            if !valid {
                return Err(CacheError::Corrupt);
            }
        }
    }
    Ok(roles)
}

pub(super) fn admit_role(
    db: &Connection,
    scope: &CacheScope,
    root: &str,
    path: &str,
    id: &str,
    admission: PinAdmission<'_>,
) -> Result<(), CacheError> {
    match admission {
        PinAdmission::Generic => return Ok(()),
        PinAdmission::Initial => {
            if read_roles(db, &scope.key, root, path)?.is_some() {
                return Err(CacheError::Conflict);
            }
            db.execute("INSERT INTO folder_pin_roles(scope_key,root_id,root_path,staging_pin_id,initial_stage) VALUES(?1,?2,?3,?4,1)",params![scope.key,root,path,id]).map_err(db_error)?;
        }
        PinAdmission::Refresh(active) => {
            let roles = read_roles(db, &scope.key, root, path)?.ok_or(CacheError::Conflict)?;
            if roles.active_pin_id.as_deref() != Some(active) || roles.staging_pin_id.is_some() {
                return Err(CacheError::Conflict);
            }
            let ready_or_stale: bool = db
                .query_row(
                    "SELECT state IN (1,2) FROM pins WHERE pin_id=?1",
                    [active],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if !ready_or_stale {
                return Err(CacheError::Conflict);
            }
            db.execute("UPDATE folder_pin_roles SET staging_pin_id=?4 WHERE scope_key=?1 AND root_id=?2 AND root_path=?3",params![scope.key,root,path,id]).map_err(db_error)?;
        }
    }
    // Validate the newly persisted relationship before the owning transaction
    // commits; any error rolls back both role intent and the new pin.
    read_roles(db, &scope.key, root, path)?.ok_or(CacheError::Corrupt)?;
    Ok(())
}

pub(super) fn promote_initial(
    db: &Connection,
    scope: &str,
    root: &str,
    path: &str,
    id: &str,
) -> Result<(), CacheError> {
    if let Some(roles) = read_roles(db, scope, root, path)?
        && roles.staging_is_initial
        && roles.active_pin_id.is_none()
        && roles.staging_pin_id.as_deref() == Some(id)
    {
        db.execute("UPDATE folder_pin_roles SET active_pin_id=staging_pin_id,staging_pin_id=NULL,initial_stage=0 WHERE scope_key=?1 AND root_id=?2 AND root_path=?3",params![scope,root,path]).map_err(db_error)?;
    }
    Ok(())
}

pub(super) fn commit_refresh(
    db: &Connection,
    scope: &str,
    root: &str,
    path: &str,
    active: &str,
    staged: &str,
) -> Result<(), CacheError> {
    if let Some(roles) = read_roles(db, scope, root, path)? {
        if roles.active_pin_id.as_deref() != Some(active)
            || roles.staging_pin_id.as_deref() != Some(staged)
        {
            return Err(CacheError::Conflict);
        }
        db.execute("UPDATE folder_pin_roles SET staging_pin_id=NULL WHERE scope_key=?1 AND root_id=?2 AND root_path=?3",params![scope,root,path]).map_err(db_error)?;
    }
    Ok(())
}

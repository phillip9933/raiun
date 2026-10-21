//! Shared cache schema; storage policy stays explicit for each database owner.

use super::{
    CACHE_VERSION, CacheError, MAX_CONTENT_RECORDS, db_error, ensure_column, validate_cache_schema,
};
use rusqlite::{Connection, Transaction, TransactionBehavior};

pub(super) enum JournalMode {
    #[cfg(not(windows))]
    Wal,
    #[cfg(windows)]
    PinnedRollback,
}

pub(super) fn initialize(db: &Connection, journal: JournalMode) -> Result<(), CacheError> {
    db.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(db_error)?;
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(db_error)?;
    if version != 0
        && version != 1
        && version != 2
        && version != 3
        && version != 4
        && version != 5
        && version != 6
        && version != 7
        && version != CACHE_VERSION as i64
    {
        return Err(CacheError::Corrupt);
    }
    match journal {
        #[cfg(not(windows))]
        JournalMode::Wal => db
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
            .map_err(db_error)?,
        #[cfg(windows)]
        JournalMode::PinnedRollback => {
            // The owner establishes these policies. Verify rather than changing
            // modes through the restricted VFS during schema setup.
            let mode: String = db
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .map_err(db_error)?;
            let sync: i64 = db
                .query_row("PRAGMA synchronous", [], |row| row.get(0))
                .map_err(db_error)?;
            let temp: i64 = db
                .query_row("PRAGMA temp_store", [], |row| row.get(0))
                .map_err(db_error)?;
            if mode != "delete" || sync != 2 || temp != 2 {
                return Err(CacheError::Corrupt);
            }
        }
    }
    db.pragma_update(None, "foreign_keys", "ON")
        .map_err(db_error)?;
    // Schema v8 adds exact-scope/stable-directory folder CloudOnly intent.
    // Never infer intent from a path or migrate existing file policies.
    // Schema v7 records only newly admitted folder roles. Never infer roles
    // for legacy pins; older binaries refuse the upgraded database.
    // DDL, data migration and user_version either all commit or all roll back.
    // In particular a full intent ledger must not partially upgrade recovery.
    let transaction =
        Transaction::new_unchecked(db, TransactionBehavior::Immediate).map_err(db_error)?;
    let locked_version: i64 = db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(db_error)?;
    if locked_version != version {
        return Err(CacheError::Conflict);
    }
    // Policy intent counters survive policy deletion, preventing an old
    // download from passing a Recent -> CloudOnly -> Recent ABA transition.
    // Triggers cover every existing policy writer in the same transaction;
    // readiness/metadata refreshes do not create new user intent. The ledger
    // has the same one-million-identity ceiling as the content index and never
    // discards a tombstone merely to admit another operation. Schema v6 makes
    // older binaries refuse this database rather than bypass these fences.
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS scopes(
           scope_key TEXT PRIMARY KEY, origin TEXT NOT NULL, account_id TEXT NOT NULL,
           space_id TEXT NOT NULL, root_resource_id TEXT NOT NULL,
           protection INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS ciphertext_epochs(
           scope_key TEXT PRIMARY KEY, epoch INTEGER NOT NULL CHECK(epoch>=0),
           FOREIGN KEY(scope_key) REFERENCES scopes(scope_key) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS listings(
           scope_key TEXT NOT NULL, parent_id TEXT NOT NULL, generation INTEGER NOT NULL,
           fetched_at INTEGER NOT NULL, complete INTEGER NOT NULL CHECK(complete=1),
           PRIMARY KEY(scope_key,parent_id),
           FOREIGN KEY(scope_key) REFERENCES scopes(scope_key) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS listing_entries(
           scope_key TEXT NOT NULL,parent_id TEXT NOT NULL,generation INTEGER NOT NULL,
           resource_id TEXT NOT NULL,name TEXT NOT NULL,path TEXT NOT NULL,
           etag TEXT NOT NULL,size INTEGER NOT NULL,directory INTEGER NOT NULL,
           modified INTEGER NOT NULL,writable INTEGER NOT NULL,encrypted INTEGER NOT NULL,
           PRIMARY KEY(scope_key,parent_id,generation,resource_id),
           UNIQUE(scope_key,parent_id,generation,name)
         );
         CREATE INDEX IF NOT EXISTS listing_resource ON listing_entries(scope_key,resource_id,etag);
         CREATE TABLE IF NOT EXISTS folder_cloud_only_intents(
           scope_key TEXT NOT NULL,root_id TEXT NOT NULL,
           PRIMARY KEY(scope_key,root_id),
           FOREIGN KEY(scope_key) REFERENCES scopes(scope_key) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS policies(
           scope_key TEXT NOT NULL,resource_id TEXT NOT NULL,policy INTEGER NOT NULL,
           target_path TEXT NOT NULL DEFAULT '/',target_etag TEXT NOT NULL DEFAULT '',
           target_state INTEGER NOT NULL DEFAULT 0,
           PRIMARY KEY(scope_key,resource_id)
         );
         CREATE TABLE IF NOT EXISTS policy_intent_revisions(
           scope_key TEXT NOT NULL,resource_id TEXT NOT NULL,
           revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>0),
           PRIMARY KEY(scope_key,resource_id)
         );
         CREATE TRIGGER IF NOT EXISTS policy_binding_immutable BEFORE UPDATE OF scope_key,resource_id ON policies
         WHEN OLD.scope_key<>NEW.scope_key OR OLD.resource_id<>NEW.resource_id
         BEGIN SELECT RAISE(ABORT,'policy binding is immutable'); END;
         CREATE TRIGGER IF NOT EXISTS policy_intent_insert AFTER INSERT ON policies BEGIN
           INSERT INTO policy_intent_revisions(scope_key,resource_id,revision)
           VALUES(NEW.scope_key,NEW.resource_id,1)
           ON CONFLICT(scope_key,resource_id) DO UPDATE SET revision=revision+1;
         END;
         CREATE TRIGGER IF NOT EXISTS policy_intent_update AFTER UPDATE OF policy ON policies BEGIN
           INSERT INTO policy_intent_revisions(scope_key,resource_id,revision)
           VALUES(NEW.scope_key,NEW.resource_id,1)
           ON CONFLICT(scope_key,resource_id) DO UPDATE SET revision=revision+1;
         END;
         CREATE TRIGGER IF NOT EXISTS policy_intent_delete AFTER DELETE ON policies BEGIN
           INSERT INTO policy_intent_revisions(scope_key,resource_id,revision)
           VALUES(OLD.scope_key,OLD.resource_id,1)
           ON CONFLICT(scope_key,resource_id) DO UPDATE SET revision=revision+1;
         END;
         CREATE TABLE IF NOT EXISTS contents(
           content_key TEXT PRIMARY KEY,scope_key TEXT NOT NULL,resource_id TEXT NOT NULL,
           etag TEXT NOT NULL,protection INTEGER NOT NULL,byte_len INTEGER NOT NULL,
           sha256 TEXT NOT NULL,relative_path TEXT NOT NULL UNIQUE,last_accessed INTEGER NOT NULL,
           retention INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS contents_lru ON contents(retention,last_accessed);
         CREATE TABLE IF NOT EXISTS pins(
           pin_id TEXT PRIMARY KEY,scope_key TEXT NOT NULL,root_id TEXT NOT NULL,
           root_path TEXT NOT NULL DEFAULT '/',state INTEGER NOT NULL,created_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS folder_pin_roles(
           scope_key TEXT NOT NULL,root_id TEXT NOT NULL,root_path TEXT NOT NULL,
           active_pin_id TEXT,staging_pin_id TEXT,
           initial_stage INTEGER NOT NULL DEFAULT 0 CHECK(initial_stage IN (0,1)),
           PRIMARY KEY(scope_key,root_id,root_path),
           CHECK(active_pin_id IS NOT NULL OR staging_pin_id IS NOT NULL),
           CHECK(initial_stage=0 OR (active_pin_id IS NULL AND staging_pin_id IS NOT NULL)),
           CHECK(active_pin_id IS NULL OR staging_pin_id IS NULL OR active_pin_id<>staging_pin_id),
           FOREIGN KEY(scope_key) REFERENCES scopes(scope_key) ON DELETE CASCADE
         );
         CREATE UNIQUE INDEX IF NOT EXISTS folder_active_pin ON folder_pin_roles(active_pin_id)
           WHERE active_pin_id IS NOT NULL;
         CREATE UNIQUE INDEX IF NOT EXISTS folder_staging_pin ON folder_pin_roles(staging_pin_id)
           WHERE staging_pin_id IS NOT NULL;
         CREATE TRIGGER IF NOT EXISTS folder_pin_role_delete BEFORE DELETE ON pins BEGIN
           DELETE FROM folder_pin_roles
             WHERE scope_key=OLD.scope_key AND root_id=OLD.root_id AND root_path=OLD.root_path
             AND ((active_pin_id=OLD.pin_id AND staging_pin_id IS NULL)
               OR (staging_pin_id=OLD.pin_id AND active_pin_id IS NULL));
           UPDATE folder_pin_roles SET active_pin_id=NULL
             WHERE scope_key=OLD.scope_key AND root_id=OLD.root_id AND root_path=OLD.root_path
             AND active_pin_id=OLD.pin_id;
           UPDATE folder_pin_roles SET staging_pin_id=NULL
             WHERE scope_key=OLD.scope_key AND root_id=OLD.root_id AND root_path=OLD.root_path
             AND staging_pin_id=OLD.pin_id;
         END;
         CREATE TABLE IF NOT EXISTS pin_items(
           pin_id TEXT NOT NULL,resource_id TEXT NOT NULL,parent_id TEXT NOT NULL,
           name TEXT NOT NULL,path TEXT NOT NULL,etag TEXT NOT NULL,size INTEGER NOT NULL,
           directory INTEGER NOT NULL,encrypted INTEGER NOT NULL,
           PRIMARY KEY(pin_id,resource_id),
           FOREIGN KEY(pin_id) REFERENCES pins(pin_id) ON DELETE CASCADE
         );
         CREATE INDEX IF NOT EXISTS pin_content ON pin_items(pin_id,resource_id,etag,directory);
         CREATE TABLE IF NOT EXISTS ciphertext_pin_roots(
           pin_id TEXT PRIMARY KEY,scope_key TEXT NOT NULL,root_resource_id TEXT NOT NULL,
           created_at INTEGER NOT NULL,last_generation INTEGER NOT NULL DEFAULT 0,
           FOREIGN KEY(scope_key) REFERENCES scopes(scope_key) ON DELETE CASCADE
         );
         CREATE INDEX IF NOT EXISTS ciphertext_pin_scope ON ciphertext_pin_roots(scope_key,pin_id);
         CREATE TABLE IF NOT EXISTS ciphertext_pin_generations(
           pin_id TEXT NOT NULL,generation INTEGER NOT NULL,epoch INTEGER NOT NULL,
           state INTEGER NOT NULL,item_count INTEGER NOT NULL DEFAULT 0,
           byte_len INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL,
           PRIMARY KEY(pin_id,generation),
           FOREIGN KEY(pin_id) REFERENCES ciphertext_pin_roots(pin_id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS ciphertext_pin_items(
           pin_id TEXT NOT NULL,generation INTEGER NOT NULL,content_key TEXT NOT NULL,
           resource_id TEXT NOT NULL,etag TEXT NOT NULL,byte_len INTEGER NOT NULL,
           kind INTEGER NOT NULL,
           PRIMARY KEY(pin_id,generation,content_key),
           FOREIGN KEY(pin_id,generation) REFERENCES ciphertext_pin_generations(pin_id,generation) ON DELETE CASCADE,
           FOREIGN KEY(content_key) REFERENCES contents(content_key) ON DELETE CASCADE
         );
         CREATE INDEX IF NOT EXISTS ciphertext_pin_content ON ciphertext_pin_items(content_key);
         CREATE TABLE IF NOT EXISTS ciphertext_writes(
           scope_key TEXT NOT NULL,write_id TEXT NOT NULL,revision INTEGER NOT NULL,
           content_key TEXT NOT NULL,state INTEGER NOT NULL,created_at INTEGER NOT NULL,
           target_key TEXT NOT NULL DEFAULT '',plaintext_len INTEGER NOT NULL DEFAULT 0,
           operation INTEGER NOT NULL DEFAULT 0,parent_key TEXT NOT NULL DEFAULT '',
           parent_operation_key TEXT NOT NULL DEFAULT '',dependency_key TEXT NOT NULL DEFAULT '',
           retry_generation INTEGER NOT NULL DEFAULT 0,
           PRIMARY KEY(scope_key,write_id),
           FOREIGN KEY(scope_key) REFERENCES scopes(scope_key) ON DELETE CASCADE,
           FOREIGN KEY(content_key) REFERENCES contents(content_key) ON DELETE RESTRICT
         );
         CREATE INDEX IF NOT EXISTS ciphertext_write_content ON ciphertext_writes(content_key);
         CREATE INDEX IF NOT EXISTS ciphertext_write_parent ON ciphertext_writes(scope_key,parent_key,operation,write_id);
         CREATE TABLE IF NOT EXISTS writes(
           id INTEGER PRIMARY KEY AUTOINCREMENT,scope_key TEXT NOT NULL,parent_id TEXT NOT NULL,
           name TEXT NOT NULL,path TEXT NOT NULL,resource_id TEXT,base_kind INTEGER NOT NULL,
           base_etag TEXT NOT NULL,content_key TEXT NOT NULL,state INTEGER NOT NULL,
           created_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS writes_pending ON writes(scope_key,state,id);
         CREATE UNIQUE INDEX IF NOT EXISTS writes_pending_target ON writes(scope_key,parent_id,name) WHERE state IN (0,1);",
    )
    .map_err(db_error)?;
    let ledger_count: i64 = db
        .query_row("SELECT COUNT(*) FROM policy_intent_revisions", [], |row| {
            row.get(0)
        })
        .map_err(db_error)?;
    let missing_count: i64 = db.query_row("SELECT COUNT(*) FROM policies p WHERE NOT EXISTS(SELECT 1 FROM policy_intent_revisions r WHERE r.scope_key=p.scope_key AND r.resource_id=p.resource_id)", [], |row| row.get(0)).map_err(db_error)?;
    if ledger_count
        .checked_add(missing_count)
        .is_none_or(|count| count > MAX_CONTENT_RECORDS as i64)
    {
        return Err(CacheError::LimitExceeded);
    }
    if version < 6 {
        // Seed in bulk before installing the per-insert capacity trigger.
        // Otherwise migrating a large old policy table repeatedly scans it.
        db.execute("INSERT OR IGNORE INTO policy_intent_revisions(scope_key,resource_id,revision) SELECT scope_key,resource_id,1 FROM policies", []).map_err(db_error)?;
    } else if missing_count != 0 {
        return Err(CacheError::Corrupt);
    }
    db.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS policy_intent_capacity BEFORE INSERT ON policy_intent_revisions
         WHEN NOT EXISTS(SELECT 1 FROM policy_intent_revisions WHERE scope_key=NEW.scope_key AND resource_id=NEW.resource_id)
           AND (SELECT COUNT(*) FROM policy_intent_revisions)>={MAX_CONTENT_RECORDS}
         BEGIN SELECT RAISE(ABORT,'policy intent capacity exceeded'); END;")) .map_err(db_error)?;
    ensure_column(db, "pins", "root_path", "TEXT NOT NULL DEFAULT '/' ")?;
    ensure_column(
        db,
        "ciphertext_pin_roots",
        "last_generation",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        db,
        "ciphertext_writes",
        "target_key",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        db,
        "ciphertext_writes",
        "plaintext_len",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        db,
        "ciphertext_writes",
        "operation",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        db,
        "ciphertext_writes",
        "parent_key",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        db,
        "ciphertext_writes",
        "parent_operation_key",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        db,
        "ciphertext_writes",
        "dependency_key",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        db,
        "ciphertext_writes",
        "retry_generation",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ciphertext_write_target ON ciphertext_writes(scope_key,target_key) WHERE target_key<>''",
        [],
    )
    .map_err(db_error)?;
    db.execute(
        "UPDATE ciphertext_pin_roots SET last_generation=MAX(last_generation,COALESCE((SELECT MAX(generation) FROM ciphertext_pin_generations WHERE pin_id=ciphertext_pin_roots.pin_id),0))",
        [],
    )
    .map_err(db_error)?;
    ensure_column(db, "policies", "target_path", "TEXT NOT NULL DEFAULT '/' ")?;
    ensure_column(db, "policies", "target_etag", "TEXT NOT NULL DEFAULT '' ")?;
    ensure_column(
        db,
        "policies",
        "target_state",
        "INTEGER NOT NULL DEFAULT 0 ",
    )?;
    // Recover target paths for existing v1 records only from complete
    // metadata already stored under the same account/root scope.
    db.execute("UPDATE pins SET root_path=COALESCE((SELECT e.path FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=pins.scope_key AND e.resource_id=pins.root_id AND e.directory=1 AND l.complete=1 LIMIT 1),root_path) WHERE root_id<>(SELECT root_resource_id FROM scopes WHERE scope_key=pins.scope_key)", []).map_err(db_error)?;
    db.execute("UPDATE policies SET target_path=COALESCE((SELECT e.path FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=policies.scope_key AND e.resource_id=policies.resource_id AND e.directory=0 AND l.complete=1 LIMIT 1),target_path),target_etag=COALESCE((SELECT e.etag FROM listing_entries e JOIN listings l ON l.scope_key=e.scope_key AND l.parent_id=e.parent_id AND l.generation=e.generation WHERE e.scope_key=policies.scope_key AND e.resource_id=policies.resource_id AND e.directory=0 AND l.complete=1 LIMIT 1),target_etag) WHERE policy=1", []).map_err(db_error)?;
    if version < 6 {
        // Older schemas did not persist a refresh state. Require a fresh
        // stable-ID verification before presenting any prior policy as
        // automatically current.
        db.execute("UPDATE policies SET target_state=1 WHERE policy=1", [])
            .map_err(db_error)?;
    }
    db.pragma_update(None, "user_version", CACHE_VERSION)
        .map_err(db_error)?;
    validate_cache_schema(db)?;
    transaction.commit().map_err(db_error)
}

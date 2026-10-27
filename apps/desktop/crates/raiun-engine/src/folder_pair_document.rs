//! Opaque account-bound document storage; decoding/authentication belongs to caller.
use raiun_core::backend::{CloudError, ErrorKind};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
const MAX_SCOPE: usize = 16 * 1024;
const MAX_DOCUMENT: usize = 512 * 1024;
pub(crate) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS folder_pair_document (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    scope BLOB NOT NULL CHECK(typeof(scope) = 'blob' AND length(scope) BETWEEN 1 AND 16384),
    document BLOB NOT NULL CHECK(typeof(document) = 'blob' AND length(document) BETWEEN 1 AND 524288)
);";
fn invalid() -> CloudError {
    CloudError::new(
        ErrorKind::InvalidResponse,
        "invalid folder-pair document bounds",
    )
}
fn conflict() -> CloudError {
    CloudError::new(
        ErrorKind::Conflict,
        "folder-pair document scope or revision changed",
    )
}
fn sql(error: rusqlite::Error) -> CloudError {
    CloudError::new(
        ErrorKind::Io,
        format!("folder-pair document database: {error}"),
    )
}
fn bounded(bytes: &[u8], max: usize) -> bool {
    !bytes.is_empty() && bytes.len() <= max
}
type StoredDocument = (Option<Vec<u8>>, Option<Vec<u8>>);

fn current(connection: &Connection, scope: &[u8]) -> Result<Option<Vec<u8>>, CloudError> {
    let row: Option<StoredDocument> = connection
        .query_row(
            "SELECT
             CASE WHEN typeof(scope)='blob' AND length(scope) BETWEEN 1 AND 16384
                  THEN scope ELSE NULL END,
             CASE WHEN typeof(document)='blob' AND length(document) BETWEEN 1 AND 524288
                  THEN document ELSE NULL END
             FROM folder_pair_document WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    match row {
        None => Ok(None),
        Some((Some(saved_scope), Some(document))) => {
            if !bounded(&saved_scope, MAX_SCOPE) || !bounded(&document, MAX_DOCUMENT) {
                return Err(invalid());
            }
            if saved_scope != scope {
                return Err(conflict());
            }
            Ok(Some(document))
        }
        Some(_) => Err(invalid()),
    }
}
/// Bounded exclusion inventory only. Does not initialize schema or grant a
/// saved account scope authority. Even a malformed table returns at most two
/// bounded rows; extra rows and invalid metadata fail closed.
#[cfg(any(windows, test))]
type SourceInventory = (Vec<u8>, Vec<u8>);

#[cfg(any(windows, test))]
pub(crate) fn source_inventory(
    connection: &Connection,
) -> Result<Option<SourceInventory>, CloudError> {
    let mut statement = connection
        .prepare(
            "SELECT CASE WHEN id=1 AND typeof(scope)='blob' AND length(scope) BETWEEN 1 AND 16384
                  THEN scope ELSE NULL END,
                CASE WHEN id=1 AND typeof(document)='blob' AND length(document) BETWEEN 1 AND 524288
                  THEN document ELSE NULL END
         FROM folder_pair_document LIMIT 2",
        )
        .map_err(sql)?;
    let mut rows = statement.query([]).map_err(sql)?;
    let Some(row) = rows.next().map_err(sql)? else {
        return Ok(None);
    };
    let scope: Option<Vec<u8>> = row.get(0).map_err(sql)?;
    let document: Option<Vec<u8>> = row.get(1).map_err(sql)?;
    if rows.next().map_err(sql)?.is_some() {
        return Err(invalid());
    }
    match (scope, document) {
        (Some(scope), Some(document))
            if bounded(&scope, MAX_SCOPE) && bounded(&document, MAX_DOCUMENT) =>
        {
            Ok(Some((scope, document)))
        }
        _ => Err(invalid()),
    }
}

pub(crate) fn load(connection: &Connection, scope: &[u8]) -> Result<Option<Vec<u8>>, CloudError> {
    if !bounded(scope, MAX_SCOPE) {
        return Err(invalid());
    }
    current(connection, scope)
}
pub(crate) fn compare_exchange(
    connection: &Connection,
    scope: &[u8],
    expected: Option<&[u8]>,
    next: &[u8],
) -> Result<(), CloudError> {
    if !bounded(scope, MAX_SCOPE)
        || !bounded(next, MAX_DOCUMENT)
        || expected.is_some_and(|value| !bounded(value, MAX_DOCUMENT))
    {
        return Err(invalid());
    }
    let transaction =
        Transaction::new_unchecked(connection, TransactionBehavior::Immediate).map_err(sql)?;
    if current(&transaction, scope)?.as_deref() != expected {
        return Err(conflict());
    }
    transaction
        .execute(
            "INSERT INTO folder_pair_document(id,scope,document) VALUES(1,?1,?2)
         ON CONFLICT(id) DO UPDATE SET document=excluded.document",
            params![scope, next],
        )
        .map_err(sql)?;
    transaction.commit().map_err(sql)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn open(path: &std::path::Path) -> Connection {
        let connection = Connection::open(path).unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        connection
    }
    #[test]
    fn source_inventory_is_bounded_and_refuses_extra_or_invalid_rows() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch("CREATE TABLE folder_pair_document(id, scope, document)")
            .unwrap();
        assert_eq!(source_inventory(&connection).unwrap(), None);
        connection
            .execute(
                "INSERT INTO folder_pair_document VALUES(1,?1,?2)",
                params![b"scope".as_slice(), b"document".as_slice()],
            )
            .unwrap();
        assert_eq!(
            source_inventory(&connection).unwrap(),
            Some((b"scope".to_vec(), b"document".to_vec()))
        );
        connection
            .execute(
                "INSERT INTO folder_pair_document VALUES(2,?1,?2)",
                params![b"other".as_slice(), b"other".as_slice()],
            )
            .unwrap();
        assert!(source_inventory(&connection).is_err());
        connection.execute_batch("DELETE FROM folder_pair_document; INSERT INTO folder_pair_document VALUES(1,zeroblob(16385),x'01')").unwrap();
        assert!(source_inventory(&connection).is_err());
    }

    #[test]
    fn persist_reopen_and_scope_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine.sqlite3");
        let a = open(&path);
        assert_eq!(load(&a, b"account-a").unwrap(), None);
        compare_exchange(&a, b"account-a", None, b"first").unwrap();
        drop(a);
        let b = open(&path);
        assert_eq!(load(&b, b"account-a").unwrap(), Some(b"first".to_vec()));
        assert!(load(&b, b"account-b").is_err());
        assert!(compare_exchange(&b, b"account-b", Some(b"first"), b"other").is_err());
        assert_eq!(load(&b, b"account-a").unwrap(), Some(b"first".to_vec()));
    }
    #[test]
    fn two_handles_reject_stale_and_create_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine.sqlite3");
        let a = open(&path);
        let b = open(&path);
        compare_exchange(&a, b"scope", None, b"one").unwrap();
        assert!(compare_exchange(&b, b"scope", None, b"overwrite").is_err());
        let stale = load(&b, b"scope").unwrap().unwrap();
        compare_exchange(&a, b"scope", Some(b"one"), b"two").unwrap();
        assert!(compare_exchange(&b, b"scope", Some(&stale), b"three").is_err());
        assert_eq!(load(&b, b"scope").unwrap(), Some(b"two".to_vec()));
        compare_exchange(&b, b"scope", Some(b"two"), b"three").unwrap();
        assert_eq!(load(&a, b"scope").unwrap(), Some(b"three".to_vec()));
    }
    #[test]
    fn invalid_bounds_preserve_previous() {
        let dir = tempfile::tempdir().unwrap();
        let a = open(&dir.path().join("engine.sqlite3"));
        compare_exchange(&a, b"scope", None, b"saved").unwrap();
        for scope in [vec![], vec![1; MAX_SCOPE + 1]] {
            assert!(load(&a, &scope).is_err());
            assert!(compare_exchange(&a, &scope, Some(b"saved"), b"next").is_err());
        }
        for document in [vec![], vec![1; MAX_DOCUMENT + 1]] {
            assert!(compare_exchange(&a, b"scope", Some(b"saved"), &document).is_err());
            assert!(compare_exchange(&a, b"scope", Some(&document), b"next").is_err());
        }
        assert_eq!(load(&a, b"scope").unwrap(), Some(b"saved".to_vec()));
        // Simulate restored/corrupt state bypassing the normal schema checks.
        // Invalid existing rows must fail, never look absent and allow reset.
        a.execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        a.execute(
            "UPDATE folder_pair_document SET document=?1 WHERE id=1",
            params![vec![1u8; MAX_DOCUMENT + 1]],
        )
        .unwrap();
        assert!(load(&a, b"scope").is_err());
        assert!(compare_exchange(&a, b"scope", None, b"reset").is_err());
        assert_eq!(
            a.query_row(
                "SELECT length(document) FROM folder_pair_document WHERE id=1",
                [],
                |row| row.get::<_, usize>(0)
            )
            .unwrap(),
            MAX_DOCUMENT + 1
        );
    }
}

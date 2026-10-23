//! Retain every database adapter and its private cache directory with the connection.

use rusqlite::{Connection, Transaction, TransactionBehavior};
use std::ops::Deref;

pub(super) enum DbOwner {
    Portable(Connection),
    #[cfg(windows)]
    PrivateWindows {
        database: raiun_sqlite_windows::RegisteredRollbackDb,
        _cache_directory: raiun_control_windows::PrivateDirectory,
    },
}

impl Deref for DbOwner {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        match self {
            Self::Portable(connection) => connection,
            #[cfg(windows)]
            Self::PrivateWindows { database, .. } => database.borrow_engine_connection(),
        }
    }
}

impl DbOwner {
    // No DerefMut: callers cannot extract/replace the connection and outlive
    // its pinned VFS. A transaction borrows the serialized database owner.
    pub(super) fn transaction(&mut self) -> rusqlite::Result<Transaction<'_>> {
        Transaction::new_unchecked(self, TransactionBehavior::Deferred)
    }
}

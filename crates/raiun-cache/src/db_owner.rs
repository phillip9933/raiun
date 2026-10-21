//! Keep the database connection inside the owner of its storage adapter.

use rusqlite::{Connection, Transaction, TransactionBehavior};
use std::ops::Deref;

pub(super) enum DbOwner {
    #[cfg(not(windows))]
    Portable(Connection),
    // Windows retains the pinned rollback VFS for the connection lifetime.
    #[cfg(windows)]
    Windows(raiun_sqlite_windows::RegisteredRollbackDb),
}

impl Deref for DbOwner {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        match self {
            #[cfg(not(windows))]
            Self::Portable(connection) => connection,
            #[cfg(windows)]
            Self::Windows(owner) => owner.borrow_cache_connection(),
        }
    }
}

impl DbOwner {
    // No DerefMut: callers cannot replace or extract the Connection. The
    // transaction borrow keeps the mutex guard and storage owner alive.
    pub(super) fn transaction(&mut self) -> rusqlite::Result<Transaction<'_>> {
        self.transaction_with_behavior(TransactionBehavior::Deferred)
    }

    pub(super) fn transaction_with_behavior(
        &mut self,
        behavior: TransactionBehavior,
    ) -> rusqlite::Result<Transaction<'_>> {
        Transaction::new_unchecked(self, behavior)
    }
}

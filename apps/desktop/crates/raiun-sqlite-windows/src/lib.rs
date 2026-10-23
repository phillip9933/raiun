//! Guarded Windows rollback-journal SQLite adapter.
//!
//! Each connection admits one fixed-purpose database and its rollback journal
//! beneath a held private directory. Cache integration uses `cache.sqlite3`;
//! trusted engine integration uses `engine.sqlite3`. WAL, shared memory,
//! temporary/attached databases and other paths are rejected. The caller owns
//! authenticated account selection and runtime activation.

#[cfg(windows)]
#[allow(unsafe_code)]
mod rollback_vfs;

#[cfg(windows)]
pub use rollback_vfs::RegisteredRollbackDb;

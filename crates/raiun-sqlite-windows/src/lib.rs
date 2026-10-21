//! Test-only rollback-journal SQLite VFS prototype.
//!
//! This crate is not wired into `raiun-cache` and does not enable the Windows
//! cache. Its Windows-only VFS accepts one fixed database and its rollback
//! journal. WAL, shared memory, temporary databases, attached databases, and
//! other paths are rejected.

#[cfg(windows)]
#[allow(unsafe_code)]
mod rollback_vfs;

#[cfg(windows)]
pub use rollback_vfs::RegisteredRollbackDb;

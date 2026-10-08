//! Platform-independent cloud protocol boundary. File bodies never enter control JSON.
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudSpace {
    pub id: String,
    pub name: String,
    pub dav_url: String,
    pub personal: bool,
    pub writable: bool,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteEntry {
    pub id: String,
    /// Absolute logical path within its Space, never a host filesystem path.
    pub path: String,
    pub directory: bool,
    pub size: u64,
    pub etag: String,
    pub modified_unix: i64,
    pub writable: bool,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WriteCondition {
    Absent,
    Match(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudError {
    pub kind: ErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ErrorKind {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Offline,
    InvalidResponse,
    Unsupported,
    Io,
}

impl CloudError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}
impl std::fmt::Display for CloudError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for CloudError {}

/// Blocking protocol operations run on engine workers, never the UI event loop.
/// A listing is complete only if this method returns Ok; visitors must stage data.
pub trait CloudBackend: Send + Sync {
    fn spaces(&self) -> Result<Vec<CloudSpace>, CloudError>;
    fn list(
        &self,
        space: &str,
        path: &str,
        visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
    ) -> Result<(), CloudError>;
    fn stat(&self, space: &str, path: &str) -> Result<RemoteEntry, CloudError>;
    fn download(
        &self,
        space: &str,
        path: &str,
        expected_etag: Option<&str>,
        destination: &Path,
    ) -> Result<RemoteEntry, CloudError>;
    fn upload(
        &self,
        space: &str,
        path: &str,
        source: &Path,
        condition: WriteCondition,
    ) -> Result<RemoteEntry, CloudError>;
    fn mkdir(&self, space: &str, path: &str) -> Result<RemoteEntry, CloudError>;
    fn delete(&self, space: &str, path: &str, expected_etag: &str) -> Result<(), CloudError>;
    /// Move within one Space without overwriting an existing destination.
    fn rename(
        &self,
        space: &str,
        from: &str,
        to: &str,
        expected_etag: &str,
    ) -> Result<RemoteEntry, CloudError>;
}

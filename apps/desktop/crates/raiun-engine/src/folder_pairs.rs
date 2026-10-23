//! Inert configuration document only; filesystem/root admission belongs to the caller.
use raiun_core::{CONFIG_SCHEMA_VERSION, Config};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MAX_DOCUMENT_BYTES: usize = 512 * 1024;
pub const MAX_PAIRS: usize = 64;
pub const MAX_RETIRED_IDS: usize = 4096;
const VERSION: u32 = 1;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountScope {
    profile: String,
    server: String,
    client: String,
    issuer: Option<String>,
    subject: String,
}
impl std::fmt::Debug for AccountScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountScope([redacted])")
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentError {
    Invalid,
    ScopeMismatch,
    StaleRevision,
    RevisionExhausted,
}
type Result<T> = std::result::Result<T, DocumentError>;
fn bounded(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}
fn canonical_url(s: &str) -> bool {
    let Ok(u) = url::Url::parse(s) else {
        return false;
    };
    matches!(u.scheme(), "https" | "http")
        && u.host_str().is_some()
        && u.username().is_empty()
        && u.password().is_none()
        && u.query().is_none()
        && u.fragment().is_none()
        && u.as_str() == s
}
impl AccountScope {
    /// Inputs must originate from the trusted authenticated session, never the document.
    pub fn new(
        profile: String,
        server: String,
        client: String,
        issuer: Option<String>,
        subject: String,
    ) -> Result<Self> {
        if !bounded(&profile, 512)
            || !bounded(&client, 2048)
            || !bounded(&subject, 2048)
            || server.len() > 4096
            || !canonical_url(&server)
            || issuer
                .as_ref()
                .is_some_and(|v| v.len() > 4096 || !canonical_url(v))
        {
            return Err(DocumentError::Invalid);
        }
        Ok(Self {
            profile,
            server,
            client,
            issuer,
            subject,
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FolderPairsDocument {
    version: u32,
    scope: AccountScope,
    revision: u64,
    config: Config,
    retired_pair_ids: Vec<String>,
    #[serde(default)]
    paused: bool,
    #[serde(default)]
    paused_space_ids: Vec<String>,
    #[serde(default)]
    media_jobs: Vec<raiun_core::MediaImportJob>,
}
impl FolderPairsDocument {
    pub fn new(scope: AccountScope, config: Config) -> Result<Self> {
        let value = Self {
            version: VERSION,
            scope,
            revision: 0,
            config,
            retired_pair_ids: vec![],
            paused: false,
            paused_space_ids: vec![],
            media_jobs: vec![],
        };
        value.encode()?;
        Ok(value)
    }
    pub fn decode(bytes: &[u8], expected: &AccountScope) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(DocumentError::Invalid);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| DocumentError::Invalid)?;
        if &value.scope != expected {
            return Err(DocumentError::ScopeMismatch);
        }
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        AccountScope::new(
            self.scope.profile.clone(),
            self.scope.server.clone(),
            self.scope.client.clone(),
            self.scope.issuer.clone(),
            self.scope.subject.clone(),
        )?;
        if self.version != VERSION
            || self.config.schema_version != CONFIG_SCHEMA_VERSION
            || self.config.pairs.len() > MAX_PAIRS
            || self.retired_pair_ids.len() > MAX_RETIRED_IDS
        {
            return Err(DocumentError::Invalid);
        }
        raiun_core::validate_media_import_jobs(&self.media_jobs)
            .map_err(|_| DocumentError::Invalid)?;
        let mut paused_ids = BTreeSet::new();
        if self.paused_space_ids.len() > 256
            || self
                .paused_space_ids
                .iter()
                .any(|id| !bounded(id, 512) || id.trim() != id || !paused_ids.insert(id))
        {
            return Err(DocumentError::Invalid);
        }
        let mut ids = BTreeSet::new();
        for id in &self.retired_pair_ids {
            if !bounded(id, 128) || !ids.insert(id) {
                return Err(DocumentError::Invalid);
            }
        }
        for pair in &self.config.pairs {
            if !bounded(&pair.id, 128)
                || !bounded(&pair.space_id, 512)
                || !ids.insert(&pair.id)
                || pair.vault.is_some()
                || pair.validate_exclusions().is_err()
            {
                return Err(DocumentError::Invalid);
            }
        }
        // Deliberately no validate_config(): it probes paths. Admission happens at execution.
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| DocumentError::Invalid)?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(DocumentError::Invalid);
        }
        Ok(bytes)
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn media_jobs(&self) -> &[raiun_core::MediaImportJob] {
        &self.media_jobs
    }
    pub fn paused(&self) -> bool {
        self.paused
    }
    pub fn paused_space_ids(&self) -> &[String] {
        &self.paused_space_ids
    }
    pub fn retired_pair_ids(&self) -> &[String] {
        &self.retired_pair_ids
    }
    /// Creates an inert replacement; secure storage must CAS expected_revision atomically.
    /// Every removed ID is retired automatically; retirement cannot be undone.
    pub fn replace(&self, expected_revision: u64, config: Config) -> Result<Self> {
        if expected_revision != self.revision {
            return Err(DocumentError::StaleRevision);
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(DocumentError::RevisionExhausted)?;
        let mut retired = self.retired_pair_ids.clone();
        for pair in &self.config.pairs {
            if !config.pairs.iter().any(|next| next.id == pair.id) {
                retired.push(pair.id.clone());
            }
        }
        let next = Self {
            version: VERSION,
            scope: self.scope.clone(),
            revision,
            config,
            retired_pair_ids: retired,
            paused: self.paused,
            paused_space_ids: self.paused_space_ids.clone(),
            media_jobs: self.media_jobs.clone(),
        };
        next.encode()?;
        Ok(next)
    }
}

/// Exclusion metadata only; these values never establish account or root authority.
pub struct SavedSourceExclusions {
    scope_digest: String,
    sources: Vec<SavedSourceExclusion>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SavedSourceKind {
    FolderPair,
    MediaJob,
}

/// One saved source, including disabled jobs. Paths are lexical, not admitted roots.
pub struct SavedSourceExclusion {
    kind: SavedSourceKind,
    id: String,
    path: std::path::PathBuf,
}
impl SavedSourceExclusion {
    pub fn kind(&self) -> SavedSourceKind {
        self.kind
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}
impl SavedSourceExclusions {
    /// Inspect an existing protected Windows engine store for exclusions only.
    /// No engine/cache/schema is initialized. SQLite may recover a hot rollback
    /// journal; this is not a physically read-only opener. The caller supplies
    /// known registry profiles and must still pin source identities before use.
    #[cfg(windows)]
    pub fn read_windows_existing(
        directory: raiun_control_windows::PrivateDirectory,
        known_profiles: &[&str],
    ) -> Result<Option<(String, Self)>> {
        if known_profiles.is_empty() || known_profiles.len() > 16 {
            return Err(DocumentError::Invalid);
        }
        let name = directory
            .path()
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or(DocumentError::Invalid)?
            .to_owned();
        let digest = name
            .strip_prefix("folder-sync-")
            .ok_or(DocumentError::Invalid)?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        {
            return Err(DocumentError::Invalid);
        }
        let db = raiun_sqlite_windows::RegisteredRollbackDb::open_engine_existing(directory)
            .map_err(|_| DocumentError::Invalid)?;
        let raw = crate::folder_pair_document::source_inventory(db.borrow_engine_connection())
            .map_err(|_| DocumentError::Invalid)?;
        let Some((scope, document)) = raw else {
            return Ok(None);
        };
        let saved: AccountScope =
            serde_json::from_slice(&scope).map_err(|_| DocumentError::Invalid)?;
        if !known_profiles.contains(&saved.profile.as_str()) {
            return Err(DocumentError::ScopeMismatch);
        }
        let exclusions = Self::decode(&scope, &document, &saved.profile)?;
        if name != format!("folder-sync-{}", exclusions.scope_digest()) {
            return Err(DocumentError::ScopeMismatch);
        }
        db.close().map_err(|_| DocumentError::Invalid)?;
        Ok(Some((saved.profile, exclusions)))
    }

    /// Decode protected inventory bytes for exclusion checks, never runtime restoration.
    /// No filesystem, database, credential or network access is performed.
    pub fn decode(stored_scope: &[u8], document: &[u8], expected_profile: &str) -> Result<Self> {
        if stored_scope.is_empty() || stored_scope.len() > 16 * 1024 {
            return Err(DocumentError::Invalid);
        }
        let scope: AccountScope =
            serde_json::from_slice(stored_scope).map_err(|_| DocumentError::Invalid)?;
        AccountScope::new(
            scope.profile.clone(),
            scope.server.clone(),
            scope.client.clone(),
            scope.issuer.clone(),
            scope.subject.clone(),
        )?;
        if scope.profile != expected_profile {
            return Err(DocumentError::ScopeMismatch);
        }
        let canonical = serde_json::to_vec(&scope).map_err(|_| DocumentError::Invalid)?;
        if canonical != stored_scope {
            return Err(DocumentError::Invalid);
        }
        let document = FolderPairsDocument::decode(document, &scope)?;
        if document
            .media_jobs
            .iter()
            .any(|job| job.account_id != scope.subject)
        {
            return Err(DocumentError::ScopeMismatch);
        }
        let mut sources = Vec::new();
        for (kind, id, path) in document
            .config
            .pairs
            .into_iter()
            .map(|pair| (SavedSourceKind::FolderPair, pair.id, pair.local_path))
            .chain(
                document
                    .media_jobs
                    .into_iter()
                    .map(|job| (SavedSourceKind::MediaJob, job.id, job.source_root)),
            )
        {
            let text = path.to_str().ok_or(DocumentError::Invalid)?;
            if !path.is_absolute() || !bounded(text, 32_000) {
                return Err(DocumentError::Invalid);
            }
            sources.push(SavedSourceExclusion { kind, id, path });
        }
        Ok(Self {
            scope_digest: format!("{:x}", Sha256::digest(stored_scope)),
            sources,
        })
    }
    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }
    pub fn sources(&self) -> &[SavedSourceExclusion] {
        &self.sources
    }
}

/// Typed persistence only. Callers retain responsibility for authentication,
/// root admission and holding Engine policy-publication guards around updates.
pub struct FolderPairsStore {
    engine: crate::Engine,
    scope: AccountScope,
    scope_bytes: Vec<u8>,
}
#[derive(Debug)]
pub enum StoreError {
    Document(DocumentError),
    Database(raiun_core::backend::CloudError),
}
impl From<DocumentError> for StoreError {
    fn from(value: DocumentError) -> Self {
        Self::Document(value)
    }
}
impl From<raiun_core::backend::CloudError> for StoreError {
    fn from(value: raiun_core::backend::CloudError) -> Self {
        Self::Database(value)
    }
}
impl FolderPairsStore {
    /// Scope must come from the trusted authenticated account, never stored JSON.
    pub fn new(
        engine: crate::Engine,
        scope: AccountScope,
    ) -> std::result::Result<Self, StoreError> {
        AccountScope::new(
            scope.profile.clone(),
            scope.server.clone(),
            scope.client.clone(),
            scope.issuer.clone(),
            scope.subject.clone(),
        )?;
        let scope_bytes = serde_json::to_vec(&scope).map_err(|_| DocumentError::Invalid)?;
        if scope_bytes.is_empty() || scope_bytes.len() > 16 * 1024 {
            return Err(DocumentError::Invalid.into());
        }
        Ok(Self {
            engine,
            scope,
            scope_bytes,
        })
    }
    pub fn load(&self) -> std::result::Result<Option<FolderPairsDocument>, StoreError> {
        self.engine
            .load_folder_pair_document(&self.scope_bytes)?
            .map(|bytes| FolderPairsDocument::decode(&bytes, &self.scope).map_err(StoreError::from))
            .transpose()
    }
    pub fn create(&self, config: Config) -> std::result::Result<FolderPairsDocument, StoreError> {
        let document = FolderPairsDocument::new(self.scope.clone(), config)?;
        let next = document.encode()?;
        self.engine
            .compare_exchange_folder_pair_document(&self.scope_bytes, None, &next)?;
        Ok(document)
    }
    /// Caller authenticates job account/destination/source and fences runtime work.
    pub fn set_media_job(
        &self,
        expected_document_revision: u64,
        expected_job_revision: u64,
        mut job: raiun_core::MediaImportJob,
    ) -> std::result::Result<FolderPairsDocument, StoreError> {
        let old = self
            .engine
            .load_folder_pair_document(&self.scope_bytes)?
            .ok_or(DocumentError::StaleRevision)?;
        let mut next = FolderPairsDocument::decode(&old, &self.scope)?;
        if next.revision != expected_document_revision {
            return Err(DocumentError::StaleRevision.into());
        }
        if let Some(existing) = next
            .media_jobs
            .iter_mut()
            .find(|existing| existing.id == job.id)
        {
            if existing.revision != expected_job_revision
                || job.revision != expected_job_revision
                || existing.account_id != job.account_id
            {
                return Err(DocumentError::StaleRevision.into());
            }
            job.revision = existing
                .revision
                .checked_add(1)
                .ok_or(DocumentError::RevisionExhausted)?;
            *existing = job;
        } else {
            if expected_job_revision != 0 || job.revision != 0 {
                return Err(DocumentError::StaleRevision.into());
            }
            job.revision = 1;
            next.media_jobs.push(job);
        }
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(DocumentError::RevisionExhausted)?;
        self.engine.compare_exchange_folder_pair_document(
            &self.scope_bytes,
            Some(&old),
            &next.encode()?,
        )?;
        Ok(next)
    }
    /// Refuses currently observed unresolved durable attempts/recovery.
    /// Removing configuration does not delete Engine history or recovery bodies.
    pub fn remove_media_job(
        &self,
        expected_document_revision: u64,
        id: &str,
        expected_job_revision: u64,
    ) -> std::result::Result<FolderPairsDocument, StoreError> {
        let old = self
            .engine
            .load_folder_pair_document(&self.scope_bytes)?
            .ok_or(DocumentError::StaleRevision)?;
        let mut next = FolderPairsDocument::decode(&old, &self.scope)?;
        if next.revision != expected_document_revision {
            return Err(DocumentError::StaleRevision.into());
        }
        let index = next
            .media_jobs
            .iter()
            .position(|job| job.id == id && job.revision == expected_job_revision)
            .ok_or(DocumentError::StaleRevision)?;
        // Fail closed here too: callers cannot hide known retained recovery simply
        // by forgetting their preflight. Runtime serialization is still required.
        if self.engine.media_import_has_unresolved(id)? {
            return Err(DocumentError::Invalid.into());
        }
        next.media_jobs.remove(index);
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(DocumentError::RevisionExhausted)?;
        self.engine.compare_exchange_folder_pair_document(
            &self.scope_bytes,
            Some(&old),
            &next.encode()?,
        )?;
        Ok(next)
    }
    pub fn set_pause(
        &self,
        expected_revision: u64,
        paused: bool,
        mut paused_space_ids: Vec<String>,
    ) -> std::result::Result<FolderPairsDocument, StoreError> {
        let old = self
            .engine
            .load_folder_pair_document(&self.scope_bytes)?
            .ok_or(DocumentError::StaleRevision)?;
        let mut next = FolderPairsDocument::decode(&old, &self.scope)?;
        if next.revision != expected_revision {
            return Err(DocumentError::StaleRevision.into());
        }
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(DocumentError::RevisionExhausted)?;
        paused_space_ids.sort();
        next.paused = paused;
        next.paused_space_ids = paused_space_ids;
        self.engine.compare_exchange_folder_pair_document(
            &self.scope_bytes,
            Some(&old),
            &next.encode()?,
        )?;
        Ok(next)
    }
    pub fn replace(
        &self,
        expected_revision: u64,
        config: Config,
    ) -> std::result::Result<FolderPairsDocument, StoreError> {
        let old = self
            .engine
            .load_folder_pair_document(&self.scope_bytes)?
            .ok_or(DocumentError::StaleRevision)?;
        let current = FolderPairsDocument::decode(&old, &self.scope)?;
        let next = current.replace(expected_revision, config)?;
        self.engine.compare_exchange_folder_pair_document(
            &self.scope_bytes,
            Some(&old),
            &next.encode()?,
        )?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raiun_core::{FolderPair, SyncMode};
    fn scope() -> AccountScope {
        AccountScope::new(
            "default".into(),
            "https://example.invalid/".into(),
            "desktop".into(),
            Some("https://issuer.invalid/".into()),
            "alice".into(),
        )
        .unwrap()
    }
    fn config() -> Config {
        Config {
            schema_version: CONFIG_SCHEMA_VERSION,
            cloud_root: "Z:\\offline-cloud".into(),
            pairs: vec![FolderPair {
                id: "one".into(),
                local_path: "Z:\\offline-pair".into(),
                space_id: "space".into(),
                vault: None,
                remote_path: "/".into(),
                mode: SyncMode::TwoWay,
                excluded_paths: vec!["private".into()],
            }],
        }
    }
    #[test]
    fn full_scope_isolation_and_redaction() {
        let s = scope();
        let bytes = FolderPairsDocument::new(s.clone(), config())
            .unwrap()
            .encode()
            .unwrap();
        for field in ["profile", "server", "client", "issuer", "subject"] {
            let mut v = serde_json::to_value(&s).unwrap();
            v[field] = serde_json::json!(if field == "server" || field == "issuer" {
                "https://other.invalid/"
            } else {
                "other"
            });
            let other: AccountScope = serde_json::from_value(v).unwrap();
            assert!(matches!(
                FolderPairsDocument::decode(&bytes, &other),
                Err(DocumentError::ScopeMismatch)
            ));
        }
        assert_eq!(format!("{s:?}"), "AccountScope([redacted])");
        assert!(
            AccountScope::new(
                "p".into(),
                "https://user:password@example.invalid/".into(),
                "c".into(),
                None,
                "s".into()
            )
            .is_err()
        );
    }
    #[test]
    fn restart_retirement_and_revision() {
        let s = scope();
        let doc = FolderPairsDocument::new(s.clone(), config()).unwrap();
        let mut empty = config();
        empty.pairs.clear();
        let removed = doc.replace(0, empty).unwrap();
        let restarted = FolderPairsDocument::decode(&removed.encode().unwrap(), &s).unwrap();
        assert_eq!(restarted.retired_pair_ids(), &["one"]);
        assert!(restarted.replace(1, config()).is_err());
        assert!(matches!(
            restarted.replace(0, config()),
            Err(DocumentError::StaleRevision)
        ));
        let mut exhausted = restarted;
        exhausted.revision = u64::MAX;
        assert!(matches!(
            exhausted.replace(u64::MAX, exhausted.config.clone()),
            Err(DocumentError::RevisionExhausted)
        ));
    }
    #[test]
    fn invalid_duplicate_vault_and_exclusions_refuse() {
        let s = scope();
        let mut c = config();
        c.pairs.push(c.pairs[0].clone());
        assert!(FolderPairsDocument::new(s.clone(), c).is_err());
        let mut c = config();
        c.pairs[0].excluded_paths = vec!["../escape".into()];
        assert!(FolderPairsDocument::new(s.clone(), c).is_err());
        let mut c = config();
        c.pairs[0].vault = Some(raiun_core::VaultBinding {
            root_path: "/".into(),
            root_resource_id: "vault".into(),
        });
        assert!(FolderPairsDocument::new(s.clone(), c).is_err());
        let d = FolderPairsDocument::new(s.clone(), config()).unwrap();
        let mut v = serde_json::to_value(&d).unwrap();
        v["version"] = 2.into();
        assert!(FolderPairsDocument::decode(&serde_json::to_vec(&v).unwrap(), &s).is_err());
    }
    #[test]
    fn byte_pair_and_retirement_bounds() {
        let s = scope();
        assert!(FolderPairsDocument::decode(&vec![b' '; MAX_DOCUMENT_BYTES + 1], &s).is_err());
        let mut c = config();
        c.pairs = (0..65)
            .map(|i| {
                let mut p = c.pairs[0].clone();
                p.id = i.to_string();
                p
            })
            .collect();
        assert!(FolderPairsDocument::new(s.clone(), c).is_err());
        let mut d = FolderPairsDocument::new(s.clone(), config()).unwrap();
        d.retired_pair_ids = (0..=MAX_RETIRED_IDS)
            .map(|i| format!("retired-{i}"))
            .collect();
        assert!(d.encode().is_err());
        d.retired_pair_ids = vec!["same".into(), "same".into()];
        assert!(d.encode().is_err());
        let mut c = config();
        c.pairs[0].remote_path = "x".repeat(MAX_DOCUMENT_BYTES);
        assert!(FolderPairsDocument::new(s, c).is_err());
    }
    #[test]
    fn offline_and_existing_non_directory_paths_are_not_probed() {
        let s = scope();
        let mut c = config();
        // An existing non-directory would be rejected by filesystem validation.
        c.pairs[0].local_path = "/proc/version".into();
        let d = FolderPairsDocument::new(s.clone(), c.clone()).unwrap();
        let restored = FolderPairsDocument::decode(&d.encode().unwrap(), &s).unwrap();
        assert_eq!(restored.config(), &c);
        assert_eq!(restored.revision(), 0);
    }
    #[test]
    fn engine_id_boundary_applies_to_active_and_retired_decode() {
        let scope = scope();
        let mut config = config();
        config.pairs[0].id = "a".repeat(128);
        let active = FolderPairsDocument::new(scope.clone(), config.clone()).unwrap();
        assert!(FolderPairsDocument::decode(&active.encode().unwrap(), &scope).is_ok());
        config.pairs[0].id.push('a');
        assert!(FolderPairsDocument::new(scope.clone(), config).is_err());
        let mut raw = serde_json::to_value(&active).unwrap();
        raw["config"]["pairs"][0]["id"] = "a".repeat(129).into();
        assert!(FolderPairsDocument::decode(&serde_json::to_vec(&raw).unwrap(), &scope).is_err());
        let mut raw = serde_json::to_value(&active).unwrap();
        raw["retired_pair_ids"] = serde_json::json!(["r".repeat(128)]);
        assert!(FolderPairsDocument::decode(&serde_json::to_vec(&raw).unwrap(), &scope).is_ok());
        raw["retired_pair_ids"] = serde_json::json!(["r".repeat(129)]);
        assert!(FolderPairsDocument::decode(&serde_json::to_vec(&raw).unwrap(), &scope).is_err());
    }
    fn exclusion_document() -> FolderPairsDocument {
        let mut config = config();
        config.pairs[0].local_path = std::env::temp_dir().join("raiun-saved-pair-offline");
        let mut document = FolderPairsDocument::new(scope(), config).unwrap();
        document.paused = true;
        document.media_jobs.push(raiun_core::MediaImportJob {
            id: "disabled-media".into(),
            revision: 1,
            account_id: "alice".into(),
            source_root: std::env::temp_dir().join("raiun-saved-media-offline"),
            space_id: "space".into(),
            destination_root: "/Photos".into(),
            destination_root_resource_id: "photos-root".into(),
            filter: raiun_core::MediaFilter::All,
            organization: raiun_core::MediaOrganization::PreserveRelativePath,
            filesystem_mtime_utc: false,
            interval_seconds: 3600,
            enabled: false,
        });
        document
    }

    #[test]
    fn saved_source_exclusions_bind_canonical_scope_and_include_disabled_media() {
        let document = exclusion_document();
        let scope_bytes = serde_json::to_vec(&scope()).unwrap();
        let decoded =
            SavedSourceExclusions::decode(&scope_bytes, &document.encode().unwrap(), "default")
                .unwrap();
        assert_eq!(
            decoded.scope_digest(),
            format!("{:x}", Sha256::digest(&scope_bytes))
        );
        assert_eq!(decoded.sources().len(), 2);
        let pair = &decoded.sources()[0];
        assert!(pair.kind() == SavedSourceKind::FolderPair);
        assert_eq!(pair.id(), "one");
        assert_eq!(pair.path(), document.config.pairs[0].local_path);
        let media = &decoded.sources()[1];
        assert!(media.kind() == SavedSourceKind::MediaJob);
        assert_eq!(media.id(), "disabled-media");
        assert_eq!(media.path(), document.media_jobs[0].source_root);
    }

    #[test]
    fn saved_source_exclusions_reject_foreign_noncanonical_and_malformed_bytes() {
        let scope_bytes = serde_json::to_vec(&scope()).unwrap();
        let bytes = exclusion_document().encode().unwrap();
        assert!(matches!(
            SavedSourceExclusions::decode(&scope_bytes, &bytes, "foreign"),
            Err(DocumentError::ScopeMismatch)
        ));
        let mut foreign = exclusion_document();
        foreign.scope.subject = "someone-else".into();
        assert!(matches!(
            SavedSourceExclusions::decode(&scope_bytes, &foreign.encode().unwrap(), "default"),
            Err(DocumentError::ScopeMismatch)
        ));
        let mut spaced = vec![b' '];
        spaced.extend_from_slice(&scope_bytes);
        for invalid in [&[][..], b"{}", &spaced, &vec![b'x'; 16 * 1024 + 1]] {
            assert!(SavedSourceExclusions::decode(invalid, &bytes, "default").is_err());
        }
        for invalid in [&[][..], b"{}", &vec![b'x'; MAX_DOCUMENT_BYTES + 1]] {
            assert!(SavedSourceExclusions::decode(&scope_bytes, invalid, "default").is_err());
        }
    }

    #[test]
    fn saved_source_exclusions_reject_media_account_mismatch_and_invalid_pair_paths() {
        let scope_bytes = serde_json::to_vec(&scope()).unwrap();
        let mut wrong_account = exclusion_document();
        wrong_account.media_jobs[0].account_id = "foreign".into();
        assert!(matches!(
            SavedSourceExclusions::decode(
                &scope_bytes,
                &wrong_account.encode().unwrap(),
                "default"
            ),
            Err(DocumentError::ScopeMismatch)
        ));
        for path in [
            std::path::PathBuf::from("relative/source"),
            std::env::temp_dir().join("control\nsource"),
            std::env::temp_dir().join("x".repeat(32_001)),
        ] {
            let mut document = exclusion_document();
            document.config.pairs[0].local_path = path;
            assert!(
                SavedSourceExclusions::decode(&scope_bytes, &document.encode().unwrap(), "default")
                    .is_err()
            );
        }
    }
}

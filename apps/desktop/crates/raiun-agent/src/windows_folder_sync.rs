//! Ordinary folder work owned by the existing Windows command thread.
use super::*;
mod media_control {
    include!("windows_media_control.rs");
}
mod vault_control {
    include!("windows_vault_control.rs");
}
use raiun_cloudfiles_windows::ConfiguredRootIdentity;
use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
use raiun_core::{CONFIG_SCHEMA_VERSION, Config, FolderPair, MediaImportJob, SyncMode};
use raiun_engine::{
    Engine, SyncRevocationHandle,
    folder_pairs::{AccountScope, FolderPairsDocument, FolderPairsStore},
};
use std::collections::BTreeMap;
use windows_folder_requests::FolderRequest;
use windows_profile_registry::{Registry, SourceKind};

pub(super) enum SourceAdmissions {
    Broker {
        profile: String,
        registry: SharedSourceAdmissions,
    },
}

pub(super) struct Setup {
    pub source_admissions: SourceAdmissions,
    pub generation: u64,
    pub scope: AccountScope,
    pub account_id: String,
    pub origin: String,
    pub client: Arc<OpenCloudClient>,
    pub spaces: Vec<CloudSpace>,
    pub directory: PrivateDirectory,
    pub cloud_root: Option<RootConfiguration>,
}

pub(super) struct Runtime {
    source_admissions: SourceAdmissions,
    scope_digest: String,
    pub generation: u64,
    account_id: String,
    engine: Engine,
    store: FolderPairsStore,
    client: Arc<OpenCloudClient>,
    spaces: Vec<CloudSpace>,
    roots: BTreeMap<String, PinnedDirectory>,
    cloud_root: Option<RootConfiguration>,
    next_periodic_sync: std::time::Instant,
    next_media_sync: std::time::Instant,
}

fn source_receipt_matches(
    snapshot: &Registry,
    profile: &str,
    scope_digest: &str,
    kind: SourceKind,
    id: &str,
    path: &Path,
    identity: ConfiguredRootIdentity,
) -> bool {
    snapshot.profiles().get(profile).is_some_and(|record| {
        record.source_reservations().iter().any(|row| {
            row.scope_digest() == scope_digest
                && row.kind() == kind
                && row.id() == id
                && Some(row.root().path()) == path.to_str()
                && row.root().volume_serial() == identity.volume_serial
                && row.root().file_index() == identity.file_index
        })
    })
}

fn store_error(_: impl std::fmt::Debug) -> String {
    "Folder settings could not be read or saved; previous settings were preserved".into()
}
impl Runtime {
    pub fn open(setup: Setup, authorized: &AtomicU64) -> Result<Self, String> {
        if setup.generation == 0 || authorized.load(Ordering::Acquire) != setup.generation {
            return Err("The account changed before folder setup".into());
        }
        use sha2::Digest;
        let scope_bytes = serde_json::to_vec(&setup.scope).map_err(store_error)?;
        let scope_digest = format!("{:x}", sha2::Sha256::digest(&scope_bytes));
        let engine = Engine::open_private_windows(setup.directory, setup.client.clone())
            .and_then(|engine| engine.with_account_scope(setup.account_id.clone(), setup.origin))
            .map_err(store_error)?;
        let store = FolderPairsStore::new(engine.clone(), setup.scope).map_err(store_error)?;
        if store.load().map_err(store_error)?.is_none() {
            store
                .create(Config {
                    schema_version: CONFIG_SCHEMA_VERSION,
                    cloud_root: setup
                        .cloud_root
                        .as_ref()
                        .map(|root| PathBuf::from(&root.path))
                        .unwrap_or_default(),
                    pairs: vec![],
                })
                .map_err(store_error)?;
        }
        let mut runtime = Self {
            source_admissions: setup.source_admissions,
            scope_digest,
            generation: setup.generation,
            account_id: setup.account_id,
            engine,
            store,
            client: setup.client,
            spaces: setup
                .spaces
                .into_iter()
                .filter(|space| !space.encrypted)
                .collect(),
            roots: BTreeMap::new(),
            cloud_root: setup.cloud_root,
            next_periodic_sync: std::time::Instant::now() + Duration::from_secs(30),
            next_media_sync: std::time::Instant::now() + Duration::from_secs(30),
        };
        let document = runtime.document()?;
        for id in document.retired_pair_ids() {
            runtime.engine.retire_pair_policy(id).map_err(store_error)?;
        }
        for pair in &document.config().pairs {
            runtime.check(authorized)?;
            // A disconnected drive must not hide all settings or prevent removal.
            if let Ok(pin) = runtime.admit_pair(pair, &document, Some(&pair.id)) {
                runtime.roots.insert(pair.id.clone(), pin);
            }
            runtime
                .engine
                .publish_pair_policy(pair)
                .map_err(store_error)?;
        }
        runtime.check(authorized)?;
        Ok(runtime)
    }
    pub fn pause_snapshot(&self) -> Result<(bool, Vec<String>), String> {
        let document = self.document()?;
        Ok((document.paused(), document.paused_space_ids().to_vec()))
    }
    pub fn revocation_handle(&self) -> SyncRevocationHandle {
        self.engine.revocation_handle()
    }
    fn document(&self) -> Result<FolderPairsDocument, String> {
        self.store
            .load()
            .map_err(store_error)?
            .ok_or_else(|| "Folder settings are unavailable".into())
    }
    fn space(&self, id: &str) -> Result<&CloudSpace, String> {
        self.spaces
            .iter()
            .find(|space| space.id == id && !space.encrypted)
            .ok_or_else(|| "This Space is unavailable to ordinary folder sync".into())
    }
    // Keep the shared ordinary-root helper usable by media admission without
    // making a job reject its own source. Only pair callers add this check.
    fn admit_pair(
        &self,
        pair: &FolderPair,
        document: &FolderPairsDocument,
        replacing: Option<&str>,
    ) -> Result<PinnedDirectory, String> {
        let pin = self.admit(pair, document.config(), replacing)?;
        self.check_source_admission(
            &pair.local_path,
            &pin,
            windows_profile_registry::SourceKind::FolderPair,
            &pair.id,
        )?;
        ensure_pair_media_sources_disjoint(
            &pair.local_path,
            &self.account_id,
            document.media_jobs(),
        )?;
        Ok(pin)
    }
    fn check_source_admission(
        &self,
        path: &Path,
        pin: &PinnedDirectory,
        kind: windows_profile_registry::SourceKind,
        id: &str,
    ) -> Result<(), String> {
        let SourceAdmissions::Broker { profile, registry } = &self.source_admissions;
        // Clone immutable admission state, releasing its independent mutex
        // before physical checks/network/SQL. No worker calls back to broker.
        let snapshot = registry
            .lock()
            .map_err(|_| "Source admission is unavailable")?
            .clone();
        let identity = pin.identity();
        if !source_receipt_matches(
            &snapshot,
            profile,
            &self.scope_digest,
            kind,
            id,
            path,
            ConfiguredRootIdentity {
                volume_serial: identity.volume_serial,
                file_index: identity.file_index,
            },
        ) {
            return Err(if snapshot.profiles().contains_key(profile) {
                "This saved source needs broker admission; settings and local data were preserved"
            } else {
                "Source account is unavailable"
            }
            .into());
        }
        pin.verify_path()
            .map_err(|_| "The admitted source changed".into())
    }

    fn admit(
        &self,
        pair: &FolderPair,
        config: &Config,
        replacing: Option<&str>,
    ) -> Result<PinnedDirectory, String> {
        if pair.vault.is_some() || !pair.local_path.is_absolute() {
            return Err("Choose an ordinary absolute local folder".into());
        }
        let space = self.space(&pair.space_id)?;
        if pair.mode != SyncMode::DownloadOnly && !space.writable {
            return Err("The selected Space is read only".into());
        }
        let pin = PinnedDirectory::open(&pair.local_path)
            .map_err(|_| "The local folder is unavailable or contains a reparse point")?;
        if overlaps_private_state(&pair.local_path, None)? {
            return Err("Folder sync cannot use Raiun's private app data".into());
        }
        if let Some(root) = &self.cloud_root {
            let registered = root
                .registration_ownership
                .as_ref()
                .is_some_and(|owner| owner.state == "registered");
            let overlap = if registered {
                raiun_cloudfiles_windows::registered_configured_root_overlaps(
                    Path::new(&root.path),
                    raiun_cloudfiles_windows::ConfiguredRootIdentity {
                        volume_serial: root.volume_serial,
                        file_index: root.file_index,
                    },
                    &pair.local_path,
                )
            } else {
                configured_roots_overlap(Path::new(&root.path), &pair.local_path)
            }
            .map_err(|_| "Could not verify the drive-folder boundary")?;
            if overlap {
                return Err("Folder sync cannot overlap the Windows cloud drive".into());
            }
        }
        for other in &config.pairs {
            if replacing == Some(other.id.as_str()) {
                continue;
            }
            if configured_roots_overlap(&other.local_path, &pair.local_path)
                .map_err(|_| "Could not verify the folder boundaries")?
            {
                return Err("Configured folder pairs must not overlap".into());
            }
        }
        // Validate the selected ordinary remote folder using the same DAV
        // semantics as the existing Linux engine; encrypted targets fail closed.
        let remote = self
            .client
            .stat(&pair.space_id, &pair.remote_path)
            .map_err(|_| "Could not verify the selected cloud folder")?;
        if !remote.directory
            || remote.encrypted
            || (pair.mode != SyncMode::DownloadOnly && !remote.writable)
        {
            return Err("The selected cloud folder is unavailable for this sync mode".into());
        }
        Ok(pin)
    }
    pub fn handle(
        &mut self,
        request: FolderRequest,
        authorized: &AtomicU64,
    ) -> Result<Value, String> {
        self.check(authorized)?;
        let document = self.document()?;
        let mut config = document.config().clone();
        match request {
            FolderRequest::VaultInspect(request) => {
                self.inspect_vault_metadata(request, authorized)
            }
            FolderRequest::Media(request) => {
                let trusted_account_id = self.account_id.clone();
                self.handle_media_metadata(request, authorized, &trusted_account_id)
            }
            FolderRequest::Pause { paused } => {
                self.check(authorized)?;
                self.store
                    .set_pause(
                        document.revision(),
                        paused,
                        document.paused_space_ids().to_vec(),
                    )
                    .map_err(store_error)?;
                // This command runs only after any earlier sync finishes.
                // Never clear Engine's revocation flag to implement resume.
                Ok(json!({}))
            }
            FolderRequest::SpacePause { space_id, paused } => {
                self.space(&space_id)?;
                let mut ids = document.paused_space_ids().to_vec();
                ids.retain(|id| id != &space_id);
                if paused {
                    ids.push(space_id.clone());
                }
                ids.sort();
                self.check(authorized)?;
                self.store
                    .set_pause(document.revision(), document.paused(), ids.clone())
                    .map_err(store_error)?;
                Ok(json!({"space_id":space_id,"paused":paused,"paused_space_ids":ids}))
            }
            FolderRequest::Pairs => serde_json::to_value(config.pairs).map_err(store_error),
            FolderRequest::Transfers => {
                let transfers = self.engine.transfers(500).map_err(store_error)?;
                self.check(authorized)?;
                serde_json::to_value(transfers).map_err(store_error)
            }
            FolderRequest::Spaces => serde_json::to_value(&self.spaces).map_err(store_error),
            FolderRequest::List { space_id, path } => {
                self.space(&space_id)?;
                let mut entries = vec![];
                self.client
                    .list(&space_id, &path, &mut |entry| {
                        entries.push(entry);
                        Ok(())
                    })
                    .map_err(|_| "Could not browse the selected Space")?;
                self.check(authorized)?;
                serde_json::to_value(entries).map_err(store_error)
            }
            FolderRequest::Add(pair) => {
                if config.pairs.iter().any(|old| old.id == pair.id) {
                    return Err("This folder connection already exists".into());
                }
                let pin = self.admit_pair(&pair, &document, None)?;
                let policy = self
                    .engine
                    .prepare_pair_policy(&pair)
                    .map_err(store_error)?;
                config.pairs.push(pair.clone());
                self.check(authorized)?;
                self.store
                    .replace(document.revision(), config)
                    .map_err(store_error)?;
                policy.publish();
                self.roots.insert(pair.id, pin);
                Ok(json!({}))
            }
            FolderRequest::Update {
                id,
                expected_pair,
                expected_auth_generation,
                mode,
                content_filter,
                exclusions,
                excluded_paths,
            } => {
                if expected_auth_generation != self.generation {
                    return Err(
                        "Folder settings changed with the active account; refresh and retry".into(),
                    );
                }
                let Some(index) = config.pairs.iter().position(|pair| pair.id == id) else {
                    return Err("Folder connection not found".into());
                };
                if config.pairs[index] != expected_pair {
                    return Err(
                        "Folder connection changed before settings were saved; refresh and retry"
                            .into(),
                    );
                }
                let mut updated = expected_pair.clone();
                updated.mode = mode;
                updated.content_filter = content_filter;
                updated.exclusions = exclusions;
                updated.excluded_paths = excluded_paths;
                updated
                    .validate_exclusions()
                    .map_err(|_| "Folder exclusions are invalid")?;
                let policy = self
                    .engine
                    .prepare_pair_policy(&updated)
                    .map_err(store_error)?;
                config.pairs[index] = updated.clone();
                self.check(authorized)?;
                self.store
                    .replace(document.revision(), config)
                    .map_err(store_error)?;
                policy.publish();
                Ok(json!({"pair":updated}))
            }
            FolderRequest::Exclusions { id, excluded_paths } => {
                let pair = config
                    .pairs
                    .iter_mut()
                    .find(|pair| pair.id == id)
                    .ok_or("Folder connection not found")?;
                pair.excluded_paths = excluded_paths;
                let policy = self.engine.prepare_pair_policy(pair).map_err(store_error)?;
                let exclusions = pair.excluded_paths.clone();
                self.check(authorized)?;
                self.store
                    .replace(document.revision(), config)
                    .map_err(store_error)?;
                policy.publish();
                Ok(json!({"pair_id":id,"excluded_paths":exclusions}))
            }
            FolderRequest::Remove { id } => {
                if !config.pairs.iter().any(|pair| pair.id == id) {
                    return Ok(json!({}));
                }
                let policy = self
                    .engine
                    .prepare_pair_retirement(&id)
                    .map_err(store_error)?;
                config.pairs.retain(|pair| pair.id != id);
                self.check(authorized)?;
                self.store
                    .replace(document.revision(), config)
                    .map_err(store_error)?;
                policy.publish();
                self.roots.remove(&id);
                Ok(json!({}))
            }
            FolderRequest::SpaceDisconnect { space_id } => {
                let ids = config
                    .pairs
                    .iter()
                    .filter(|pair| pair.space_id == space_id)
                    .map(|pair| pair.id.clone())
                    .collect::<Vec<_>>();
                if ids.is_empty() {
                    return Ok(json!({"space_id":space_id,"removed_pair_ids":ids}));
                }
                let policy = self
                    .engine
                    .prepare_pair_retirements(&ids)
                    .map_err(store_error)?;
                config.pairs.retain(|pair| pair.space_id != space_id);
                self.check(authorized)?;
                self.store
                    .replace(document.revision(), config)
                    .map_err(store_error)?;
                policy.publish();
                for id in &ids {
                    self.roots.remove(id);
                }
                Ok(json!({"space_id":space_id,"removed_pair_ids":ids}))
            }
            FolderRequest::Sync { .. } => {
                Err("Sync work must be queued by the Windows worker".into())
            }
        }
    }
    pub fn prepare_sync(
        &self,
        space: Option<&str>,
        authorized: &AtomicU64,
    ) -> Result<(u64, Vec<FolderPair>), String> {
        self.check(authorized)?;
        if let Some(id) = space {
            self.space(id)?;
        }
        let document = self.document()?;
        if document.paused() {
            return Err("Sync is paused globally".into());
        }
        if space.is_some_and(|id| {
            document
                .paused_space_ids()
                .iter()
                .any(|paused| paused == id)
        }) {
            return Err("Sync is paused for this Space".into());
        }
        let pairs = document
            .config()
            .pairs
            .iter()
            .filter(|pair| {
                space.is_none_or(|id| pair.space_id == id)
                    && !document.paused_space_ids().contains(&pair.space_id)
            })
            .cloned()
            .collect::<Vec<_>>();
        if pairs.is_empty() {
            return Err("No folder connections are configured for this selection".into());
        }
        Ok((document.revision(), pairs))
    }
    pub fn run_sync(
        &mut self,
        revision: u64,
        pairs: Vec<FolderPair>,
        authorized: &AtomicU64,
    ) -> Result<(), String> {
        for pair in pairs {
            self.check(authorized)?;
            let current = self.document()?;
            if current.paused()
                || current.paused_space_ids().contains(&pair.space_id)
                || current.revision() != revision
                || !current.config().pairs.contains(&pair)
            {
                return Err("Folder settings changed before sync".into());
            }
            // Only a never-admitted restored pair may acquire its first pin.
            // Existing pins are verified below and never silently replaced.
            if !self.roots.contains_key(&pair.id) {
                let pin = self.admit_pair(&pair, &current, Some(&pair.id))?;
                self.check(authorized)?;
                self.roots.insert(pair.id.clone(), pin);
            }
            self.roots
                .get(&pair.id)
                .ok_or("The local folder was not admitted")?
                .verify_path()
                .map_err(|_| "The selected local folder changed")?;
            self.check_source_admission(
                &pair.local_path,
                self.roots
                    .get(&pair.id)
                    .ok_or("The local folder was not admitted")?,
                windows_profile_registry::SourceKind::FolderPair,
                &pair.id,
            )?;
            self.engine.sync_pair(&pair).map_err(
                |_| "Folder sync needs attention; local and recovery data were preserved",
            )?;
        }
        Ok(())
    }
    /// Idle-only ordinary reconciliation, not recovered-edit replay.
    pub fn periodic_tick(&mut self, authorized: &AtomicU64) -> Option<Result<(), String>> {
        if self.check(authorized).is_err() || std::time::Instant::now() < self.next_periodic_sync {
            return None;
        }
        if self.document().is_ok_and(|document| {
            document.paused()
                || document
                    .config()
                    .pairs
                    .iter()
                    .all(|pair| document.paused_space_ids().contains(&pair.space_id))
        }) {
            self.next_periodic_sync = std::time::Instant::now() + Duration::from_secs(30);
            return None;
        }
        let result = (|| {
            let (revision, pairs) = self.prepare_sync(None, authorized)?;
            self.run_sync(revision, pairs, authorized)
        })();
        // Unix ordinary cadence is 30 seconds; failures wait a full minute.
        self.next_periodic_sync =
            std::time::Instant::now() + Duration::from_secs(if result.is_ok() { 30 } else { 60 });
        Some(result)
    }
    fn check(&self, authorized: &AtomicU64) -> Result<(), String> {
        if self.generation == 0 || authorized.load(Ordering::Acquire) != self.generation {
            Err("The account changed before folder work".into())
        } else {
            Ok(())
        }
    }
}

// Disabled jobs still retain their source/recovery state. Cross-profile source
// admission remains broker-owned; this checks only the current account.
fn ensure_pair_media_sources_disjoint(
    local_path: &Path,
    account_id: &str,
    jobs: &[MediaImportJob],
) -> Result<(), String> {
    for job in jobs.iter().filter(|job| job.account_id == account_id) {
        if configured_roots_overlap(&job.source_root, local_path)
            .map_err(|_| "Could not verify media source boundaries")?
        {
            return Err("Folder sync cannot overlap a media backup source".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod source_overlap_tests {
    use super::*;

    #[test]
    fn source_receipt_requires_exact_profile_scope_kind_id_path_and_physical_identity() {
        use windows_profile_registry::{RootReservation, SourceReservation};
        let profile = "profile-11111111111111111111111111111111";
        let foreign_profile = "profile-22222222222222222222222222222222";
        let scope = "a".repeat(64);
        let path = Path::new(r"C:\SyntheticSource");
        let identity = ConfiguredRootIdentity {
            volume_serial: 7,
            file_index: 11,
        };
        let snapshot = Registry::decode_or_default(None)
            .unwrap()
            .with_added(profile, "Synthetic A")
            .unwrap()
            .with_added(foreign_profile, "Synthetic B")
            .unwrap()
            .with_reserved_source(
                profile,
                SourceReservation::new(
                    scope.clone(),
                    SourceKind::FolderPair,
                    "pair-one".into(),
                    RootReservation::new(r"C:\SyntheticSource".into(), 7, 11, false).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let matches = |profile, scope, kind, id, path, identity| {
            source_receipt_matches(&snapshot, profile, scope, kind, id, path, identity)
        };
        assert!(matches(
            profile,
            &scope,
            SourceKind::FolderPair,
            "pair-one",
            path,
            identity
        ));
        assert!(!matches(
            foreign_profile,
            &scope,
            SourceKind::FolderPair,
            "pair-one",
            path,
            identity
        ));
        let foreign_scope = "b".repeat(64);
        assert!(!matches(
            profile,
            &foreign_scope,
            SourceKind::FolderPair,
            "pair-one",
            path,
            identity
        ));
        assert!(!matches(
            profile,
            &scope,
            SourceKind::MediaJob,
            "pair-one",
            path,
            identity
        ));
        assert!(!matches(
            profile,
            &scope,
            SourceKind::FolderPair,
            "pair-other",
            path,
            identity
        ));
        assert!(!matches(
            profile,
            &scope,
            SourceKind::FolderPair,
            "pair-one",
            Path::new(r"C:\Other"),
            identity
        ));
        assert!(!matches(
            profile,
            &scope,
            SourceKind::FolderPair,
            "pair-one",
            path,
            ConfiguredRootIdentity {
                volume_serial: 8,
                ..identity
            }
        ));
        assert!(!matches(
            profile,
            &scope,
            SourceKind::FolderPair,
            "pair-one",
            path,
            ConfiguredRootIdentity {
                file_index: 12,
                ..identity
            }
        ));
    }

    #[test]
    fn folder_pair_rejects_existing_media_source_without_replacing_its_own_job() {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let nonce: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let temp = std::env::temp_dir().join(format!("raiun-pair-media-overlap-{nonce}"));
        std::fs::create_dir(&temp).unwrap();
        let source = temp.join("photos");
        let child = source.join("child");
        let separate = temp.join("documents");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::create_dir(&separate).unwrap();
        let job = MediaImportJob {
            id: "same-as-pair".into(),
            revision: 1,
            account_id: "synthetic-account".into(),
            source_root: source.clone(),
            space_id: "synthetic-space".into(),
            destination_root: "/backup".into(),
            destination_root_resource_id: "synthetic-destination".into(),
            filter: raiun_core::MediaFilter::All,
            exclusions: Vec::new(),
            organization: raiun_core::MediaOrganization::PreserveRelativePath,
            filesystem_mtime_utc: false,
            interval_seconds: 3600,
            enabled: false,
        };
        // A disabled media job is still reserved, even if its ID equals a pair ID.
        let jobs = [job];
        for path in [source.as_path(), child.as_path(), temp.as_path()] {
            assert!(ensure_pair_media_sources_disjoint(path, "synthetic-account", &jobs).is_err());
        }
        assert!(ensure_pair_media_sources_disjoint(&separate, "synthetic-account", &jobs).is_ok());
        assert!(ensure_pair_media_sources_disjoint(&source, "different-account", &jobs).is_ok());
        std::fs::remove_dir_all(&temp).unwrap();
    }
}

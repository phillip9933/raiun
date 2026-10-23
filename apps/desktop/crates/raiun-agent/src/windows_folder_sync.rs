//! Ordinary folder work owned by the existing Windows command thread.
use super::*;
use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
use raiun_core::{CONFIG_SCHEMA_VERSION, Config, FolderPair, SyncMode};
use raiun_engine::{
    Engine, SyncRevocationHandle,
    folder_pairs::{AccountScope, FolderPairsDocument, FolderPairsStore},
};
use std::collections::BTreeMap;
use windows_folder_requests::FolderRequest;

pub(super) struct Setup {
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
    pub generation: u64,
    engine: Engine,
    store: FolderPairsStore,
    client: Arc<OpenCloudClient>,
    spaces: Vec<CloudSpace>,
    roots: BTreeMap<String, PinnedDirectory>,
    cloud_root: Option<RootConfiguration>,
}

fn store_error(_: impl std::fmt::Debug) -> String {
    "Folder settings could not be read or saved; previous settings were preserved".into()
}
impl Runtime {
    pub fn open(setup: Setup, authorized: &AtomicU64) -> Result<Self, String> {
        if setup.generation == 0 || authorized.load(Ordering::Acquire) != setup.generation {
            return Err("The account changed before folder setup".into());
        }
        let engine = Engine::open_private_windows(setup.directory, setup.client.clone())
            .and_then(|engine| engine.with_account_scope(setup.account_id, setup.origin))
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
            generation: setup.generation,
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
        };
        let document = runtime.document()?;
        for id in document.retired_pair_ids() {
            runtime.engine.retire_pair_policy(id).map_err(store_error)?;
        }
        for pair in &document.config().pairs {
            runtime.check(authorized)?;
            // A disconnected drive must not hide all settings or prevent removal.
            if let Ok(pin) = runtime.admit(pair, document.config(), Some(&pair.id)) {
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
            FolderRequest::Pairs => serde_json::to_value(config.pairs).map_err(store_error),
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
                let pin = self.admit(&pair, &config, None)?;
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
        let pairs = document
            .config()
            .pairs
            .iter()
            .filter(|pair| space.is_none_or(|id| pair.space_id == id))
            .cloned()
            .collect::<Vec<_>>();
        if pairs.is_empty() {
            return Err("No folder connections are configured for this selection".into());
        }
        Ok((document.revision(), pairs))
    }
    pub fn run_sync(
        &self,
        revision: u64,
        pairs: Vec<FolderPair>,
        authorized: &AtomicU64,
    ) -> Result<(), String> {
        for pair in pairs {
            self.check(authorized)?;
            let current = self.document()?;
            if current.revision() != revision || !current.config().pairs.contains(&pair) {
                return Err("Folder settings changed before sync".into());
            }
            self.roots
                .get(&pair.id)
                .ok_or("The local folder was not admitted")?
                .verify_path()
                .map_err(|_| "The selected local folder changed")?;
            self.engine.sync_pair(&pair).map_err(
                |_| "Folder sync needs attention; local and recovery data were preserved",
            )?;
        }
        Ok(())
    }
    fn check(&self, authorized: &AtomicU64) -> Result<(), String> {
        if self.generation == 0 || authorized.load(Ordering::Acquire) != self.generation {
            Err("The account changed before folder work".into())
        } else {
            Ok(())
        }
    }
}

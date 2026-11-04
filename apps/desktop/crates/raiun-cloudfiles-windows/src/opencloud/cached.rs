//! Cached namespace strategy: original protected identities locate metadata,
//! never online role/token/write authority. File bytes are served only by an
//! installed verified offline vault route; ordinary missing data refuses.
use super::*;
fn logical_parent(path: &str) -> &str {
    path.rsplit_once('/')
        .map(|(p, _)| if p.is_empty() { "/" } else { p })
        .unwrap_or("/")
}
impl OpenCloudPlaceholderBackend {
    pub fn list_cached_vault(
        &self,
        space: &str,
        root: &str,
        path: &str,
        logical: &str,
    ) -> Result<Vec<raiun_core::backend::RemoteEntry>, BackendError> {
        self.ensure_active()?;
        if !self.cached_only {
            return Err(BackendError::Unavailable);
        }
        let route = self
            .vault_routes
            .as_ref()
            .ok_or(BackendError::Unavailable)?
            .exact_root(space, root, path)?
            .ok_or(BackendError::NotFound)?;
        route
            .backend()
            .binding()
            .list(logical)
            .map_err(|_| BackendError::Unavailable)
    }

    pub fn offline_client(&self) -> Result<Arc<OpenCloudClient>, BackendError> {
        self.ensure_active()?;
        if !self.cached_only || !self.client.is_offline() {
            return Err(BackendError::Unavailable);
        }
        Ok(self.client.clone())
    }
    pub fn new_cached_only(
        client: Arc<OpenCloudClient>,
        scope: ProviderScope,
        root: crate::ConfiguredRootIdentity,
        catalog: Arc<dyn ProviderIdentityCatalog>,
        personal_space: &str,
        personal_root: &str,
        encrypted_locations: &[(String, String)],
    ) -> Result<Self, BackendError> {
        if !client.is_offline() {
            return Err(BackendError::Unavailable);
        }
        let mut backend = Self::new_with_identity_catalog(client, scope, root, catalog)?;
        backend.restore_vault_exclusions(root, encrypted_locations)?;
        backend.cached_only = true;
        backend.register_cached_composite(personal_space, personal_root)?;
        Ok(backend)
    }
    pub(super) fn register_cached_composite(
        &self,
        personal_space: &str,
        personal_root: &str,
    ) -> Result<OpaqueIdentity, BackendError> {
        self.ensure_active()?;
        if !self.cached_only
            || !self.client.is_offline()
            || !valid_remote_id(personal_space)
            || !valid_remote_id(personal_root)
        {
            return Err(BackendError::Unavailable);
        }
        let identity = composite_root_identity(&self.scope, personal_space, personal_root);
        if self.owns_composite_root_identity(identity) {
            return Ok(identity);
        }
        self.load_catalog_for_root(personal_space, personal_root)?
            .ok_or(BackendError::Unavailable)?;
        let mut state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
        if !state.directories.values().any(|d| {
            d.space_id == personal_space
                && d.root_resource_id == personal_root
                && d.path == "/"
                && d.remote_id == personal_root
        }) {
            return Err(BackendError::Unavailable);
        }
        if identity_in_use(&state, identity) {
            return Err(BackendError::Unavailable);
        }
        state.location_labels.insert(
            (personal_space.into(), personal_root.into()),
            "Personal".into(),
        );
        state.namespace_directories.insert(
            identity,
            NamespaceDirectory::Root {
                account_id: self.scope.account_id.clone(),
                personal_space_id: personal_space.into(),
                personal_root_id: personal_root.into(),
            },
        );
        Ok(identity)
    }
    pub(super) fn enumerate_cached(
        &self,
        identity: OpaqueIdentity,
    ) -> Result<Vec<PlaceholderChild>, BackendError> {
        self.ensure_active()?;
        let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
        let mut result = Vec::new();
        let make = |name: String, id: OpaqueIdentity| PlaceholderChild {
            name,
            identity: id.as_bytes().to_vec(),
            metadata: PlaceholderMetadata {
                is_directory: true,
                length: 0,
            },
            last_write_time: 0,
        };
        match state.namespace_directories.get(&identity) {
            Some(NamespaceDirectory::Root {
                account_id,
                personal_space_id,
                personal_root_id,
            }) => {
                if account_id != self.scope.account_id() {
                    return Err(BackendError::Unavailable);
                }
                let mut roots = state.directories.iter().filter(|(_, d)| {
                    d.space_id == *personal_space_id
                        && d.root_resource_id == *personal_root_id
                        && d.path == "/"
                        && d.remote_id == *personal_root_id
                });
                let (id, _) = roots.next().ok_or(BackendError::Unavailable)?;
                if roots.next().is_some() {
                    return Err(BackendError::Unavailable);
                }
                result.push(make("Personal".into(), *id));
                let mut namespaces =
                    state
                        .namespace_directories
                        .iter()
                        .filter_map(|(id, n)| match n {
                            NamespaceDirectory::Spaces {
                                account_id: a,
                                personal_space_id: s,
                                personal_root_id: r,
                            } if a == account_id
                                && s == personal_space_id
                                && r == personal_root_id =>
                            {
                                Some(*id)
                            }
                            _ => None,
                        });
                let spaces = namespaces.next().ok_or(BackendError::Unavailable)?;
                if namespaces.next().is_some() {
                    return Err(BackendError::Unavailable);
                }
                result.push(make("Spaces".into(), spaces));
            }
            Some(NamespaceDirectory::Spaces { .. }) => {
                for (id, d) in &state.directories {
                    if d.path == "/"
                        && d.remote_id == d.root_resource_id
                        && d.space_id != self.personal_cached_space(&state)?
                    {
                        if let Some(name) = state
                            .location_labels
                            .get(&(d.space_id.clone(), d.root_resource_id.clone()))
                            .and_then(|s| s.strip_prefix("Spaces / "))
                        {
                            result.push(make(name.into(), *id));
                        }
                    }
                }
            }
            None => {
                let parent = state
                    .directories
                    .get(&identity)
                    .ok_or(BackendError::NotFound)?;
                for (id, d) in &state.directories {
                    if d.space_id == parent.space_id
                        && d.root_resource_id == parent.root_resource_id
                        && d.path != parent.path
                        && logical_parent(&d.path) == parent.path
                    {
                        let name = d
                            .path
                            .rsplit('/')
                            .next()
                            .filter(|n| valid_windows_component(n))
                            .ok_or(BackendError::Unavailable)?;
                        result.push(make(name.into(), *id));
                    }
                }
                // Locked encrypted targets have no ordinary catalogue alias.
                // Live offline routes are added below after releasing state.
            }
        }
        if result.len() > MAX_DIRECTORY_CHILDREN {
            return Err(BackendError::Unavailable);
        }
        let parent = state.directories.get(&identity).cloned();
        drop(state);
        if let Some(parent) = parent {
            if let Some(registry) = &self.vault_routes {
                for route in registry.snapshot()? {
                    if route.space_id() == parent.space_id
                        && route.root_path() != parent.path
                        && logical_parent(route.root_path()) == parent.path
                    {
                        let name = route
                            .root_path()
                            .rsplit('/')
                            .next()
                            .filter(|s| valid_windows_component(s))
                            .ok_or(BackendError::Unavailable)?;
                        result.retain(|c| c.name != name);
                        result.push(make(
                            name.into(),
                            OpaqueIdentity(route.backend().root_identity()),
                        ));
                    }
                }
            }
        }
        if matches!(
            self.state
                .lock()
                .map_err(|_| BackendError::Unavailable)?
                .namespace_directories
                .get(&identity),
            Some(NamespaceDirectory::Spaces { .. })
        ) {
            if let Some(routes) = &self.vault_routes {
                for route in routes.snapshot()? {
                    if route.root_path() == "/" {
                        let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
                        if let Some(label) = state
                            .location_labels
                            .get(&(route.space_id().into(), route.root_resource_id().into()))
                            .and_then(|s| s.strip_prefix("Spaces / "))
                        {
                            result.push(make(
                                label.into(),
                                OpaqueIdentity(route.backend().root_identity()),
                            ));
                        }
                    }
                }
            }
        }
        result.sort_by(|a, b| a.name.cmp(&b.name));
        if result.len() > MAX_DIRECTORY_CHILDREN
            || result
                .windows(2)
                .any(|w| w[0].name.to_lowercase() == w[1].name.to_lowercase())
        {
            return Err(BackendError::Unavailable);
        }
        Ok(result)
    }
    // A native name is presentation only, joined to a protected root opaque.
    pub(crate) fn cached_space_roots(&self) -> Result<Vec<PlaceholderChild>, BackendError> {
        if !self.cached_only {
            return Err(BackendError::Unavailable);
        }
        let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
        let personal = self.personal_cached_space(&state)?;
        let mut result = state
            .directories
            .iter()
            .filter(|(_, d)| {
                d.path == "/" && d.remote_id == d.root_resource_id && d.space_id != personal
            })
            .map(|(id, _)| PlaceholderChild {
                name: String::new(),
                identity: id.as_bytes().to_vec(),
                metadata: PlaceholderMetadata {
                    is_directory: true,
                    length: 0,
                },
                last_write_time: 0,
            })
            .collect::<Vec<_>>();
        drop(state);
        if let Some(routes) = &self.vault_routes {
            for route in routes.snapshot()? {
                if route.root_path() == "/" && route.space_id() != personal {
                    result.push(PlaceholderChild {
                        name: String::new(),
                        identity: route.backend().root_identity().to_vec(),
                        metadata: PlaceholderMetadata {
                            is_directory: true,
                            length: 0,
                        },
                        last_write_time: 0,
                    });
                }
            }
        }
        Ok(result)
    }
    pub(crate) fn set_cached_space_label(
        &self,
        identity: &[u8],
        name: &str,
    ) -> Result<(), BackendError> {
        if !self.cached_only || !valid_windows_component(name) {
            return Err(BackendError::Unavailable);
        }
        let opaque = OpaqueIdentity(identity.try_into().map_err(|_| BackendError::Unavailable)?);
        let key = {
            let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
            state
                .directories
                .get(&opaque)
                .filter(|d| d.path == "/" && d.remote_id == d.root_resource_id)
                .map(|d| (d.space_id.clone(), d.root_resource_id.clone()))
        };
        let key = match key {
            Some(k) => k,
            None => {
                let route = self
                    .vault_routes
                    .as_ref()
                    .ok_or(BackendError::Unavailable)?
                    .resolve_identity(identity)?
                    .filter(|r| {
                        r.root_path() == "/" && r.backend().root_identity().as_slice() == identity
                    })
                    .ok_or(BackendError::Unavailable)?;
                (route.space_id().into(), route.root_resource_id().into())
            }
        };
        let mut state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
        let label = format!("Spaces / {name}");
        if state
            .location_labels
            .iter()
            .any(|(k, v)| k != &key && v.to_lowercase() == label.to_lowercase())
        {
            return Err(BackendError::Unavailable);
        }
        state.location_labels.insert(key, label);
        Ok(())
    }
    fn personal_cached_space(&self, state: &State) -> Result<String, BackendError> {
        let mut roots = state
            .namespace_directories
            .values()
            .filter_map(|n| match n {
                NamespaceDirectory::Root {
                    account_id,
                    personal_space_id,
                    ..
                } if account_id == self.scope.account_id() => Some(personal_space_id.clone()),
                _ => None,
            });
        let root = roots.next().ok_or(BackendError::Unavailable)?;
        if roots.next().is_some() {
            return Err(BackendError::Unavailable);
        }
        Ok(root)
    }
}

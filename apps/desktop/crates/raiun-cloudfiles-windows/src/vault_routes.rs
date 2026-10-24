//! Account/root-bound route inventory for the existing single native cloud root.
//! This module does not register a root or grant native projection by itself.
use crate::vault_placeholder::WindowsVaultPlaceholderBackend;
use crate::{BackendError, ConfiguredRootIdentity, ProviderScope};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

const MAX_ROUTES: usize = 16;

pub struct VerifiedVaultRoute {
    local_root: ConfiguredRootIdentity,
    space_id: String,
    root_resource_id: String,
    root_path: String,
    backend: Arc<WindowsVaultPlaceholderBackend>,
}
impl VerifiedVaultRoute {
    /// Cancel and drain this retained route; this alone does not clean local plaintext.
    pub fn revoke_hydration(&self) -> Result<(), BackendError> {
        self.backend
            .binding()
            .revoke()
            .map_err(|_| BackendError::Unavailable)
    }
    pub(crate) fn local_root(&self) -> ConfiguredRootIdentity {
        self.local_root
    }
    pub(crate) fn revoke_and_cleanup_identities(
        &self,
    ) -> Result<std::collections::BTreeSet<[u8; 16]>, BackendError> {
        self.backend
            .binding()
            .revoke()
            .map_err(|_| BackendError::Unavailable)?;
        self.backend.cleanup_identities()
    }
    pub fn backend(&self) -> &Arc<WindowsVaultPlaceholderBackend> {
        &self.backend
    }
    pub fn space_id(&self) -> &str {
        &self.space_id
    }
    pub fn root_resource_id(&self) -> &str {
        &self.root_resource_id
    }
    pub fn root_path(&self) -> &str {
        &self.root_path
    }
}

pub struct VaultRouteRegistry {
    owner: ProviderScope,
    local_root: ConfiguredRootIdentity,
    revoked: AtomicBool,
    routes: Mutex<Vec<Arc<VerifiedVaultRoute>>>,
    known_roots: Mutex<Vec<(String, String)>>,
}
impl VaultRouteRegistry {
    /// The owner must supply its authenticated provider and retained native
    /// root identity. This does not pin a filesystem path or connect Cloud Files.
    pub fn new(owner: ProviderScope, local_root: ConfiguredRootIdentity) -> Self {
        Self {
            owner,
            local_root,
            revoked: AtomicBool::new(false),
            routes: Mutex::new(Vec::new()),
            known_roots: Mutex::new(Vec::new()),
        }
    }

    /// Restore historical exclusions only. No session, active route, or key is
    /// created. The trusted broker supplies every saved path for this profile,
    /// including paths recorded under earlier account credentials/root folders.
    pub(crate) fn restore_exclusions(
        &self,
        expected_local_root: ConfiguredRootIdentity,
        locations: &[(String, String)],
    ) -> Result<(), BackendError> {
        if self.local_root.file_index == 0
            || expected_local_root != self.local_root
            || self.revoked.load(Ordering::Acquire)
            || locations.len() > 128
        {
            return Err(BackendError::Unavailable);
        }
        let mut known = self
            .known_roots
            .lock()
            .map_err(|_| BackendError::Unavailable)?;
        let mut next = known.clone();
        for (space, path) in locations {
            let canonical = path == "/"
                || (path.starts_with('/')
                    && !path.ends_with('/')
                    && path[1..]
                        .split('/')
                        .all(|part| !part.is_empty() && part != "." && part != ".."));
            if space.trim().is_empty()
                || space.len() > 4096
                || space.chars().any(char::is_control)
                || path.len() > 32_000
                || path.contains('\\')
                || path.chars().any(char::is_control)
                || !canonical
            {
                return Err(BackendError::Unavailable);
            }
            if !next.contains(&(space.clone(), path.clone())) {
                if next.len() >= 128 {
                    return Err(BackendError::Unavailable);
                }
                next.push((space.clone(), path.clone()));
            }
        }
        if self.revoked.load(Ordering::Acquire) {
            return Err(BackendError::Unavailable);
        }
        *known = next;
        Ok(())
    }

    /// Disable further admission atomically before taking route ownership.
    /// The caller retains these Arcs across revoke/drain and cleanup failures.
    /// Remove only this exact target from active projection, retaining its Arc
    /// for the worker's revoke/drain/cleanup sequence and failed retries.
    pub(crate) fn retire_one(
        &self,
        space: &str,
        root_id: &str,
        root_path: &str,
    ) -> Result<Option<Arc<VerifiedVaultRoute>>, BackendError> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(BackendError::Unavailable);
        }
        let mut routes = self
            .routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let target = routes.iter().position(|route| {
            route.space_id == space
                && route.root_resource_id == root_id
                && route.root_path == normalize(root_path)
        });
        Ok(target.map(|index| routes.remove(index)))
    }

    pub(crate) fn retire_all(&self) -> Result<Vec<Arc<VerifiedVaultRoute>>, BackendError> {
        self.revoked.store(true, Ordering::Release);
        // Poison is not authority to resume use, but Rust still owns every Arc.
        // Recover ownership solely to revoke/retain it; admission stays revoked.
        let mut routes = self
            .routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(std::mem::take(&mut *routes))
    }

    pub fn install(
        &self,
        backend: Arc<WindowsVaultPlaceholderBackend>,
        expected_local_root: ConfiguredRootIdentity,
    ) -> Result<Arc<VerifiedVaultRoute>, BackendError> {
        if self.local_root.file_index == 0
            || expected_local_root != self.local_root
            || self.revoked.load(Ordering::Acquire)
        {
            return Err(BackendError::Unavailable);
        }
        let (space_id, root_resource_id, root_path) = backend
            .binding()
            .route_location(&self.owner)
            .map_err(|_| BackendError::Unavailable)?;
        // Never hold the inventory lock while acquiring publication leases.
        backend
            .binding()
            .with_publication(|| {
                // Retain an exclusion even after lock/removal. A known encrypted
                // location must never silently fall back to ordinary callbacks.
                let mut known = self.known_roots.lock().map_err(|_| refused())?;
                if !known
                    .iter()
                    .any(|(space, path)| space == &space_id && path == &root_path)
                {
                    if known.len() >= 128 {
                        return Err(refused());
                    }
                    known.push((space_id.clone(), root_path.clone()));
                }
                let mut routes = self.routes.lock().map_err(|_| refused())?;
                if self.revoked.load(Ordering::Acquire)
                    || routes.len() >= MAX_ROUTES
                    || routes.iter().any(|old| {
                        old.space_id == space_id
                            && (old.root_resource_id == root_resource_id
                                || overlaps(&old.root_path, &root_path))
                    })
                {
                    return Err(refused());
                }
                let route = Arc::new(VerifiedVaultRoute {
                    local_root: self.local_root,
                    space_id,
                    root_resource_id,
                    root_path,
                    backend: Arc::clone(&backend),
                });
                routes.push(Arc::clone(&route));
                Ok(route)
            })
            .map_err(|_| BackendError::Unavailable)
    }

    /// Resolve only the exact freshly observed directory root. All other
    /// encrypted entries stay unsupported by the ordinary provider.
    pub fn exact_root(
        &self,
        space: &str,
        path: &str,
        resource_id: &str,
    ) -> Result<Option<Arc<VerifiedVaultRoute>>, BackendError> {
        let routes = self.snapshot()?;
        let route = routes.into_iter().find(|route| {
            route.space_id == space
                && route.root_resource_id == resource_id
                && route.root_path == normalize(path)
        });
        if let Some(route) = &route {
            route
                .backend
                .binding()
                .route_location(&self.owner)
                .map_err(|_| BackendError::Unavailable)?;
        }
        Ok(route)
    }

    pub(crate) fn has_root_id(&self, space: &str, root_id: &str) -> Result<bool, BackendError> {
        Ok(self
            .snapshot()?
            .iter()
            .any(|route| route.space_id == space && route.root_resource_id == root_id))
    }

    pub fn has_space_root(&self, space: &str) -> Result<bool, BackendError> {
        Ok(self
            .snapshot()?
            .iter()
            .any(|route| route.space_id == space && route.root_path == "/"))
    }

    pub fn has_direct_child(&self, space: &str, parent: &str) -> Result<bool, BackendError> {
        let known = self
            .known_roots
            .lock()
            .map_err(|_| BackendError::Unavailable)?;
        Ok(known.iter().any(|(known_space, path)| {
            if known_space != space || path == "/" {
                return false;
            }
            let parent_path = path
                .rsplit_once('/')
                .map(|(prefix, _)| if prefix.is_empty() { "/" } else { prefix })
                .unwrap_or("/");
            normalize(parent) == parent_path
        }))
    }

    pub fn is_known_root(&self, space: &str, path: &str) -> Result<bool, BackendError> {
        Ok(self
            .known_roots
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .iter()
            .any(|(known_space, known_path)| known_space == space && known_path == normalize(path)))
    }

    pub fn covers_path(&self, space: &str, path: &str) -> Result<bool, BackendError> {
        Ok(self
            .known_roots
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .iter()
            .any(|(known_space, root)| {
                known_space == space
                    && (root == "/"
                        || root == normalize(path)
                        || normalize(path)
                            .strip_prefix(root)
                            .is_some_and(|suffix| suffix.starts_with('/')))
            }))
    }

    pub fn resolve_identity(
        &self,
        identity: &[u8],
    ) -> Result<Option<Arc<VerifiedVaultRoute>>, BackendError> {
        let mut found = None;
        for route in self.snapshot()? {
            if route.backend.owns_identity(identity)? {
                if found.is_some() {
                    return Err(BackendError::Unavailable);
                }
                found = Some(route);
            }
        }
        if let Some(route) = &found {
            route
                .backend
                .binding()
                .route_location(&self.owner)
                .map_err(|_| BackendError::Unavailable)?;
        }
        Ok(found)
    }

    pub fn remove(&self, space: &str, resource_id: &str) -> Result<bool, BackendError> {
        let removed = {
            let mut routes = self.routes.lock().map_err(|_| BackendError::Unavailable)?;
            routes
                .iter()
                .position(|r| r.space_id == space && r.root_resource_id == resource_id)
                .map(|index| routes.remove(index))
        };
        if let Some(route) = removed {
            route
                .backend
                .binding()
                .revoke()
                .map_err(|_| BackendError::Unavailable)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Revoke and drain every route before the auth owner removes keys or
    /// changes credentials. Never wait on a route while holding inventory lock.
    pub fn revoke_all(&self) -> Result<(), BackendError> {
        self.revoked.store(true, Ordering::Release);
        let routes =
            std::mem::take(&mut *self.routes.lock().map_err(|_| BackendError::Unavailable)?);
        let mut failed = false;
        for route in routes {
            failed |= route.backend.binding().revoke().is_err();
        }
        if failed {
            Err(BackendError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn snapshot(&self) -> Result<Vec<Arc<VerifiedVaultRoute>>, BackendError> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(BackendError::Unavailable);
        }
        let routes = self
            .routes
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .clone();
        if self.revoked.load(Ordering::Acquire) {
            return Err(BackendError::Unavailable);
        }
        Ok(routes)
    }
}
fn normalize(path: &str) -> &str {
    if path == "/" {
        "/"
    } else {
        path.trim_end_matches('/')
    }
}
fn overlaps(a: &str, b: &str) -> bool {
    let a = normalize(a);
    let b = normalize(b);
    a == b
        || a == "/"
        || b == "/"
        || a.strip_prefix(b)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || b.strip_prefix(a)
            .is_some_and(|suffix| suffix.starts_with('/'))
}
fn refused() -> raiun_core::backend::CloudError {
    raiun_core::backend::CloudError::new(
        raiun_core::backend::ErrorKind::Forbidden,
        "Vault route admission refused",
    )
}

//! Worker-local metadata pins for one additive create health query. These are
//! actual registered-root/managed-route observations, never a connection owner.
use super::*;
use crate::fresh_create_target::{FreshCreateTargetKind, NativeCreateFacts};
use crate::opencloud::CapturedDirectoryParent;

pub(super) struct FreshNativeInspection {
    root_path: PathBuf,
    root: RootInspectionLease,
    parent: RawOwnedHandle,
    parent_snapshot: RootSnapshot,
    ancestors: Vec<(RawOwnedHandle, RootSnapshot)>,
    route: Vec<crate::PlaceholderChild>,
    leaf_path: PathBuf,
    leaf: RawOwnedHandle,
    leaf_snapshot: RootSnapshot,
    kind: FreshCreateTargetKind,
    facts: NativeCreateFacts,
}

impl FreshNativeInspection {
    pub(super) fn inspect(
        root_path: &Path,
        root_identity: crate::ConfiguredRootIdentity,
        captured: &CapturedDirectoryParent,
        parent_components: &[String],
        name: &str,
        kind: FreshCreateTargetKind,
    ) -> Result<Self, Error> {
        if captured.scope.root_volume_serial != root_identity.volume_serial
            || captured.scope.root_file_index != root_identity.file_index
            || !valid_component(name)
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let root = pin_registered_configured_root(root_path, root_identity)?;
        let components: Vec<_> = parent_components.iter().map(String::as_str).collect();
        let (parent, parent_snapshot, ancestors) =
            native_namespace_directory::pin_reinspected_namespace_parent(
                &root,
                root_path,
                &captured.route,
                captured.identity,
                &components,
            )?;
        let mut leaf_path = root_path.to_path_buf();
        for component in parent_components {
            leaf_path.push(component);
        }
        leaf_path.push(name);
        // Metadata only, OPEN_REPARSE_POINT, no DELETE sharing. These handles
        // stay on this worker for the full query and never authorize mutation.
        let leaf = match kind {
            FreshCreateTargetKind::Directory => open_root(
                &leaf_path,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
            )?,
            FreshCreateTargetKind::File => open_plain_leaf_metadata(&leaf_path)?,
        };
        let leaf_snapshot = root_snapshot(leaf.0)?;
        let local_id = |snapshot: RootSnapshot| crate::LocalFileIdentity {
            volume_serial: snapshot.identity.volume_serial,
            file_index: snapshot.identity.file_index,
        };
        let mut parents = vec![crate::LocalFileIdentity {
            volume_serial: root_identity.volume_serial,
            file_index: root_identity.file_index,
        }];
        parents.extend(ancestors.iter().map(|(_, snapshot)| local_id(*snapshot)));
        parents.push(local_id(parent_snapshot));
        let full_components = parent_components
            .iter()
            .cloned()
            .chain(std::iter::once(name.to_owned()))
            .collect();
        let facts = NativeCreateFacts::from_checked_pins(
            root_identity,
            full_components,
            kind,
            local_id(leaf_snapshot),
            parents,
        )
        .ok_or(Error::ConfiguredRootChanged)?;
        let result = Self {
            root_path: root_path.to_path_buf(),
            root,
            parent,
            parent_snapshot,
            ancestors,
            route: captured.route.clone(),
            leaf_path,
            leaf,
            leaf_snapshot,
            kind,
            facts,
        };
        result.verify()?;
        Ok(result)
    }

    pub(super) fn bind_space(&self, space: &mut crate::FreshCreateSpace) -> Result<(), Error> {
        self.verify()?;
        space
            .target
            .as_mut()
            .ok_or(Error::ProviderUnavailable)?
            .bind_native_custody(&space.scope, &self.facts)
            .ok_or(Error::ConfiguredRootChanged)
    }

    pub(super) fn facts(&self) -> &NativeCreateFacts {
        &self.facts
    }

    pub(super) fn verify(&self) -> Result<(), Error> {
        native_namespace_directory::verify_reinspected_namespace_root(&self.root, &self.root_path)?;
        if self.ancestors.len() + 1 != self.route.len() {
            return Err(Error::ConfiguredRootChanged);
        }
        let mut ancestor_path = self.root_path.clone();
        for ((handle, original), expected) in self.ancestors.iter().zip(&self.route) {
            ancestor_path.push(&expected.name);
            let observed = root_snapshot(handle.0)?;
            if observed.identity != original.identity
                || !valid_callback_directory_snapshot(observed)
                || !cleanup_cloud_reparse_tag(observed.reparse_tag)
                || native_namespace_directory::opaque_directory_identity(handle.0)?.as_slice()
                    != expected.identity
                || !windows_paths_equal(
                    &final_path_for_handle(handle.0).map_err(|_| Error::ConfiguredRootChanged)?,
                    &ancestor_path,
                )
            {
                return Err(Error::ConfiguredRootChanged);
            }
        }
        let parent = root_snapshot(self.parent.0)?;
        if parent.identity != self.parent_snapshot.identity
            || !valid_callback_directory_snapshot(parent)
            || !cleanup_cloud_reparse_tag(parent.reparse_tag)
            || self.leaf_path.parent().is_none_or(|expected| {
                final_path_for_handle(self.parent.0)
                    .map_or(true, |actual| !windows_paths_equal(&actual, expected))
            })
            || self.route.last().is_none_or(|expected| {
                native_namespace_directory::opaque_directory_identity(self.parent.0)
                    .map_or(true, |id| id.as_slice() != expected.identity)
            })
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let leaf = root_snapshot(self.leaf.0)?;
        if leaf.identity != self.leaf_snapshot.identity
            || leaf.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || leaf.reparse_tag != 0
            || leaf.placeholder_state != 0
            || (leaf.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0)
                != (self.kind == FreshCreateTargetKind::Directory)
            || !windows_paths_equal(
                &final_path_for_handle(self.leaf.0).map_err(|_| Error::ConfiguredRootChanged)?,
                &self.leaf_path,
            )
        {
            return Err(Error::ConfiguredRootChanged);
        }
        native_namespace_directory::verify_reinspected_namespace_root(&self.root, &self.root_path)
    }
}

/// Unlike open_root, this does not require a directory. Shape, no-reparse/CF0,
/// path and identity checks still run before any facts can be used.
fn open_plain_leaf_metadata(path: &Path) -> Result<RawOwnedHandle, Error> {
    let path = wide_path(path)?;
    // SAFETY: bounded no-follow path, metadata-only access, no inheritance and
    // no data/DELETE permission. RAII owns the successful handle on this worker.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(win32_io_error("open fresh create leaf metadata"));
    }
    Ok(RawOwnedHandle(handle))
}

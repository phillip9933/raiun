//! Bounded read-only collection before atomic folder policy admission.

use super::*;
use raiun_cache::FolderPolicyListing;
use std::collections::BTreeSet;

impl Engine {
    pub(super) fn set_folder_cloud_only_live(
        &self,
        space: &str,
        scope: &CacheScope,
        selected: &RemoteEntry,
    ) -> Result<(), CloudError> {
        let _metadata = self.metadata_publication()?;
        let context = self
            .offline_cache
            .as_ref()
            .expect("folder policy requires cache");
        let (current_scope, root) = self.online_plaintext_scope(space)?;
        if current_scope != *scope || !selected.directory || selected.encrypted {
            return Err(folder_changed());
        }
        let selected_parent = if selected.path == "/" {
            if selected.id != root.id {
                return Err(folder_changed());
            }
            root.clone()
        } else {
            let path = parent_path(&selected.path)?;
            let parent = self.backend.stat(space, &path)?;
            if !parent.directory || parent.encrypted || parent.path != path {
                return Err(folder_changed());
            }
            parent
        };
        let mut observations = Vec::new();
        let mut total_entries = 0usize;
        let mut metadata_bytes = 0usize;
        if selected.path != "/" {
            // This observation proves the selected stable directory still
            // occupies the exact parent/path before any descendant is admitted.
            let observation = self.collect_folder_policy_listing(
                space,
                scope,
                &selected_parent,
                false,
                &mut total_entries,
                &mut metadata_bytes,
            )?;
            if !observation
                .entries
                .iter()
                .any(|item| item.entry == *selected)
            {
                return Err(folder_changed());
            }
            observations.push(observation);
        }
        let mut seen = BTreeSet::from([selected.id.clone()]);
        let mut pending = vec![(selected.clone(), 0usize)];
        while let Some((parent, depth)) = pending.pop() {
            if depth > MAX_REFRESH_DEPTH {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "folder policy exceeds the directory-depth limit",
                ));
            }
            let observation = self.collect_folder_policy_listing(
                space,
                scope,
                &parent,
                true,
                &mut total_entries,
                &mut metadata_bytes,
            )?;
            for item in &observation.entries {
                if !seen.insert(item.entry.id.clone()) {
                    return Err(folder_changed());
                }
                if item.entry.directory {
                    pending.push((item.entry.clone(), depth + 1));
                }
            }
            observations.push(observation);
        }
        // No cached listings or pin states have changed during collection.
        // Recheck account/root and selected directory identity at the handoff.
        let (final_scope, _) = self.online_plaintext_scope(space)?;
        let final_selected = self.backend.stat(space, &selected.path)?;
        let final_parent = self.backend.stat(space, &selected_parent.path)?;
        if final_scope != *scope || final_selected != *selected || final_parent != selected_parent {
            return Err(folder_changed());
        }
        context
            .cache
            .set_folder_cloud_only(
                scope,
                &CachedEntry {
                    parent_resource_id: selected_parent.id,
                    entry: selected.clone(),
                },
                &observations,
            )
            .map_err(cache_cloud_error)
    }

    pub(super) fn collect_folder_policy_listing(
        &self,
        space: &str,
        scope: &CacheScope,
        parent: &RemoteEntry,
        reject_encrypted: bool,
        total_entries: &mut usize,
        metadata_bytes: &mut usize,
    ) -> Result<FolderPolicyListing, CloudError> {
        let cache = &self
            .offline_cache
            .as_ref()
            .expect("folder policy requires cache")
            .cache;
        // Capture before the network read. The cache compares this generation
        // under its final transaction rather than accepting a later baseline.
        let expected_generation = match cache.listing(scope, &parent.id) {
            Ok(listing) => Some(listing.generation),
            Err(raiun_cache::CacheError::IncompleteListing) => None,
            Err(error) => return Err(cache_cloud_error(error)),
        };
        let entries = self.list_live(space, &parent.path)?;
        let mut cached = Vec::with_capacity(entries.len());
        *metadata_bytes = metadata_bytes.saturating_add(parent.id.len());
        for entry in entries {
            if !is_direct_child_path(&parent.path, &entry.path) {
                return Err(folder_changed());
            }
            *total_entries = total_entries.saturating_add(1);
            *metadata_bytes = metadata_bytes
                .saturating_add(parent.id.len())
                .saturating_add(entry.id.len())
                .saturating_add(entry.path.len())
                .saturating_add(entry.etag.len());
            if *total_entries > MAX_LIST_ENTRIES || *metadata_bytes > MAX_REFRESH_PATH_BYTES {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "folder policy exceeds its bounded metadata limit",
                ));
            }
            if entry.encrypted {
                if reject_encrypted {
                    return Err(unsupported_encrypted_cache());
                }
                // Count raw siblings against the traversal budget even when
                // they are outside this plaintext policy's authority.
                continue;
            }
            cached.push(CachedEntry {
                parent_resource_id: parent.id.clone(),
                entry,
            });
        }
        Ok(FolderPolicyListing {
            parent_resource_id: parent.id.clone(),
            expected_generation,
            entries: cached,
        })
    }
}

fn folder_changed() -> CloudError {
    CloudError::new(
        ErrorKind::Conflict,
        "folder identity or metadata changed while updating availability",
    )
}

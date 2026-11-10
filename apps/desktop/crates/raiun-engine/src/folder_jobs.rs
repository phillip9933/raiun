//! Ordinary directory jobs. The caller retains its provider namespace lease
//! throughout each job; the execution gate excludes competing engine writes.

use super::*;

fn refused(message: &str) -> CloudError {
    CloudError::new(ErrorKind::Conflict, message)
}

fn admitted(check: &(dyn Fn() -> bool + Sync)) -> Result<(), CloudError> {
    if check() {
        Ok(())
    } else {
        Err(refused("folder job was cancelled or its account changed"))
    }
}

fn target_path(path: &str) -> Result<(), CloudError> {
    validate_remote_path(path).map_err(refused)?;
    if path == "/" || path.len() > 4096 {
        return Err(refused("folder job requires a bounded non-root path"));
    }
    Ok(())
}

fn overlap(left: &str, right: &str) -> bool {
    left == right
        || left == "/"
        || right == "/"
        || left
            .strip_prefix(right)
            .is_some_and(|tail| tail.starts_with('/'))
        || right
            .strip_prefix(left)
            .is_some_and(|tail| tail.starts_with('/'))
}

fn remote_parent(path: &str) -> Result<&str, CloudError> {
    target_path(path)?;
    let (parent, _) = path
        .rsplit_once('/')
        .ok_or_else(|| refused("folder path has no parent"))?;
    Ok(if parent.is_empty() { "/" } else { parent })
}

fn ordinary_directory(entry: &RemoteEntry, path: &str) -> Result<(), CloudError> {
    if entry.path != path
        || !entry.directory
        || entry.encrypted
        || !entry.writable
        || entry.id.is_empty()
        || entry.id.starts_with("pending:")
        || entry.id.starts_with("raiun-pending-create:")
    {
        return Err(refused(
            "folder job requires a fresh writable ordinary directory",
        ));
    }
    Ok(())
}

impl Engine {
    fn folder_job_scope(
        &self,
        space: &str,
        selected: &CloudSpace,
        root: &RemoteEntry,
    ) -> Result<CacheScope, CloudError> {
        if self.vault_binding.is_some() || self.offline_cache.is_none() || !selected.writable {
            return Err(refused(
                "ordinary account-bound folder jobs are unavailable",
            ));
        }
        ordinary_directory(root, "/")?;
        let scope = self.plaintext_scope_from_observation(space, selected, root)?;
        self.create_cache(&scope)?;
        Ok(scope)
    }

    /// Exclude every unresolved ordinary journal write, including legacy
    /// Match edits and writes retained under an older root for this Space.
    fn guard_folder_job_pending(&self, space: &str, path: &str) -> Result<(), CloudError> {
        let context = self
            .offline_cache
            .as_ref()
            .ok_or_else(|| refused("folder job cache is unavailable"))?;
        let mut after: Option<String> = None;
        let mut seen = 0u64;
        let mut total = None;
        loop {
            let page = context
                .cache
                .pending_write_page(&context.origin, &context.account_id, after.as_deref(), 100)
                .map_err(cache_cloud_error)?;
            let count = page.pending_count.saturating_add(page.conflict_count);
            if count > MAX_LIST_ENTRIES as u64 || total.is_some_and(|old| old != count) {
                return Err(refused(
                    "folder job pending-write scan is incomplete or changed",
                ));
            }
            total = Some(count);
            seen = seen.saturating_add(page.items.len() as u64);
            for item in page.items {
                if item.space_id == space && overlap(path, &item.path) {
                    return Err(refused(
                        "folder subtree has pending local edits; local bytes were preserved",
                    ));
                }
            }
            match page.next_after {
                Some(next)
                    if after
                        .as_ref()
                        .is_none_or(|old| next.parse::<i64>().ok() > old.parse::<i64>().ok()) =>
                {
                    after = Some(next)
                }
                Some(_) => return Err(refused("folder job pending-write cursor did not advance")),
                None if !page.truncated && seen == count => return Ok(()),
                None => return Err(refused("folder job pending-write scan is incomplete")),
            }
        }
    }

    /// Delete an explicitly selected whole directory with one conditional
    /// parent DELETE. No child-by-child deletion or recursive enumeration is used.
    pub fn delete_folder_job(
        &self,
        space: &str,
        path: &str,
        expected_root_id: &str,
        expected_resource_id: &str,
        expected_etag: &str,
        check: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), CloudError> {
        target_path(path)?;
        let tag = expected_etag.as_bytes();
        if expected_resource_id.is_empty()
            || tag.len() < 2
            || tag.first() != Some(&b'"')
            || tag.last() != Some(&b'"')
            || tag[1..tag.len() - 1]
                .iter()
                .any(|byte| !(0x21..=0x7e).contains(byte) || *byte == b'"')
        {
            return Err(refused(
                "whole-folder deletion requires an exact identity and strong ETag",
            ));
        }
        admitted(check)?;
        let _execution = self.execution()?;
        admitted(check)?;
        let _metadata = self.metadata_publication()?;
        let (selected, root) = self.backend.space_root_metadata(space)?;
        let scope = self.folder_job_scope(space, &selected, &root)?;
        if expected_root_id.is_empty() || root.id != expected_root_id {
            return Err(refused(
                "folder job Space root differs from the prepared root",
            ));
        }
        let id = self.begin_transfer(None, space, path, "delete")?;
        let outcome = self.backend.delete_folder_and_confirm_with_preflight(
            space,
            path,
            expected_resource_id,
            expected_etag,
            &|selected, root| {
                admitted(check)?;
                if self.folder_job_scope(space, selected, root)? != scope {
                    return Err(refused("folder job Space root changed"));
                }
                self.guard_folder_job_pending(space, path)?;
                self.prepare_observed_cache_mutation(space, &[path], selected, root)?;
                admitted(check)
            },
        );
        self.finish_transfer(
            id,
            if outcome.is_ok() {
                "completed"
            } else {
                "failed"
            },
            0,
            outcome.as_ref().err().map(|error| error.message.as_str()),
        )?;
        outcome
    }

    /// Prepare one entirely new directory tree in level order. At most four
    /// sibling MKCOL operations run concurrently under one execution lease.
    /// A failed/cancelled job may retain confirmed new directories; it never
    /// rolls them back or adopts an already existing destination.
    pub fn create_folder_job_tree(
        &self,
        space: &str,
        expected_root_id: &str,
        expected_parent_id: &str,
        paths: &[String],
        check: &(dyn Fn() -> bool + Sync),
    ) -> Result<Vec<RemoteEntry>, CloudError> {
        if paths.is_empty() || paths.len() > MAX_LIST_ENTRIES {
            return Err(refused("folder tree is empty or exceeds the entry limit"));
        }
        let mut paths = paths.to_vec();
        for path in &paths {
            target_path(path)?;
        }
        paths.sort_by(|left, right| {
            left.bytes()
                .filter(|byte| *byte == b'/')
                .count()
                .cmp(&right.bytes().filter(|byte| *byte == b'/').count())
                .then_with(|| left.cmp(right))
        });
        let root_path = paths[0].clone();
        let all: std::collections::HashSet<_> = paths.iter().cloned().collect();
        if all.len() != paths.len()
            || paths.iter().any(|path| {
                path != &root_path
                    && (!path
                        .strip_prefix(&root_path)
                        .is_some_and(|tail| tail.starts_with('/'))
                        || !all.contains(remote_parent(path).unwrap_or("")))
            })
        {
            return Err(refused(
                "folder job paths must describe one complete new tree",
            ));
        }
        admitted(check)?;
        let _execution = self.execution()?;
        admitted(check)?;
        let _metadata = self.metadata_publication()?;
        let (selected, root) = self.backend.space_root_metadata(space)?;
        let scope = self.folder_job_scope(space, &selected, &root)?;
        if expected_root_id.is_empty() || root.id != expected_root_id {
            return Err(refused(
                "folder job Space root differs from the prepared root",
            ));
        }
        self.guard_folder_job_pending(space, &root_path)?;
        let parent_path = remote_parent(&root_path)?;
        let parent = if parent_path == "/" {
            root
        } else {
            self.backend.stat(space, parent_path)?
        };
        ordinary_directory(&parent, parent_path)?;
        if expected_parent_id.is_empty() || parent.id != expected_parent_id {
            return Err(refused(
                "folder job destination parent differs from the prepared parent",
            ));
        }
        // Establish absence using a live lookup, never the provider's memo.
        self.folder_job_absent(space, &root_path)?;
        let mut parents = BTreeMap::from([(parent_path.to_owned(), parent.id)]);
        let mut entries = Vec::with_capacity(paths.len());
        let mut start = 0;
        while start < paths.len() {
            admitted(check)?;
            let depth = paths[start].bytes().filter(|byte| *byte == b'/').count();
            let end = paths[start..]
                .iter()
                .position(|path| path.bytes().filter(|byte| *byte == b'/').count() != depth)
                .map_or(paths.len(), |offset| start + offset);
            for chunk in paths[start..end].chunks(4) {
                let results = std::thread::scope(|threads| {
                    let mut workers = Vec::with_capacity(chunk.len());
                    for path in chunk {
                        let parent_id = parents
                            .get(remote_parent(path)?)
                            .ok_or_else(|| refused("folder tree parent was not confirmed"))?;
                        let scope = &scope;
                        workers.push(threads.spawn(move || {
                            self.create_folder_job_directory(space, path, parent_id, scope, check)
                        }));
                    }
                    workers
                        .into_iter()
                        .map(|worker| {
                            worker
                                .join()
                                .map_err(|_| refused("folder creation worker failed"))?
                        })
                        .collect::<Result<Vec<_>, CloudError>>()
                })?;
                for entry in results {
                    parents.insert(entry.path.clone(), entry.id.clone());
                    entries.push(entry);
                }
            }
            start = end;
        }
        Ok(entries)
    }

    fn folder_job_absent(&self, space: &str, path: &str) -> Result<(), CloudError> {
        match self.backend.stat(space, path) {
            Err(error) if error.kind == ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(refused("folder job destination already exists")),
            Err(error) => Err(error),
        }
    }

    // Execution and metadata ownership belong to the outer tree job. Calling
    // public mkdir here would attempt to acquire the same execution mutex.
    fn create_folder_job_directory(
        &self,
        space: &str,
        path: &str,
        parent_id: &str,
        scope: &CacheScope,
        check: &(dyn Fn() -> bool + Sync),
    ) -> Result<RemoteEntry, CloudError> {
        admitted(check)?;
        let id = self.begin_transfer(None, space, path, "mkdir")?;
        let outcome = self
            .backend
            .mkdir_and_confirm_with_preflight(space, path, &|selected, root| {
                admitted(check)?;
                if self.folder_job_scope(space, selected, root)? != *scope {
                    return Err(refused("folder job Space root changed"));
                }
                let parent_path = remote_parent(path)?;
                let parent = if parent_path == "/" {
                    root.clone()
                } else {
                    self.backend.stat(space, parent_path)?
                };
                ordinary_directory(&parent, parent_path)?;
                if parent.id != parent_id {
                    return Err(refused("folder job parent identity changed"));
                }
                self.folder_job_absent(space, path)?;
                self.guard_folder_job_pending(space, path)?;
                self.prepare_observed_cache_mutation(space, &[path], selected, root)?;
                admitted(check)
            })
            .and_then(|entry| {
                ordinary_directory(&entry, path)?;
                Ok(entry)
            });
        self.finish_transfer(
            id,
            if outcome.is_ok() {
                "completed"
            } else {
                "failed"
            },
            0,
            outcome.as_ref().err().map(|error| error.message.as_str()),
        )?;
        outcome
    }
}

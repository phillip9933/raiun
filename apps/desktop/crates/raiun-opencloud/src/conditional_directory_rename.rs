//! One bounded ordinary directory ID-MOVE. The subtree observations are not an
//! atomic server subtree condition. Callers retain all original native/catalog
//! custody; any ambiguous send must remain unresolved and must never be replayed.
use super::*;
impl OpenCloudClient {
    /// Freshly qualify the captured subtree and send once. `before_send` is
    /// synchronous local-only: no network I/O or client re-entry is permitted.
    pub fn conditional_directory_rename_with_context_before_send(
        &self,
        request: ConditionalMoveRequest<'_>,
        expected_subtree: &[RemoteEntry],
        before_send: impl FnOnce() -> Result<(), CloudError>,
    ) -> Result<ConditionalRenameResponse, CloudError> {
        let _guard = RangeContextGuard::enter(request.context);
        validate_request(&request)?;
        if request.expected_source_size != 0 {
            return Err(invalid("directory metadata size must be zero"));
        }
        self.ensure_context_current(request.context)?;

        let source_path =
            recovery_target_path(request.remote_root_path, request.source_relative_path)?;
        let destination_path =
            recovery_target_path(request.remote_root_path, request.destination_relative_path)?;
        let spaces = self.discover_spaces(Some(request.context), MAX_ENTRIES)?;
        let mut matching = spaces
            .into_iter()
            .filter(|candidate| candidate.id == request.space);
        let selected = matching
            .next()
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "cloud space was not found"))?;
        if matching.next().is_some() {
            return Err(conflict("cloud space identity is ambiguous"));
        }
        if selected.encrypted || is_vault_path(&source_path) || is_vault_path(&destination_path) {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted Spaces and vault paths do not accept ordinary MOVE",
            ));
        }
        if !selected.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "OpenCloud Space is read only",
            ));
        }

        let root_url =
            Url::parse(&selected.dav_url).map_err(|_| invalid("Space DAV URL is invalid"))?;
        if !same_origin(&self.server, &root_url)
            || !root_url.username().is_empty()
            || root_url.password().is_some()
            || root_url.query().is_some()
            || root_url.fragment().is_some()
        {
            return Err(invalid("Space DAV URL is outside the configured origin"));
        }
        let source_url = append_logical_path(&root_url, &source_path)?;
        let destination_url = append_logical_path(&root_url, &destination_path)?;
        let configured_root_url = append_logical_path(&root_url, request.remote_root_path)?;

        self.validate_directory_rename_root(
            &configured_root_url,
            request.remote_root_path,
            request.expected_root_id,
        )?;
        let source_ancestor_root = self.ensure_plain_ancestors_with_context(
            &selected,
            &source_path,
            false,
            Some(request.context),
        )?;
        let destination_ancestor_root = self.ensure_plain_ancestors_with_context(
            &selected,
            &destination_path,
            false,
            Some(request.context),
        )?;
        if source_ancestor_root != destination_ancestor_root {
            return Err(conflict("source and destination ancestry changed"));
        }

        self.verify_directory_move_parents(&request, &source_path, &destination_path)?;
        self.ensure_writable_target(&selected, &source_url, &source_path)?;
        let source = self.stat_at_dav(&source_url, &source_path)?;
        if source.id != request.expected_source_id
            || source.etag != request.expected_source_etag
            || !is_strong_etag(&source.etag)
            || !source.directory
            || source.encrypted
            || !source.writable
        {
            return Err(conflict("source identity, revision, or file kind changed"));
        }

        self.check_directory_rename_subtree(&request, expected_subtree)?;
        match self.stat_leaf_direct_with_context(
            &destination_url,
            &destination_path,
            request.context,
        ) {
            Err(error) if error.kind == ErrorKind::NotFound => {}
            Ok(_) => return Err(conflict("rename destination already exists")),
            Err(error) => return Err(error),
        }
        self.ensure_writable_target(&selected, &destination_url, &destination_path)?;

        // Recheck the configured root and source/destination evidence directly
        // before constructing the one request. MOVE itself is not an atomic
        // compare-and-swap on the root, parent or provider file identity.
        self.validate_directory_rename_root(
            &configured_root_url,
            request.remote_root_path,
            request.expected_root_id,
        )?;
        let fresh_source = self.stat_at_dav(&source_url, &source_path)?;
        if fresh_source.id != request.expected_source_id
            || fresh_source.etag != request.expected_source_etag
            || !is_strong_etag(&fresh_source.etag)
            || !fresh_source.directory
            || fresh_source.encrypted
            || !fresh_source.writable
        {
            return Err(conflict("source changed before conditional MOVE"));
        }
        match self.stat_leaf_direct_with_context(
            &destination_url,
            &destination_path,
            request.context,
        ) {
            Err(error) if error.kind == ErrorKind::NotFound => {}
            Ok(_) => return Err(conflict("rename destination appeared before MOVE")),
            Err(error) => return Err(error),
        }
        self.check_directory_rename_subtree(&request, expected_subtree)?;
        self.verify_directory_move_parents(&request, &source_path, &destination_path)?;
        self.ensure_context_current(request.context)?;

        let method = Method::from_bytes(b"MOVE").expect("static HTTP method");
        let mutation_url = super::conditional_delete::resource_delete_url(
            &self.server,
            &root_url,
            &selected.id,
            request.expected_root_id,
            request.expected_source_id,
        )?;
        let (builder, token) =
            self.request_with_context(method, &mutation_url, Some(request.context))?;
        let destination = HeaderValue::from_str(destination_url.as_str())
            .map_err(|_| invalid("conditional MOVE destination header is invalid"))?;
        let etag = HeaderValue::from_str(request.expected_source_etag)
            .map_err(|_| invalid("conditional MOVE source validator is invalid"))?;
        let source_parent_url = append_logical_path(&root_url, &logical_parent(&source_path))?;
        let destination_parent_url =
            append_logical_path(&root_url, &logical_parent(&destination_path))?;
        let parent_conditions = HeaderValue::from_str(&format!(
            "<{}> ([{}]) <{}> ([{}])",
            source_parent_url,
            request.source_parent_etag,
            destination_parent_url,
            request.destination_parent_etag
        ))
        .map_err(|_| invalid("conditional directory MOVE parent conditions are invalid"))?;
        let move_request = builder
            .header("Destination", destination)
            .header("Overwrite", "F")
            .header("If", parent_conditions)
            .header(IF_MATCH, etag)
            .build()
            .map_err(|_| invalid("conditional MOVE request is invalid"))?;
        before_send()?;
        let response = match self.conditional_http.execute(move_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(ConditionalRenameResponse::Uncertain(network(error)));
            }
        };
        if let Err(error) = self.ensure_context_current(request.context) {
            return Ok(ConditionalRenameResponse::Uncertain(error));
        }
        let status = response.status();
        if status == StatusCode::CREATED || status == StatusCode::NO_CONTENT {
            return Ok(ConditionalRenameResponse::Renamed);
        }
        let error = checked(
            response,
            &[StatusCode::CREATED, StatusCode::NO_CONTENT],
            &token,
        )
        .err()
        .unwrap_or_else(|| invalid("unexpected conditional MOVE response"));
        if let Err(context_error) = self.ensure_context_current(request.context) {
            return Ok(ConditionalRenameResponse::Uncertain(context_error));
        }
        Ok(ConditionalRenameResponse::Uncertain(error))
    }

    fn check_directory_rename_subtree(
        &self,
        request: &ConditionalMoveRequest<'_>,
        expected: &[RemoteEntry],
    ) -> Result<(), CloudError> {
        if expected.is_empty() || expected.len() > 1024 {
            return Err(invalid("directory move requires a bounded managed subtree"));
        }
        let root = recovery_target_path(request.remote_root_path, request.source_relative_path)?;
        let mut pending = vec![root.clone()];
        let mut actual = vec![self.stat_with_context(request.space, &root, request.context)?];
        while let Some(path) = pending.pop() {
            self.list_with_context(request.space, &path, request.context, &mut |entry| {
                if actual.len() >= 1024
                    || logical_parent(&entry.path) != path
                    || entry.encrypted
                    || !entry.writable
                    || entry.path.split('/').count() > 64
                    || actual
                        .iter()
                        .any(|e| e.id == entry.id || e.path.eq_ignore_ascii_case(&entry.path))
                {
                    return Err(conflict("directory subtree changed or is unsupported"));
                }
                if entry.directory {
                    pending.push(entry.path.clone());
                }
                actual.push(entry);
                Ok(())
            })?;
        }
        if actual.len() != expected.len()
            || actual.iter().any(|entry| {
                entry.encrypted
                    || !entry.writable
                    || !expected.iter().any(|e| {
                        e.path == entry.path
                            && e.id == entry.id
                            && e.directory == entry.directory
                            && e.etag == entry.etag
                            && (e.directory || e.size == entry.size)
                    })
            })
        {
            return Err(conflict(
                "directory subtree no longer matches captured bindings",
            ));
        }
        Ok(())
    }
    fn verify_directory_move_parents(
        &self,
        request: &ConditionalMoveRequest<'_>,
        source: &str,
        destination: &str,
    ) -> Result<(), CloudError> {
        for (path, id, etag) in [
            (
                logical_parent(source),
                request.source_parent_id,
                request.source_parent_etag,
            ),
            (
                logical_parent(destination),
                request.destination_parent_id,
                request.destination_parent_etag,
            ),
        ] {
            let entry = self.stat_with_context(request.space, &path, request.context)?;
            if !entry.directory
                || entry.encrypted
                || !entry.writable
                || entry.id != id
                || entry.etag != etag
                || !is_strong_etag(&entry.etag)
            {
                return Err(conflict("conditional MOVE original parent changed"));
            }
        }
        Ok(())
    }
    fn validate_directory_rename_root(
        &self,
        root_url: &Url,
        root_path: &str,
        expected_root_id: &str,
    ) -> Result<(), CloudError> {
        let root = self.stat_at_dav(root_url, root_path)?;
        if root.id != expected_root_id || !root.directory || root.encrypted || !root.writable {
            return Err(conflict("configured remote root identity changed"));
        }
        Ok(())
    }
}
fn validate_request(request: &ConditionalMoveRequest<'_>) -> Result<(), CloudError> {
    if request.space.is_empty()
        || request.space.len() > MAX_DAV_ENTRY
        || request.space.chars().any(char::is_control)
        || request.expected_root_id.is_empty()
        || request.expected_root_id.len() > MAX_DAV_ENTRY
        || request.expected_root_id.chars().any(char::is_control)
        || request.expected_source_id.is_empty()
        || request.expected_source_id.len() > MAX_DAV_ENTRY
        || request.expected_source_id.chars().any(char::is_control)
        || request.expected_source_etag.len() > MAX_DAV_ENTRY
        || !is_strong_etag(request.expected_source_etag)
        || HeaderValue::from_str(request.expected_source_etag).is_err()
    {
        return Err(invalid("conditional MOVE identity or validator is invalid"));
    }
    for (id, etag) in [
        (request.source_parent_id, request.source_parent_etag),
        (
            request.destination_parent_id,
            request.destination_parent_etag,
        ),
    ] {
        if id.is_empty()
            || id.len() > MAX_DAV_ENTRY
            || id.chars().any(char::is_control)
            || !is_strong_etag(etag)
            || etag.len() > MAX_DAV_ENTRY
            || HeaderValue::from_str(etag).is_err()
        {
            return Err(invalid(
                "conditional MOVE parent identity/validator is invalid",
            ));
        }
    }
    let source = recovery_target_path(request.remote_root_path, request.source_relative_path)?;
    let destination =
        recovery_target_path(request.remote_root_path, request.destination_relative_path)?;
    let source_leaf = source.rsplit('/').next().unwrap_or_default();
    let destination_leaf = destination.rsplit('/').next().unwrap_or_default();
    if source.eq_ignore_ascii_case(&destination)
        || (logical_parent(&source) == logical_parent(&destination)
            && source_leaf.eq_ignore_ascii_case(destination_leaf))
        || destination
            .to_lowercase()
            .starts_with(&format!("{}/", source.to_lowercase()))
    {
        return Err(invalid(
            "conditional directory MOVE requires distinct paths outside the source subtree",
        ));
    }
    if source.trim_end_matches('/') == request.remote_root_path.trim_end_matches('/')
        || destination.trim_end_matches('/') == request.remote_root_path.trim_end_matches('/')
    {
        return Err(invalid("conditional MOVE cannot address the Space root"));
    }
    Ok(())
}

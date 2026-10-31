//! One conditional WebDAV MOVE preflight/send boundary.
//!
//! This API does not make MOVE atomic with source identity or parent state,
//! does not verify the destination identity, and does not complete local
//! provider work. Callers must retain the original publication and must not
//! replay after an uncertain result.

use super::*;

/// Inputs captured by a trusted caller for one same-parent ordinary-file MOVE.
/// Debug formatting is intentionally unavailable because these fields contain
/// remote names and identity metadata.
pub struct ConditionalRenameRequest<'a> {
    pub space: &'a str,
    pub remote_root_path: &'a str,
    pub expected_root_id: &'a str,
    pub source_relative_path: &'a str,
    pub destination_relative_path: &'a str,
    pub expected_source_id: &'a str,
    pub expected_source_size: u64,
    pub expected_source_etag: &'a str,
    pub context: RangeReadContext,
}

/// Result after one MOVE request has begun.
pub enum ConditionalRenameResponse {
    Renamed,
    /// Kept for API compatibility; this preflight/send-only helper does not
    /// classify any post-send status as a definitive rejection.
    Rejected(CloudError),
    Uncertain(CloudError),
}

impl OpenCloudClient {
    /// Preflight and send one conditional, non-overwriting MOVE for an
    /// ordinary file within its captured parent. Errors returned directly
    /// mean no MOVE was sent. Once send begins, transport, context changes,
    /// successful statuses after auth expiry, and unknown statuses are
    /// uncertain unless the response is 201 or 204 and the captured context
    /// remains current. Other statuses are uncertain because the server may
    /// have committed the MOVE before a later response failure. Its dedicated
    /// HTTP client disables reqwest retries. This API performs no post-MOVE
    /// readback or local completion.
    pub fn conditional_rename_with_context(
        &self,
        request: ConditionalRenameRequest<'_>,
    ) -> Result<ConditionalRenameResponse, CloudError> {
        self.conditional_rename_with_context_before_send(request, || Ok(()))
    }

    /// Preflight and prepare the same single MOVE, then invoke `before_send`
    /// exactly once at the final local boundary immediately before HTTP
    /// execution. An error from the callback is definitely pre-send; after it
    /// returns success, the existing uncertain-send rules apply. The callback
    /// must be synchronous and must not perform network I/O or re-enter this
    /// client. It is intended for a caller-owned one-use local claim, not for
    /// extending remote authorization or making MOVE atomic.
    pub fn conditional_rename_with_context_before_send(
        &self,
        request: ConditionalRenameRequest<'_>,
        before_send: impl FnOnce() -> Result<(), CloudError>,
    ) -> Result<ConditionalRenameResponse, CloudError> {
        let _guard = RangeContextGuard::enter(request.context);
        validate_request(&request)?;
        self.ensure_context_current(request.context)?;

        let source_path =
            recovery_target_path(request.remote_root_path, request.source_relative_path)?;
        let destination_path =
            recovery_target_path(request.remote_root_path, request.destination_relative_path)?;
        let spaces = self.discover_spaces(Some(request.context), MAX_ENTRIES)?;
        let selected = spaces
            .into_iter()
            .find(|candidate| candidate.id == request.space)
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "cloud space was not found"))?;
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

        self.validate_root_entry(
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

        self.ensure_writable_target(&selected, &source_url, &source_path)?;
        let source = self.stat_at_dav(&source_url, &source_path)?;
        if source.id != request.expected_source_id
            || source.size != request.expected_source_size
            || source.etag != request.expected_source_etag
            || !is_strong_etag(&source.etag)
            || source.directory
            || source.encrypted
            || !source.writable
        {
            return Err(conflict("source identity, revision, or file kind changed"));
        }

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
        self.validate_root_entry(
            &configured_root_url,
            request.remote_root_path,
            request.expected_root_id,
        )?;
        let fresh_source = self.stat_at_dav(&source_url, &source_path)?;
        if fresh_source.id != request.expected_source_id
            || fresh_source.size != request.expected_source_size
            || fresh_source.etag != request.expected_source_etag
            || !is_strong_etag(&fresh_source.etag)
            || fresh_source.directory
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
        self.ensure_context_current(request.context)?;

        let method = Method::from_bytes(b"MOVE").expect("static HTTP method");
        let (builder, token) =
            self.request_with_context(method, &source_url, Some(request.context))?;
        let destination = HeaderValue::from_str(destination_url.as_str())
            .map_err(|_| invalid("conditional MOVE destination header is invalid"))?;
        let etag = HeaderValue::from_str(request.expected_source_etag)
            .map_err(|_| invalid("conditional MOVE source validator is invalid"))?;
        let move_request = builder
            .header("Destination", destination)
            .header("Overwrite", "F")
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

    fn validate_root_entry(
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

fn validate_request(request: &ConditionalRenameRequest<'_>) -> Result<(), CloudError> {
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
    let source = recovery_target_path(request.remote_root_path, request.source_relative_path)?;
    let destination =
        recovery_target_path(request.remote_root_path, request.destination_relative_path)?;
    let source_leaf = source.rsplit('/').next().unwrap_or_default();
    let destination_leaf = destination.rsplit('/').next().unwrap_or_default();
    if source == destination
        || logical_parent(&source) != logical_parent(&destination)
        || source_leaf.eq_ignore_ascii_case(destination_leaf)
    {
        return Err(invalid(
            "conditional MOVE requires distinct names in the exact same parent",
        ));
    }
    if source.trim_end_matches('/') == request.remote_root_path.trim_end_matches('/')
        || destination.trim_end_matches('/') == request.remote_root_path.trim_end_matches('/')
    {
        return Err(invalid("conditional MOVE cannot address the Space root"));
    }
    Ok(())
}

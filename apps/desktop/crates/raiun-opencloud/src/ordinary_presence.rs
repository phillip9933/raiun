//! Metadata-only lookup that distinguishes an absent ordinary leaf from
//! failures while validating its configured root or ancestry.

use super::*;

/// Captured context for one ordinary target lookup. Debug formatting is
/// intentionally unavailable because the request carries remote names and IDs.
pub struct OrdinaryPresenceRequest<'a> {
    pub space: &'a str,
    pub remote_root_path: &'a str,
    pub expected_root_id: &'a str,
    pub relative_path: &'a str,
    pub context: RangeReadContext,
}

/// Exact ordinary leaf presence. `Absent` can only result from an actual HTTP
/// 404 from the direct leaf stat after root and ancestry validation.
pub enum OrdinaryTargetPresence {
    Present(RemoteEntry),
    Absent,
}

impl OpenCloudClient {
    /// Stat one ordinary target beneath the captured configured root. Only a
    /// actual HTTP 404 from the exact leaf request becomes `Absent`; root and
    /// parent failures stay errors. This method performs metadata HTTP only
    /// and grants no mutation, inventory, or provider authority.
    pub fn ordinary_target_presence_with_context(
        &self,
        request: OrdinaryPresenceRequest<'_>,
    ) -> Result<OrdinaryTargetPresence, CloudError> {
        let _guard = RangeContextGuard::enter(request.context);
        validate_request(&request)?;
        self.ensure_context_current(request.context)?;
        let target_path = recovery_target_path(request.remote_root_path, request.relative_path)?;
        if is_vault_path(request.remote_root_path) || is_vault_path(&target_path) {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted vault paths are unavailable to ordinary metadata lookups",
            ));
        }

        let spaces = self.discover_spaces(Some(request.context), MAX_ENTRIES)?;
        let selected = spaces
            .into_iter()
            .find(|candidate| candidate.id == request.space)
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "cloud space was not found"))?;
        if selected.encrypted {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted Spaces are unavailable to ordinary metadata lookups",
            ));
        }
        let dav_root =
            Url::parse(&selected.dav_url).map_err(|_| invalid("Space DAV URL is invalid"))?;
        if !same_origin(&self.server, &dav_root)
            || !dav_root.username().is_empty()
            || dav_root.password().is_some()
            || dav_root.query().is_some()
            || dav_root.fragment().is_some()
        {
            return Err(invalid("Space DAV URL is outside the configured origin"));
        }
        let configured_root_url = append_logical_path(&dav_root, request.remote_root_path)?;
        let target_url = append_logical_path(&dav_root, &target_path)?;

        self.validate_configured_root(
            &configured_root_url,
            request.remote_root_path,
            request.expected_root_id,
        )?;
        let initial_ancestry = self.ordinary_ancestry_snapshot_with_context(
            &selected,
            &target_path,
            request.remote_root_path,
            request.expected_root_id,
            request.context,
        )?;
        self.ensure_context_current(request.context)?;

        let leaf = self.stat_leaf_direct_with_context(&target_url, &target_path, request.context);
        if let Ok(entry) = &leaf {
            if entry.encrypted || is_vault_path(&entry.path) {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "encrypted target is unavailable to ordinary metadata lookups",
                ));
            }
        } else if leaf
            .as_ref()
            .is_err_and(|error| error.kind != ErrorKind::NotFound)
        {
            return leaf.map(OrdinaryTargetPresence::Present);
        }

        self.validate_configured_root(
            &configured_root_url,
            request.remote_root_path,
            request.expected_root_id,
        )?;
        let final_ancestry = self.ordinary_ancestry_snapshot_with_context(
            &selected,
            &target_path,
            request.remote_root_path,
            request.expected_root_id,
            request.context,
        )?;
        if initial_ancestry != final_ancestry {
            return Err(conflict("ordinary ancestry changed during target lookup"));
        }
        self.ensure_context_current(request.context)?;

        match leaf {
            Ok(entry) => Ok(OrdinaryTargetPresence::Present(entry)),
            Err(error) if error.kind == ErrorKind::NotFound => Ok(OrdinaryTargetPresence::Absent),
            Err(error) => Err(error),
        }
    }

    fn validate_configured_root(
        &self,
        root_url: &Url,
        root_path: &str,
        expected_root_id: &str,
    ) -> Result<(), CloudError> {
        let root = self.stat_at_dav(root_url, root_path)?;
        if root.id != expected_root_id || !root.directory || root.encrypted {
            return Err(conflict("configured ordinary root identity changed"));
        }
        Ok(())
    }

    fn ordinary_ancestry_snapshot_with_context(
        &self,
        selected: &CloudSpace,
        target_path: &str,
        configured_root_path: &str,
        expected_root_id: &str,
        context: RangeReadContext,
    ) -> Result<Vec<(String, String)>, CloudError> {
        validate_logical_path(target_path)?;
        let parts: Vec<_> = target_path
            .split('/')
            .filter(|part| !part.is_empty())
            .collect();
        if parts.len() > MAX_VAULT_GUARD_DEPTH {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "remote path exceeds the ordinary ancestry depth limit",
            ));
        }
        let root_path = configured_root_path.trim_end_matches('/');
        let root_path = if root_path.is_empty() { "/" } else { root_path };
        let root_url =
            Url::parse(&selected.dav_url).map_err(|_| invalid("Space DAV URL is invalid"))?;
        let mut snapshot = Vec::with_capacity(parts.len().max(1));
        let mut path = String::new();
        let ancestors = parts.len().saturating_sub(1);
        for index in 0..=ancestors {
            if index > 0 {
                path.push('/');
                path.push_str(parts[index - 1]);
            }
            let current = if path.is_empty() { "/" } else { &path };
            if is_vault_path(current) {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "encrypted vault ancestry is unavailable to ordinary lookups",
                ));
            }
            let url = append_logical_path(&root_url, current)?;
            let entry = self.stat_at_dav(&url, current)?;
            if !entry.directory || entry.encrypted {
                return Err(CloudError::new(
                    ErrorKind::Unsupported,
                    "ordinary target ancestry contains a non-directory or encrypted item",
                ));
            }
            if entry.id.is_empty()
                || entry.id.len() > MAX_DAV_ENTRY
                || entry.id.chars().any(char::is_control)
            {
                return Err(invalid("ordinary ancestry identity is invalid"));
            }
            let normalized_current = current.trim_end_matches('/');
            let normalized_current = if normalized_current.is_empty() {
                "/"
            } else {
                normalized_current
            };
            if normalized_current == root_path && entry.id != expected_root_id {
                return Err(conflict("configured ordinary root identity changed"));
            }
            snapshot.push((current.to_owned(), entry.id));
            self.ensure_context_current(context)?;
        }
        Ok(snapshot)
    }

    pub(super) fn stat_leaf_direct_with_context(
        &self,
        url: &Url,
        path: &str,
        context: RangeReadContext,
    ) -> Result<RemoteEntry, CloudError> {
        let body = b"<?xml version=\"1.0\" encoding=\"utf-8\"?><d:propfind xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\" xmlns:lg=\"http://graph.opencloud.eu/ns\" xmlns:ocrclone=\"ocrclone\"><d:prop><d:resourcetype/><d:getcontentlength/><d:getetag/><d:getlastmodified/><d:getcontenttype/><oc:fileid/><oc:permissions/><lg:encrypted/><lg:contentType/><ocrclone:integrity-id/></d:prop></d:propfind>";
        let method = Method::from_bytes(b"PROPFIND").expect("static HTTP method");
        let (request, token) = self.request_with_context(method, url, Some(context))?;
        let response = request
            .header("Depth", "0")
            .header(CONTENT_TYPE, "application/xml; charset=utf-8")
            .header("Initiator-ID", &self.initiator_id)
            .body(body.as_slice())
            .send()
            .map_err(network)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err(CloudError::new(
                ErrorKind::NotFound,
                "ordinary target was not found",
            ));
        }
        let mut response = checked(response, &[StatusCode::MULTI_STATUS], &token)?;
        let bytes = read_bounded(&mut response, MAX_DAV_RESPONSE as usize)?;
        let mut found = None;
        parse_multistatus(&bytes, url, path, &mut |entry| {
            if found.is_some() {
                return Err(invalid("ordinary target stat returned multiple entries"));
            }
            found = Some(entry);
            Ok(())
        })?;
        let entry =
            found.ok_or_else(|| invalid("ordinary target stat omitted its requested entry"))?;
        if entry.path.trim_end_matches('/') != path.trim_end_matches('/') {
            return Err(invalid("ordinary target stat returned a different path"));
        }
        Ok(entry)
    }
}

fn validate_request(request: &OrdinaryPresenceRequest<'_>) -> Result<(), CloudError> {
    if request.space.is_empty()
        || request.space.len() > MAX_DAV_ENTRY
        || request.space.chars().any(char::is_control)
        || request.expected_root_id.is_empty()
        || request.expected_root_id.len() > MAX_DAV_ENTRY
        || request.expected_root_id.chars().any(char::is_control)
    {
        return Err(invalid("ordinary target lookup identity is invalid"));
    }
    let target = recovery_target_path(request.remote_root_path, request.relative_path)?;
    if target.split('/').filter(|part| !part.is_empty()).count() > MAX_VAULT_GUARD_DEPTH {
        return Err(CloudError::new(
            ErrorKind::Unsupported,
            "ordinary target exceeds the ancestry depth limit",
        ));
    }
    if target.trim_end_matches('/') == request.remote_root_path.trim_end_matches('/') {
        return Err(invalid("ordinary target lookup cannot address its root"));
    }
    Ok(())
}

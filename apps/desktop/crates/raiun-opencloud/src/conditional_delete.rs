//! One resource-ID-addressed ordinary-file DELETE. Observed source/root/ancestry
//! checks plus If-Match are not proof of final server revision/location CAS.
//! No pathname mutation fallback, automatic replay, readback or native ACK.
use super::*;

pub struct ConditionalDeleteRequest<'a> {
    pub space: &'a str,
    pub remote_root_path: &'a str,
    pub expected_root_id: &'a str,
    pub source_relative_path: &'a str,
    pub expected_source_id: &'a str,
    pub expected_source_size: u64,
    pub expected_source_etag: &'a str,
    pub context: RangeReadContext,
}

pub enum ConditionalDeleteResponse {
    Deleted,
    Uncertain(CloudError),
}

impl OpenCloudClient {
    /// Direct Err means definitely no DELETE was sent. Once execution begins,
    /// every transport/context/non-success outcome is uncertain, never replayed.
    /// The synchronous local-only guard is invoked once, after the final remote
    /// proof, immediately before retry-disabled HTTP execution. It must not do
    /// network I/O or re-enter this client. The caller retains original custody.
    pub fn conditional_delete_with_context_before_send(
        &self,
        request: ConditionalDeleteRequest<'_>,
        before_send: impl FnOnce() -> Result<(), CloudError>,
    ) -> Result<ConditionalDeleteResponse, CloudError> {
        let _guard = RangeContextGuard::enter(request.context);
        if !is_strong_etag(request.expected_source_etag)
            || request.expected_source_etag.len() > MAX_DAV_ENTRY
            || HeaderValue::from_str(request.expected_source_etag).is_err()
        {
            return Err(invalid("conditional DELETE validator is invalid"));
        }
        let source_path =
            recovery_target_path(request.remote_root_path, request.source_relative_path)?;
        if source_path.trim_end_matches('/') == request.remote_root_path.trim_end_matches('/')
            || is_vault_path(request.remote_root_path)
            || is_vault_path(&source_path)
        {
            return Err(invalid(
                "conditional DELETE requires an ordinary nonroot file",
            ));
        }
        self.ensure_context_current(request.context)?;
        let spaces = self.discover_spaces(Some(request.context), MAX_ENTRIES)?;
        let selected = spaces
            .iter()
            .find(|space| space.id == request.space)
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "cloud space was not found"))?;
        if !selected.personal || !selected.writable || selected.encrypted {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "ordinary Personal file deletion is unavailable",
            ));
        }
        let root_url =
            Url::parse(&selected.dav_url).map_err(|_| invalid("Space DAV URL is invalid"))?;
        let target_url = resource_delete_url(
            &self.server,
            &root_url,
            &selected.id,
            request.expected_root_id,
            request.expected_source_id,
        )?;
        let configured_root_url = append_logical_path(&root_url, request.remote_root_path)?;
        let source_url = append_logical_path(&root_url, &source_path)?;
        let check_root = || -> Result<(), CloudError> {
            let root = self.stat_at_dav(&configured_root_url, request.remote_root_path)?;
            if root.id != request.expected_root_id
                || !root.directory
                || root.encrypted
                || !root.writable
            {
                return Err(conflict("configured ordinary root identity changed"));
            }
            Ok(())
        };
        let check_source = || -> Result<(), CloudError> {
            self.ensure_writable_target(selected, &source_url, &source_path)?;
            let entry = self.stat_at_dav(&source_url, &source_path)?;
            if entry.id != request.expected_source_id
                || entry.size != request.expected_source_size
                || entry.etag != request.expected_source_etag
                || !is_strong_etag(&entry.etag)
                || entry.directory
                || entry.encrypted
                || !entry.writable
            {
                return Err(conflict(
                    "conditional DELETE source identity or revision changed",
                ));
            }
            Ok(())
        };
        check_root()?;
        self.ensure_plain_ancestors_with_context(
            selected,
            &source_path,
            false,
            Some(request.context),
        )?;
        check_source()?;
        check_root()?;
        check_source()?;
        self.ensure_context_current(request.context)?;
        let (builder, token) =
            self.request_with_context(Method::DELETE, &target_url, Some(request.context))?;
        let request_http = builder
            .header(
                IF_MATCH,
                HeaderValue::from_str(request.expected_source_etag)
                    .map_err(|_| invalid("conditional DELETE validator is invalid"))?,
            )
            .build()
            .map_err(|_| invalid("conditional DELETE request is invalid"))?;
        before_send()?;
        let response = match self.conditional_http.execute(request_http) {
            Ok(response) => response,
            Err(error) => return Ok(ConditionalDeleteResponse::Uncertain(network(error))),
        };
        if let Err(error) = self.ensure_context_current(request.context) {
            return Ok(ConditionalDeleteResponse::Uncertain(error));
        }
        if matches!(response.status(), StatusCode::NO_CONTENT | StatusCode::OK) {
            return Ok(ConditionalDeleteResponse::Deleted);
        }
        let error = checked(response, &[StatusCode::NO_CONTENT, StatusCode::OK], &token)
            .err()
            .unwrap_or_else(|| invalid("unexpected conditional DELETE response"));
        Ok(ConditionalDeleteResponse::Uncertain(error))
    }
}

#[derive(PartialEq, Eq)]
struct ResourceReference<'a> {
    provider: Option<&'a str>,
    space: &'a str,
    opaque: Option<&'a str>,
}
fn reference(value: &str) -> Result<ResourceReference<'_>, CloudError> {
    fn component(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 4096
            && !matches!(value, "." | "..")
            && !value.chars().any(|c| {
                c.is_whitespace()
                    || c.is_control()
                    || matches!(c, '$' | '!' | '/' | '\\' | '%' | '?' | '#')
            })
    }
    if value.len() > MAX_DAV_ENTRY {
        return Err(invalid("resource reference exceeds its limit"));
    }
    let (storage_space, opaque) = match value.split_once('!') {
        Some((prefix, opaque)) if component(opaque) => (prefix, Some(opaque)),
        Some(_) => return Err(invalid("resource reference has no usable opaque identity")),
        None => (value, None),
    };
    let (provider, space) = match storage_space.split_once('$') {
        Some((provider, space)) if component(provider) => (Some(provider), space),
        Some(_) => {
            return Err(invalid(
                "resource reference has no usable provider identity",
            ));
        }
        None => (None, storage_space),
    };
    if !component(space) {
        return Err(invalid("resource reference has no usable Space identity"));
    }
    Ok(ResourceReference {
        provider,
        space,
        opaque,
    })
}

/// Graph serializes drive.id/DAV root as FormatResourceID(root), omitting the
/// opaque root only when it equals SpaceId. PROPFIND fileid retains the full
/// ResourceID. Match parsed components; never assume selected.id is an ID prefix.
fn resource_delete_url(
    server: &Url,
    root: &Url,
    selected: &str,
    expected_root: &str,
    source: &str,
) -> Result<Url, CloudError> {
    if !same_origin(server, root)
        || !root.username().is_empty()
        || root.password().is_some()
        || root.query().is_some()
        || root.fragment().is_some()
    {
        return Err(invalid("Space DAV URL is outside the configured origin"));
    }
    let mut segments = root
        .path_segments()
        .ok_or_else(|| invalid("Space DAV URL has no path"))?
        .collect::<Vec<_>>();
    if segments.last() == Some(&"") {
        segments.pop();
    }
    if segments.len() < 3
        || segments[segments.len() - 3] != "dav"
        || segments[segments.len() - 2] != "spaces"
        || decode_safe_segment(segments[segments.len() - 1])? != selected
    {
        return Err(invalid(
            "Space DAV URL has no canonical captured root reference",
        ));
    }
    let selected_ref = reference(selected)?;
    let root_ref = reference(expected_root)?;
    let source_ref = reference(source)?;
    if root_ref.opaque.is_none()
        || source_ref.opaque.is_none()
        || selected_ref.provider != root_ref.provider
        || selected_ref.space != root_ref.space
        || source_ref.provider != root_ref.provider
        || source_ref.space != root_ref.space
        || selected_ref
            .opaque
            .is_some_and(|id| Some(id) != root_ref.opaque)
        || (selected_ref.opaque.is_none() && root_ref.opaque != Some(root_ref.space))
        || source_ref.opaque == root_ref.opaque
        || source_ref.opaque == Some(source_ref.space)
    {
        return Err(invalid(
            "conditional DELETE resource is outside its captured nonroot namespace",
        ));
    }
    let service_segments = &segments[..segments.len() - 1];
    let encoded = percent_encoding::utf8_percent_encode(source, percent_encoding::NON_ALPHANUMERIC);
    let mut target = root.clone();
    target.set_path(&format!("/{}/{encoded}/", service_segments.join("/")));
    if !same_origin(server, &target) {
        return Err(invalid("conditional DELETE endpoint origin changed"));
    }
    Ok(target)
}

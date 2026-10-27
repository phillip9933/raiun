//! Read-only vault discovery and raw DAV metadata.
//!
//! This API is intentionally separate from [`crate::OpenCloudClient`]'s
//! [`raiun_core::backend::CloudBackend`] implementation. It never reads file
//! content, returns a password/key, or mutates server state. Returned identity,
//! ETag, and integrity-token values are server metadata, not cryptographic proof.

use percent_encoding::percent_decode_str;
use quick_xml::{NsReader, escape::resolve_predefined_entity, events::Event, name::ResolveResult};
use raiun_core::backend::{CloudBackend, CloudError, CloudSpace, ErrorKind};
use reqwest::{Method, StatusCode, header::CONTENT_TYPE};
use std::collections::HashSet;
use url::Url;

use crate::{OpenCloudClient, checked, invalid, network, read_bounded, same_origin};

const MAX_VAULT_XML_BYTES: usize = 2 * 1024 * 1024;
const MAX_VAULT_RESPONSES: usize = 10_000;
const MAX_XML_DEPTH: usize = 32;
const MAX_TEXT_FIELD: usize = 4_096;
const MAX_TOKEN_BYTES: usize = 4_096;

const DAV: &[u8] = b"DAV:";
const OC: &[u8] = b"http://owncloud.org/ns";
const VAULT_NS: &[u8] = b"ocrclone";
const VAULT_CONTENT_TYPE: &str = "application/vnd.opencloud.vault";

const PROPFIND_BODY: &[u8] = b"<?xml version=\"1.0\" encoding=\"utf-8\"?><d:propfind xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\" xmlns:ocrclone=\"ocrclone\"><d:prop><d:resourcetype/><d:getcontentlength/><d:getetag/><d:getlastmodified/><d:getcontenttype/><oc:fileid/><oc:id/><oc:name/><oc:size/><oc:permissions/><ocrclone:integrity-id/></d:prop></d:propfind>";

/// A stable resource identity and bounded, raw WebDAV metadata record.
/// `strong_etag` is a server revision hint; the format does not authenticate it.
#[derive(Debug, Clone, PartialEq, Eq)]
/// Raw DAV metadata for one resource. Resource IDs are only scoped to a server
/// account and Space; key them by server/account + Space ID + resource ID.
/// ETags are server revision hints and are not authenticated by the vault
/// format.
pub struct VaultDavEntry {
    pub id: String,
    /// Decoded path relative to the selected Space DAV root.
    pub path: String,
    /// Raw server name. Descendant names may still be encrypted ciphertext.
    pub raw_name: String,
    pub directory: bool,
    pub modified_unix: i64,
    pub writable: bool,
    pub size: u64,
    pub strong_etag: Option<String>,
    /// Untrusted root-identification signals for this collection.
    pub vault_evidence: Vec<VaultEvidence>,
    /// Server-advertised href after origin and path-scope validation.
    pub href: String,
}

/// Server metadata that identifies a folder vault and its current root listing.
/// `integrity_token` is opaque until the vault codec authenticates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRootListing {
    pub space_id: String,
    /// The DAV root obtained from the selected Graph Space record.
    pub space_dav_root: String,
    /// Absolute logical path within the selected Space.
    pub root_path: String,
    pub root: VaultDavEntry,
    pub children: Vec<VaultDavEntry>,
    pub integrity_token: Option<String>,
    pub evidence: Vec<VaultEvidence>,
}

/// Untrusted server-side signal that a DAV collection is a vault root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultEvidence {
    FolderNameSuffix,
    IntegrityProperty,
    ContentType,
}

/// Read-only metadata operations for folder vaults in non-encrypted Spaces.
/// Construct this from the authenticated OpenCloud client; callers cannot
/// supply an arbitrary DAV root URL or widen the configured origin.
pub struct VaultMetadataClient<'a> {
    client: &'a OpenCloudClient,
}

impl<'a> VaultMetadataClient<'a> {
    pub fn new(client: &'a OpenCloudClient) -> Self {
        Self { client }
    }

    /// Find immediate vault-signaled directory children of a plain directory.
    /// Signals include a case-insensitive `.vault` suffix, a nonempty integrity
    /// property, or the vault content type. The parent path is logical and
    /// absolute within the selected Space.
    pub fn discover_folder_vaults(
        &self,
        space_id: &str,
        parent_path: &str,
    ) -> Result<Vec<VaultDavEntry>, CloudError> {
        validate_logical_path(parent_path)?;
        let (space, space_root) = self.resolve_space(space_id, false)?;
        let listing = self.list_path(&space, &space_root, parent_path, "1")?;
        if !listing.evidence.is_empty() {
            return Err(unsupported(
                "folder-vault discovery requires a non-vault parent directory",
            ));
        }
        Ok(listing
            .children
            .into_iter()
            .filter(|entry| entry.directory && !entry.vault_evidence.is_empty())
            .collect())
    }

    /// Inspect an explicitly selected folder path and return its raw root and
    /// immediate-child metadata. The returned token still requires codec
    /// verification before a password is considered correct.
    pub fn inspect_folder_vault(
        &self,
        space_id: &str,
        vault_path: &str,
    ) -> Result<VaultRootListing, CloudError> {
        validate_logical_path(vault_path)?;
        if vault_path == "/" {
            return Err(unsupported("the Space root is not a folder-vault path"));
        }
        let (space, space_root) = self.resolve_space(space_id, false)?;
        let directory_path = with_trailing_slash(vault_path);
        let listing = self.list_path(&space, &space_root, &directory_path, "1")?;
        if listing.evidence.is_empty() {
            return Err(unsupported("selected folder is not identified as a vault"));
        }
        Ok(listing)
    }

    /// Inspect a vault target. `/` is accepted only for a whole-Space vault;
    /// every other path must be a marked folder vault inside an ordinary Space.
    pub fn inspect_vault(
        &self,
        space_id: &str,
        vault_path: &str,
    ) -> Result<VaultRootListing, CloudError> {
        validate_logical_path(vault_path)?;
        if vault_path != "/" {
            return self.inspect_folder_vault(space_id, vault_path);
        }
        let (space, space_root) = self.resolve_space(space_id, true)?;
        if !space.encrypted {
            return Err(unsupported(
                "the Space root is a vault only when Graph marks the Space encrypted",
            ));
        }
        let mut listing = self.list_path(&space, &space_root, "/", "1")?;
        if !listing.root.directory {
            return Err(unsupported("encrypted Space root is not a DAV collection"));
        }
        if !listing.evidence.contains(&VaultEvidence::ContentType) {
            listing.evidence.push(VaultEvidence::ContentType);
        }
        Ok(listing)
    }

    fn resolve_space(
        &self,
        space_id: &str,
        allow_encrypted: bool,
    ) -> Result<(CloudSpace, Url), CloudError> {
        if space_id.is_empty() || space_id.len() > 512 || space_id.chars().any(char::is_control) {
            return Err(invalid("cloud Space id is invalid"));
        }
        let space = self
            .client
            .spaces()?
            .into_iter()
            .find(|space| space.id == space_id)
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "cloud Space was not found"))?;
        if space.encrypted && !allow_encrypted {
            return Err(unsupported(
                "whole-Space vault metadata is not supported by this folder-vault API",
            ));
        }
        let root = Url::parse(&space.dav_url).map_err(|_| invalid("Space DAV root is invalid"))?;
        if !same_origin(&self.client.server, &root)
            || root.username() != ""
            || root.password().is_some()
            || root.query().is_some()
            || root.fragment().is_some()
        {
            return Err(invalid(
                "Space DAV root is outside the configured server origin",
            ));
        }
        Ok((space, ensure_trailing_slash(root)?))
    }

    /// Inspect a raw path inside the selected Space. This remains crate
    /// private because callers must separately bind it to a verified vault
    /// session and revalidate the vault root identity before each operation.
    pub(crate) fn inspect_raw_path(
        &self,
        space_id: &str,
        logical_path: &str,
        depth: &str,
    ) -> Result<VaultRootListing, CloudError> {
        if !matches!(depth, "0" | "1") {
            return Err(invalid("vault DAV depth must be 0 or 1"));
        }
        validate_logical_path(logical_path)?;
        let (space, space_root) = self.resolve_space(space_id, true)?;
        self.list_path(&space, &space_root, logical_path, depth)
    }

    fn list_path(
        &self,
        space: &CloudSpace,
        space_root: &Url,
        logical_path: &str,
        depth: &str,
    ) -> Result<VaultRootListing, CloudError> {
        let requested = append_path(space_root, logical_path)?;
        let (request, token) = self.client.request(
            Method::from_bytes(b"PROPFIND").expect("static HTTP method"),
            &requested,
        )?;
        let response = request
            .header("Depth", depth)
            .header(CONTENT_TYPE, "application/xml; charset=utf-8")
            .body(PROPFIND_BODY)
            .send()
            .map_err(network)?;
        let mut response = checked(response, &[StatusCode::MULTI_STATUS], &token)?;
        let body = read_bounded(&mut response, MAX_VAULT_XML_BYTES)?;
        let listing = parse_listing(
            &body,
            &self.client.server,
            space,
            space_root,
            &requested,
            logical_path,
        )?;
        if depth == "1" && !listing.root.directory {
            return Err(unsupported("selected vault root is not a collection"));
        }
        Ok(listing)
    }
}

fn parse_listing(
    body: &[u8],
    configured_server: &Url,
    space: &CloudSpace,
    space_root: &Url,
    requested: &Url,
    logical_path: &str,
) -> Result<VaultRootListing, CloudError> {
    let mut reader = NsReader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buffer = Vec::new();
    let mut depth = 0usize;
    let mut response: Option<ResponseBuilder> = None;
    let mut propstat: Option<PropstatBuilder> = None;
    let mut prop_depth = None;
    let mut resource_type_depth = None;
    let mut field: Option<FieldBuffer> = None;
    let mut parsed = Vec::new();
    let mut saw_multistatus = false;
    let mut closed_multistatus = false;

    loop {
        match reader.read_resolved_event_into(&mut buffer) {
            Ok((namespace, Event::Start(element))) => {
                depth += 1;
                if depth > MAX_XML_DEPTH {
                    return Err(invalid("vault DAV XML nesting exceeds its limit"));
                }
                let local = element.local_name();
                let name = local_name(local.as_ref());
                if namespace_is(&namespace, DAV) && name == "multistatus" {
                    if saw_multistatus || depth != 1 {
                        return Err(invalid("vault DAV response has an invalid root element"));
                    }
                    saw_multistatus = true;
                } else if namespace_is(&namespace, DAV) && name == "response" {
                    if !saw_multistatus || response.is_some() || depth != 2 {
                        return Err(invalid("vault DAV response nesting is invalid"));
                    }
                    response = Some(ResponseBuilder {
                        depth,
                        ..ResponseBuilder::default()
                    });
                } else if response.is_some() {
                    if field.is_some() {
                        return Err(invalid("nested DAV scalar property is invalid"));
                    }
                    if namespace_is(&namespace, DAV) && name == "propstat" {
                        if propstat.is_some() {
                            return Err(invalid("nested DAV propstat is invalid"));
                        }
                        propstat = Some(PropstatBuilder {
                            depth,
                            ..PropstatBuilder::default()
                        });
                    } else if namespace_is(&namespace, DAV) && name == "prop" {
                        if propstat.is_none() || prop_depth.is_some() {
                            return Err(invalid("DAV property structure is invalid"));
                        }
                        prop_depth = Some(depth);
                    } else if let Some(property_depth) = prop_depth {
                        if depth == property_depth + 1 {
                            let key = property_key(&namespace, name);
                            if let Some(key) = key {
                                if field.is_some() {
                                    return Err(invalid("nested DAV scalar property is invalid"));
                                }
                                mark_property_seen(
                                    propstat.as_mut().expect("propstat exists"),
                                    key,
                                )?;
                                if key == PropertyKey::ResourceType {
                                    resource_type_depth = Some(depth);
                                } else {
                                    field = Some(FieldBuffer {
                                        depth,
                                        key,
                                        value: String::new(),
                                    });
                                }
                            }
                        } else if namespace_is(&namespace, DAV)
                            && name == "collection"
                            && resource_type_depth == Some(depth - 1)
                        {
                            let current = propstat.as_mut().expect("propstat exists");
                            if current.values.collection_count > 0 {
                                return Err(invalid("DAV resource type repeats collection"));
                            }
                            current.values.collection_count += 1;
                        }
                    } else if let Some(current) = propstat.as_ref()
                        && namespace_is(&namespace, DAV)
                        && name == "status"
                        && depth == current.depth + 1
                    {
                        field = Some(FieldBuffer {
                            depth,
                            key: PropertyKey::Status,
                            value: String::new(),
                        });
                    } else if let Some(current) = response.as_ref()
                        && namespace_is(&namespace, DAV)
                        && name == "href"
                        && depth == current.depth + 1
                    {
                        field = Some(FieldBuffer {
                            depth,
                            key: PropertyKey::Href,
                            value: String::new(),
                        });
                    }
                }
            }
            Ok((namespace, Event::Empty(element))) => {
                let local = element.local_name();
                let name = local_name(local.as_ref());
                let event_depth = depth + 1;
                if let Some(property_depth) = prop_depth
                    && event_depth == property_depth + 1
                {
                    if let Some(key) = property_key(&namespace, name) {
                        let current = propstat.as_mut().expect("propstat exists");
                        mark_property_seen(current, key)?;
                        if key == PropertyKey::ResourceType {
                            resource_type_depth = None;
                        } else {
                            apply_empty_property(current, key)?;
                        }
                    }
                }
                if namespace_is(&namespace, DAV)
                    && name == "collection"
                    && resource_type_depth
                        .is_some_and(|resource_depth| event_depth == resource_depth + 1)
                {
                    let current = propstat.as_mut().expect("propstat exists");
                    if current.values.collection_count > 0 {
                        return Err(invalid("DAV resource type repeats collection"));
                    }
                    current.values.collection_count += 1;
                }
            }
            Ok((_, Event::Text(text))) => {
                if let Some(active) = field.as_mut() {
                    if active.value.len() > MAX_TEXT_FIELD {
                        return Err(invalid("vault DAV property exceeds its size limit"));
                    }
                    let decoded = text
                        .decode()
                        .map_err(|_| invalid("vault DAV response contains invalid text"))?;
                    active.value.push_str(&decoded);
                    if active.value.len() > MAX_TEXT_FIELD {
                        return Err(invalid("vault DAV property exceeds its size limit"));
                    }
                }
            }
            Ok((_, Event::CData(_))) => {
                return Err(invalid("vault DAV response contains unsupported CDATA"));
            }
            Ok((_, Event::GeneralRef(reference))) => {
                if let Some(active) = field.as_mut() {
                    let reference_name = reference
                        .decode()
                        .map_err(|_| invalid("vault DAV entity reference is invalid"))?;
                    if let Some(character) = reference
                        .resolve_char_ref()
                        .map_err(|_| invalid("vault DAV character reference is invalid"))?
                    {
                        active.value.push(character);
                    } else if let Some(value) = resolve_predefined_entity(&reference_name) {
                        active.value.push_str(value);
                    } else {
                        return Err(invalid("vault DAV response uses an undeclared entity"));
                    }
                    if active.value.len() > MAX_TEXT_FIELD {
                        return Err(invalid("vault DAV property exceeds its size limit"));
                    }
                } else {
                    return Err(invalid(
                        "vault DAV response has an unexpected entity reference",
                    ));
                }
            }
            Ok((namespace, Event::End(element))) => {
                let local = element.local_name();
                let name = local_name(local.as_ref());
                if field.as_ref().is_some_and(|active| active.depth == depth) {
                    let active = field.take().expect("active field exists");
                    apply_field(&mut response, &mut propstat, active)?;
                }
                if namespace_is(&namespace, DAV) && name == "prop" && prop_depth == Some(depth) {
                    prop_depth = None;
                    resource_type_depth = None;
                } else if namespace_is(&namespace, DAV) && name == "propstat" {
                    let completed = propstat
                        .take()
                        .ok_or_else(|| invalid("unexpected DAV propstat end"))?;
                    if completed.depth != depth {
                        return Err(invalid("DAV propstat structure is invalid"));
                    }
                    let status = completed
                        .status
                        .as_deref()
                        .ok_or_else(|| invalid("DAV propstat omitted status"))?;
                    if parse_status_code(status)? == 200 {
                        let current = response
                            .as_mut()
                            .ok_or_else(|| invalid("DAV propstat has no response"))?;
                        current.values.merge(completed.values)?;
                    }
                } else if namespace_is(&namespace, DAV) && name == "response" {
                    if propstat.is_some() || prop_depth.is_some() {
                        return Err(invalid("DAV response ended inside properties"));
                    }
                    let completed = response
                        .take()
                        .ok_or_else(|| invalid("unexpected DAV response end"))?;
                    if completed.depth != depth {
                        return Err(invalid("DAV response structure is invalid"));
                    }
                    parsed.push(completed);
                    if parsed.len() > MAX_VAULT_RESPONSES {
                        return Err(invalid("vault DAV response exceeds its entry limit"));
                    }
                } else if namespace_is(&namespace, DAV) && name == "multistatus" {
                    if response.is_some() || depth != 1 {
                        return Err(invalid("vault DAV multistatus structure is invalid"));
                    }
                    closed_multistatus = true;
                }
                depth = depth.saturating_sub(1);
            }
            Ok((_, Event::DocType(_))) => {
                return Err(invalid("vault DAV response contains a document type"));
            }
            Ok((_, Event::Eof)) => break,
            Err(_) => return Err(invalid("vault DAV response is malformed XML")),
            _ => {}
        }
        buffer.clear();
    }
    if !saw_multistatus || !closed_multistatus || response.is_some() || propstat.is_some() {
        return Err(invalid("vault DAV response is incomplete"));
    }
    build_listing(
        parsed,
        configured_server,
        space,
        space_root,
        requested,
        logical_path,
    )
}

fn build_listing(
    parsed: Vec<ResponseBuilder>,
    configured_server: &Url,
    space: &CloudSpace,
    space_root: &Url,
    requested: &Url,
    logical_path: &str,
) -> Result<VaultRootListing, CloudError> {
    if parsed.is_empty() {
        return Err(invalid("vault DAV response contains no resources"));
    }
    let root_segments = decoded_segments(space_root)?;
    let requested_segments = decoded_segments(requested)?;
    let mut identities = HashSet::new();
    let mut paths = HashSet::new();
    let mut root = None;
    let mut children = Vec::new();

    for parsed_response in parsed {
        let href = parsed_response
            .href
            .ok_or_else(|| invalid("vault DAV response omitted href"))?;
        let actual = requested
            .join(&href)
            .map_err(|_| invalid("vault DAV href is invalid"))?;
        validate_scoped_href(configured_server, space_root, &actual)?;
        let actual_segments = decoded_segments(&actual)?;
        if actual_segments.len() < root_segments.len()
            || actual_segments[..root_segments.len()] != root_segments
        {
            return Err(invalid("vault DAV href escaped the selected Space root"));
        }
        let (relative_segments, is_root) = if actual_segments == requested_segments {
            (&[][..], true)
        } else {
            if actual_segments.len() != requested_segments.len() + 1
                || actual_segments[..requested_segments.len()] != requested_segments
            {
                return Err(invalid(
                    "vault DAV response returned a nested or unrelated item",
                ));
            }
            (&actual_segments[requested_segments.len()..], false)
        };
        let mut values = parsed_response.values;
        if !values.saw_resource_type {
            return Err(invalid("vault DAV response omitted resource type"));
        }
        let id = values
            .file_id
            .take()
            .or_else(|| values.id.take())
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| invalid("vault DAV response omitted stable resource identity"))?;
        if id.len() > 512 || id.chars().any(char::is_control) || !identities.insert(id.clone()) {
            return Err(invalid(
                "vault DAV response contains a duplicate or invalid identity",
            ));
        }
        let raw_name = if is_root {
            values.name.take().unwrap_or_else(|| {
                requested_segments
                    .last()
                    .cloned()
                    .unwrap_or_else(|| "root".to_owned())
            })
        } else {
            let href_name = relative_segments
                .last()
                .cloned()
                .ok_or_else(|| invalid("vault DAV child path is empty"))?;
            if values.name.as_deref().is_some_and(|name| name != href_name) {
                return Err(invalid("vault DAV name property does not match its href"));
            }
            values.name.take().unwrap_or(href_name)
        };
        validate_raw_name(&raw_name)?;
        // A Space endpoint is keyed by its resource identity, while oc:name is
        // its display name. Only that exact Graph-selected root may differ;
        // folder roots and children still have to match their href component.
        if is_root
            && !(logical_path == "/" && requested_segments == root_segments)
            && requested_segments
                .last()
                .is_some_and(|requested_name| requested_name != &raw_name)
        {
            return Err(invalid("vault root name property does not match its href"));
        }
        let path = if is_root {
            relative_logical_path(logical_path)
        } else {
            join_logical_path(logical_path, &raw_name)
        };
        if !paths.insert(path.clone()) {
            return Err(invalid("vault DAV response contains duplicate paths"));
        }
        let directory = values.collection_count == 1;
        let size = match values.content_length.or(values.size) {
            Some(size) => size,
            None if directory => 0,
            None => return Err(invalid("vault DAV file omitted content length")),
        };
        let mut vault_evidence = Vec::new();
        if raw_name.to_lowercase().ends_with(".vault") {
            vault_evidence.push(VaultEvidence::FolderNameSuffix);
        }
        if values.integrity_token.is_some() {
            vault_evidence.push(VaultEvidence::IntegrityProperty);
        }
        if values
            .content_type
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case(VAULT_CONTENT_TYPE))
        {
            vault_evidence.push(VaultEvidence::ContentType);
        }
        let entry = VaultDavEntry {
            id,
            path,
            raw_name,
            directory,
            size,
            modified_unix: values.modified_unix.unwrap_or(0),
            writable: values.writable.unwrap_or(true),
            strong_etag: values.etag.filter(|etag| is_strong_etag(etag)),
            vault_evidence,
            href: actual.to_string(),
        };
        if is_root {
            if root
                .replace((entry, values.integrity_token, values.content_type))
                .is_some()
            {
                return Err(invalid("vault DAV response repeats the requested root"));
            }
        } else {
            children.push(entry);
        }
    }

    let (root_entry, integrity_token, _content_type) =
        root.ok_or_else(|| invalid("vault DAV response omitted requested root"))?;
    let mut evidence = Vec::new();
    evidence.clone_from(&root_entry.vault_evidence);
    Ok(VaultRootListing {
        space_id: space.id.clone(),
        space_dav_root: space_root.to_string(),
        root_path: root_entry.path.clone(),
        root: root_entry,
        children,
        integrity_token,
        evidence,
    })
}

fn validate_scoped_href(server: &Url, root: &Url, actual: &Url) -> Result<(), CloudError> {
    if !same_origin(server, actual)
        || !same_origin(root, actual)
        || actual.username() != ""
        || actual.password().is_some()
        || actual.query().is_some()
        || actual.fragment().is_some()
    {
        return Err(invalid("vault DAV href leaves the configured origin"));
    }
    let root_segments = decoded_segments(root)?;
    let actual_segments = decoded_segments(actual)?;
    if actual_segments.len() < root_segments.len()
        || actual_segments[..root_segments.len()] != root_segments
    {
        return Err(invalid("vault DAV href escaped the advertised DAV root"));
    }
    Ok(())
}

fn append_path(root: &Url, path: &str) -> Result<Url, CloudError> {
    validate_logical_path(path)?;
    let mut result = root.clone();
    {
        let mut segments = result
            .path_segments_mut()
            .map_err(|_| invalid("Space DAV root cannot contain a path"))?;
        segments.pop_if_empty();
        for segment in path.split('/').filter(|segment| !segment.is_empty()) {
            segments.push(segment);
        }
        if path == "/" || path.ends_with('/') {
            segments.push("");
        }
    }
    Ok(result)
}

fn with_trailing_slash(path: &str) -> String {
    if path.ends_with('/') {
        path.to_owned()
    } else {
        format!("{path}/")
    }
}

fn ensure_trailing_slash(mut root: Url) -> Result<Url, CloudError> {
    if !root.path().ends_with('/') {
        let mut segments = root
            .path_segments_mut()
            .map_err(|_| invalid("Space DAV root cannot contain a path"))?;
        segments.push("");
    }
    Ok(root)
}

fn validate_logical_path(path: &str) -> Result<(), CloudError> {
    if path == "/" {
        return Ok(());
    }
    let trimmed = path
        .strip_suffix('/')
        .filter(|_| path != "/")
        .unwrap_or(path);
    if !trimmed.starts_with('/')
        || trimmed.contains('\\')
        || trimmed.chars().any(char::is_control)
        || trimmed
            .split('/')
            .skip(1)
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(unsupported(
            "vault path is not a safe absolute logical path",
        ));
    }
    Ok(())
}

fn relative_logical_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn join_logical_path(parent: &str, name: &str) -> String {
    let parent = relative_logical_path(parent);
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn decoded_segments(url: &Url) -> Result<Vec<String>, CloudError> {
    let segments: Vec<_> = url
        .path_segments()
        .ok_or_else(|| invalid("DAV URL cannot contain paths"))?
        .collect();
    let mut decoded = Vec::with_capacity(segments.len());
    for (index, segment) in segments.iter().enumerate() {
        if segment.is_empty() {
            if index + 1 != segments.len() {
                return Err(invalid("DAV URL contains an empty path component"));
            }
        } else {
            decoded.push(decode_safe_segment(segment)?);
        }
    }
    Ok(decoded)
}

fn decode_safe_segment(segment: &str) -> Result<String, CloudError> {
    let decoded = percent_decode_str(segment)
        .decode_utf8()
        .map_err(|_| invalid("vault DAV href contains invalid UTF-8"))?
        .into_owned();
    validate_raw_name(&decoded)?;
    Ok(decoded)
}

fn validate_raw_name(name: &str) -> Result<(), CloudError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.chars().any(char::is_control)
    {
        return Err(invalid("vault DAV response contains an unsafe name"));
    }
    Ok(())
}

fn is_strong_etag(value: &str) -> bool {
    value.len() >= 2
        && value.starts_with('"')
        && value.ends_with('"')
        && !value.starts_with("W/")
        && value[1..value.len() - 1]
            .chars()
            .all(|character| character != '"' && !character.is_control())
}

fn local_name(name: &[u8]) -> &str {
    std::str::from_utf8(name).unwrap_or("")
}

fn namespace_is(namespace: &ResolveResult<'_>, expected: &[u8]) -> bool {
    matches!(namespace, ResolveResult::Bound(value) if value.as_ref() == expected)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PropertyKey {
    Href,
    Status,
    ResourceType,
    ContentLength,
    Etag,
    LastModified,
    ContentType,
    FileId,
    Id,
    Name,
    Size,
    Permissions,
    IntegrityToken,
}

fn property_key(namespace: &ResolveResult<'_>, name: &str) -> Option<PropertyKey> {
    match (namespace, name) {
        (ResolveResult::Bound(value), "resourcetype") if value.as_ref() == DAV => {
            Some(PropertyKey::ResourceType)
        }
        (ResolveResult::Bound(value), "getcontentlength") if value.as_ref() == DAV => {
            Some(PropertyKey::ContentLength)
        }
        (ResolveResult::Bound(value), "getetag") if value.as_ref() == DAV => {
            Some(PropertyKey::Etag)
        }
        (ResolveResult::Bound(value), "getlastmodified") if value.as_ref() == DAV => {
            Some(PropertyKey::LastModified)
        }
        (ResolveResult::Bound(value), "getcontenttype") if value.as_ref() == DAV => {
            Some(PropertyKey::ContentType)
        }
        (ResolveResult::Bound(value), "fileid") if value.as_ref() == OC => {
            Some(PropertyKey::FileId)
        }
        (ResolveResult::Bound(value), "id") if value.as_ref() == OC => Some(PropertyKey::Id),
        (ResolveResult::Bound(value), "name") if value.as_ref() == OC => Some(PropertyKey::Name),
        (ResolveResult::Bound(value), "size") if value.as_ref() == OC => Some(PropertyKey::Size),
        (ResolveResult::Bound(value), "permissions") if value.as_ref() == OC => {
            Some(PropertyKey::Permissions)
        }
        (ResolveResult::Bound(value), "integrity-id") if value.as_ref() == VAULT_NS => {
            Some(PropertyKey::IntegrityToken)
        }
        _ => None,
    }
}

fn apply_empty_property(
    propstat: &mut PropstatBuilder,
    key: PropertyKey,
) -> Result<(), CloudError> {
    match key {
        // Directory PROPFIND responses commonly include a requested size
        // property with no value. Keep it absent here; build_listing knows
        // whether the resource is a collection and defaults only collections
        // to zero. Files still fail closed when no valid size is supplied.
        PropertyKey::ContentLength | PropertyKey::Size => {}
        PropertyKey::Etag => propstat.values.etag = Some(String::new()),
        PropertyKey::LastModified => propstat.values.modified_unix = Some(0),
        PropertyKey::ContentType => propstat.values.content_type = Some(String::new()),
        PropertyKey::FileId => propstat.values.file_id = Some(String::new()),
        PropertyKey::Id => propstat.values.id = Some(String::new()),
        PropertyKey::Name => propstat.values.name = Some(String::new()),
        PropertyKey::Permissions => propstat.values.writable = Some(false),
        PropertyKey::IntegrityToken => propstat.values.integrity_token = None,
        PropertyKey::ResourceType => {}
        PropertyKey::Href | PropertyKey::Status => {
            return Err(invalid("DAV structural field is unexpectedly empty"));
        }
    }
    Ok(())
}

#[derive(Default)]
struct ResponseBuilder {
    depth: usize,
    href: Option<String>,
    values: PropValues,
}

#[derive(Default)]
struct PropstatBuilder {
    depth: usize,
    status: Option<String>,
    values: PropValues,
}

#[derive(Default)]
struct PropValues {
    seen: HashSet<PropertyKey>,
    saw_resource_type: bool,
    collection_count: usize,
    content_length: Option<u64>,
    size: Option<u64>,
    etag: Option<String>,
    modified_unix: Option<i64>,
    writable: Option<bool>,
    content_type: Option<String>,
    file_id: Option<String>,
    id: Option<String>,
    name: Option<String>,
    integrity_token: Option<String>,
}

impl PropValues {
    fn merge(&mut self, mut other: PropValues) -> Result<(), CloudError> {
        if self.seen.iter().any(|key| other.seen.contains(key)) {
            return Err(invalid(
                "successful DAV propstats contain duplicate properties",
            ));
        }
        self.seen.extend(other.seen.drain());
        self.saw_resource_type |= other.saw_resource_type;
        self.collection_count += other.collection_count;
        self.content_length = other.content_length.or(self.content_length);
        self.size = other.size.or(self.size);
        self.etag = other.etag.or_else(|| self.etag.take());
        self.modified_unix = other.modified_unix.or(self.modified_unix);
        self.writable = other.writable.or(self.writable);
        self.content_type = other.content_type.or_else(|| self.content_type.take());
        self.file_id = other.file_id.or_else(|| self.file_id.take());
        self.id = other.id.or_else(|| self.id.take());
        self.name = other.name.or_else(|| self.name.take());
        self.integrity_token = other
            .integrity_token
            .or_else(|| self.integrity_token.take());
        if let (Some(content_length), Some(size)) = (self.content_length, self.size)
            && content_length != size
        {
            return Err(invalid(
                "DAV content length and OpenCloud size properties disagree",
            ));
        }
        Ok(())
    }
}

struct FieldBuffer {
    depth: usize,
    key: PropertyKey,
    value: String,
}

fn mark_property_seen(propstat: &mut PropstatBuilder, key: PropertyKey) -> Result<(), CloudError> {
    if !propstat.values.seen.insert(key) {
        return Err(invalid("DAV propstat repeats a property"));
    }
    if key == PropertyKey::ResourceType {
        propstat.values.saw_resource_type = true;
    }
    Ok(())
}

fn apply_field(
    response: &mut Option<ResponseBuilder>,
    propstat: &mut Option<PropstatBuilder>,
    field: FieldBuffer,
) -> Result<(), CloudError> {
    let value = field.value.trim().to_owned();
    if value.len() > MAX_TEXT_FIELD {
        return Err(invalid("vault DAV property exceeds its size limit"));
    }
    match field.key {
        PropertyKey::Href => {
            let response = response
                .as_mut()
                .ok_or_else(|| invalid("DAV href has no response"))?;
            if response.href.replace(value).is_some() {
                return Err(invalid("DAV response repeats href"));
            }
        }
        PropertyKey::Status => {
            let propstat = propstat
                .as_mut()
                .ok_or_else(|| invalid("DAV status has no propstat"))?;
            if propstat.status.replace(value).is_some() {
                return Err(invalid("DAV propstat repeats status"));
            }
        }
        PropertyKey::ContentLength | PropertyKey::Size => {
            let propstat = propstat
                .as_mut()
                .ok_or_else(|| invalid("DAV property has no propstat"))?;
            if value.is_empty() {
                // Treat blank numeric properties as absent. A file must still
                // have a parseable size by build_listing; directory size is
                // metadata noise and defaults to zero there.
                return Ok(());
            }
            let parsed = value
                .parse::<u64>()
                .map_err(|_| invalid("DAV size property is invalid"))?;
            if field.key == PropertyKey::ContentLength {
                propstat.values.content_length = Some(parsed);
            } else {
                propstat.values.size = Some(parsed);
            }
        }
        PropertyKey::Etag => {
            propstat
                .as_mut()
                .ok_or_else(|| invalid("DAV property has no propstat"))?
                .values
                .etag = Some(value)
        }
        PropertyKey::LastModified => {
            let propstat = propstat
                .as_mut()
                .ok_or_else(|| invalid("DAV property has no propstat"))?;
            propstat.values.modified_unix = Some(super::parse_http_date(&value).unwrap_or(0));
        }
        PropertyKey::ContentType => {
            propstat
                .as_mut()
                .ok_or_else(|| invalid("DAV property has no propstat"))?
                .values
                .content_type = Some(value)
        }
        PropertyKey::FileId => {
            propstat
                .as_mut()
                .ok_or_else(|| invalid("DAV property has no propstat"))?
                .values
                .file_id = Some(value)
        }
        PropertyKey::Id => {
            propstat
                .as_mut()
                .ok_or_else(|| invalid("DAV property has no propstat"))?
                .values
                .id = Some(value)
        }
        PropertyKey::Name => {
            propstat
                .as_mut()
                .ok_or_else(|| invalid("DAV property has no propstat"))?
                .values
                .name = Some(value)
        }
        PropertyKey::Permissions => {
            let propstat = propstat
                .as_mut()
                .ok_or_else(|| invalid("DAV property has no propstat"))?;
            propstat.values.writable = Some(super::dav_permissions_writable(&value));
        }
        PropertyKey::IntegrityToken => {
            if value.len() > MAX_TOKEN_BYTES || value.chars().any(char::is_control) {
                return Err(invalid(
                    "vault integrity property exceeds its limit or contains controls",
                ));
            }
            if !value.is_empty() {
                propstat
                    .as_mut()
                    .ok_or_else(|| invalid("DAV property has no propstat"))?
                    .values
                    .integrity_token = Some(value);
            }
        }
        PropertyKey::ResourceType => {}
    }
    Ok(())
}

fn parse_status_code(status: &str) -> Result<u16, CloudError> {
    let (version, remainder) = status
        .split_once(' ')
        .ok_or_else(|| invalid("DAV propstat status line is malformed"))?;
    let (code, reason) = remainder.split_once(' ').unwrap_or((remainder, ""));
    let valid_version = version
        .strip_prefix("HTTP/")
        .and_then(|version| version.split_once('.'))
        .is_some_and(|(major, minor)| {
            !major.is_empty()
                && !minor.is_empty()
                && major.bytes().all(|byte| byte.is_ascii_digit())
                && minor.bytes().all(|byte| byte.is_ascii_digit())
        });
    if !valid_version || code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("DAV propstat status line is malformed"));
    }
    if reason
        .chars()
        .any(|character| character.is_control() && character != '\t')
    {
        return Err(invalid("DAV propstat status line is malformed"));
    }
    let code = code
        .parse::<u16>()
        .map_err(|_| invalid("DAV propstat status line is malformed"))?;
    if !(100..=599).contains(&code) {
        return Err(invalid("DAV propstat status code is out of range"));
    }
    Ok(code)
}

fn unsupported(message: &str) -> CloudError {
    CloudError::new(ErrorKind::Unsupported, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn space() -> CloudSpace {
        CloudSpace {
            id: "space-id".into(),
            name: "Personal".into(),
            dav_url: "https://cloud.example/dav/spaces/space-id/".into(),
            personal: true,
            writable: true,
            encrypted: false,
        }
    }

    fn xml(root_path: &str, root_name: &str, child_href: &str, child_name: &str) -> String {
        format!(
            r#"<?xml version="1.0"?>
            <d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone">
              <d:response><d:href>{}</d:href><d:propstat><d:prop>
                <d:resourcetype><d:collection/></d:resourcetype><d:getetag>"root-rev"</d:getetag>
                <oc:fileid>root-id</oc:fileid><oc:name>{}</oc:name><oc:size>0</oc:size>
                <ocrclone:integrity-id>opaque-token</ocrclone:integrity-id>
              </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
              <d:response><d:href>{}</d:href><d:propstat><d:prop>
                <d:resourcetype/><d:getcontentlength>29</d:getcontentlength><d:getetag>W/"weak"</d:getetag>
                <oc:fileid>child-id</oc:fileid><oc:name>{}</oc:name>
              </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
            </d:multistatus>"#,
            root_path, root_name, child_href, child_name
        )
    }

    fn urls(path: &str) -> (Url, Url, Url) {
        let server = Url::parse("https://cloud.example/").unwrap();
        let root = Url::parse("https://cloud.example/dav/spaces/space-id/").unwrap();
        let requested = append_path(&root, path).unwrap();
        (server, root, requested)
    }

    #[test]
    fn parses_bounded_raw_folder_vault_metadata() {
        let (server, root, requested) = urls("/folder.vault");
        let body = xml(
            "/dav/spaces/space-id/folder.vault/",
            "folder.vault",
            "/dav/spaces/space-id/folder.vault/secret.bin",
            "secret.bin",
        );
        let listing = parse_listing(
            body.as_bytes(),
            &server,
            &space(),
            &root,
            &requested,
            "/folder.vault",
        )
        .unwrap();
        assert_eq!(listing.root_path, "/folder.vault");
        assert!(listing.root.directory);
        assert_eq!(listing.root.id, "root-id");
        assert_eq!(listing.root.strong_etag.as_deref(), Some("\"root-rev\""));
        assert_eq!(listing.integrity_token.as_deref(), Some("opaque-token"));
        assert!(listing.evidence.contains(&VaultEvidence::FolderNameSuffix));
        assert!(listing.evidence.contains(&VaultEvidence::IntegrityProperty));
        assert_eq!(listing.children.len(), 1);
        assert_eq!(listing.children[0].size, 29);
        assert_eq!(listing.children[0].strong_etag, None);
        assert_eq!(listing.children[0].path, "/folder.vault/secret.bin");
    }

    #[test]
    fn propstat_status_lines_are_required_validated_and_non_200_is_ignored() {
        let (server, root, requested) = urls("/folder.vault");
        let base = xml(
            "/dav/spaces/space-id/folder.vault/",
            "folder.vault",
            "/dav/spaces/space-id/folder.vault/secret.bin",
            "secret.bin",
        );

        let mut missing = base.clone();
        missing = missing.replace("<d:status>HTTP/1.1 200 OK</d:status>", "");
        assert!(
            parse_listing(
                missing.as_bytes(),
                &server,
                &space(),
                &root,
                &requested,
                "/folder.vault"
            )
            .is_err()
        );

        for malformed in [
            "HTTP/banana 200 OK",
            "HTTP/1.1 nope Not Found",
            "HTTP/1.1 600 Bad",
        ] {
            let invalid_status = base.replace("HTTP/1.1 200 OK", malformed);
            assert!(
                parse_listing(
                    invalid_status.as_bytes(),
                    &server,
                    &space(),
                    &root,
                    &requested,
                    "/folder.vault"
                )
                .is_err()
            );
        }

        let non_200 = base.replace(
            "</d:propstat></d:response>",
            "</d:propstat><d:propstat><d:prop><x:optional xmlns:x=\"urn:optional\">ignored</x:optional></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat></d:response>",
        );
        assert!(
            parse_listing(
                non_200.as_bytes(),
                &server,
                &space(),
                &root,
                &requested,
                "/folder.vault"
            )
            .is_ok()
        );
    }

    #[test]
    fn conflicting_dav_and_opencloud_sizes_are_rejected() {
        let (server, root, requested) = urls("/folder.vault");
        let body = xml(
            "/dav/spaces/space-id/folder.vault/",
            "folder.vault",
            "/dav/spaces/space-id/folder.vault/secret.bin",
            "secret.bin",
        )
        .replace(
            "<d:getcontentlength>29</d:getcontentlength>",
            "<d:getcontentlength>29</d:getcontentlength><oc:size>30</oc:size>",
        );
        assert!(
            parse_listing(
                body.as_bytes(),
                &server,
                &space(),
                &root,
                &requested,
                "/folder.vault"
            )
            .is_err()
        );
    }

    #[test]
    fn empty_directory_sizes_are_optional_but_files_still_require_a_valid_size() {
        let (server, root, requested) = urls("/folder.vault");
        let directory_response = |directory_size_properties: &str, child_size: &str| {
            format!(
                r#"<?xml version="1.0"?>
                <d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone">
                  <d:response><d:href>/dav/spaces/space-id/folder.vault/</d:href><d:propstat><d:prop>
                    <d:resourcetype><d:collection/></d:resourcetype>{directory_size_properties}
                    <d:getetag>"root-rev"</d:getetag><oc:fileid>root-id</oc:fileid>
                    <oc:name>folder.vault</oc:name><ocrclone:integrity-id>opaque-token</ocrclone:integrity-id>
                  </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
                  <d:response><d:href>/dav/spaces/space-id/folder.vault/secret.bin</d:href><d:propstat><d:prop>
                    <d:resourcetype/>{child_size}<d:getetag>"file-rev"</d:getetag>
                    <oc:fileid>child-id</oc:fileid><oc:name>secret.bin</oc:name>
                  </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
                </d:multistatus>"#
            )
        };

        for directory_sizes in [
            "<d:getcontentlength/><oc:size/>",
            "<d:getcontentlength>   </d:getcontentlength><oc:size> </oc:size>",
        ] {
            let body = directory_response(
                directory_sizes,
                "<d:getcontentlength>17</d:getcontentlength>",
            );
            let listing = parse_listing(
                body.as_bytes(),
                &server,
                &space(),
                &root,
                &requested,
                "/folder.vault",
            )
            .unwrap();
            assert_eq!(listing.root.size, 0);
            assert_eq!(listing.children[0].size, 17);
            assert_eq!(listing.integrity_token.as_deref(), Some("opaque-token"));
        }

        let missing_file_size = directory_response(
            "<d:getcontentlength/><oc:size/>",
            "<d:getcontentlength> </d:getcontentlength>",
        );
        assert!(
            parse_listing(
                missing_file_size.as_bytes(),
                &server,
                &space(),
                &root,
                &requested,
                "/folder.vault",
            )
            .is_err(),
            "a file without a valid size must remain invalid"
        );

        let malformed_file_size = directory_response(
            "<d:getcontentlength/>",
            "<d:getcontentlength>unknown</d:getcontentlength>",
        );
        assert!(
            parse_listing(
                malformed_file_size.as_bytes(),
                &server,
                &space(),
                &root,
                &requested,
                "/folder.vault",
            )
            .is_err(),
            "a nonempty malformed file size must remain invalid"
        );
    }

    #[test]
    fn root_listing_supports_space_root_and_percent_encoded_names() {
        let (server, root, requested) = urls("/");
        let body = xml(
            "/dav/spaces/space-id/",
            "space-id",
            "/dav/spaces/space-id/folder%20one.VAULT/",
            "folder one.VAULT",
        );
        let listing =
            parse_listing(body.as_bytes(), &server, &space(), &root, &requested, "/").unwrap();
        assert_eq!(listing.root.path, "/");
        assert_eq!(listing.children[0].path, "/folder one.VAULT");
        assert!(
            listing.children[0]
                .vault_evidence
                .contains(&VaultEvidence::FolderNameSuffix)
        );
    }

    #[test]
    fn space_root_display_name_is_not_its_dav_identifier() {
        let (server, root, requested) = urls("/");
        let mut selected = space();
        selected.personal = false;
        selected.encrypted = true;
        selected.name = "Secure Team".into();
        let body = xml(
            "/dav/spaces/space-id/",
            "Secure Team",
            "/dav/spaces/space-id/ciphertext",
            "ciphertext",
        );
        let listing =
            parse_listing(body.as_bytes(), &server, &selected, &root, &requested, "/").unwrap();
        assert_eq!(listing.space_id, selected.id);
        assert_eq!(listing.root.id, "root-id");
        assert_eq!(listing.root.raw_name, "Secure Team");
        assert_eq!(listing.root.path, "/");
        assert_eq!(listing.root.href, root.as_str());
    }

    #[test]
    fn space_display_name_exception_does_not_relax_folder_or_child_scope() {
        let (server, root, requested) = urls("/folder.vault");
        let folder = xml(
            "/dav/spaces/space-id/folder.vault/",
            "other.vault",
            "/dav/spaces/space-id/folder.vault/ciphertext",
            "ciphertext",
        );
        assert!(
            parse_listing(
                folder.as_bytes(),
                &server,
                &space(),
                &root,
                &requested,
                "/folder.vault"
            )
            .is_err()
        );
        let (_, _, requested) = urls("/");
        let foreign = xml(
            "/dav/spaces/other-space/",
            "Secure Team",
            "/dav/spaces/other-space/ciphertext",
            "ciphertext",
        );
        assert!(
            parse_listing(
                foreign.as_bytes(),
                &server,
                &space(),
                &root,
                &requested,
                "/"
            )
            .is_err()
        );
        let child = xml(
            "/dav/spaces/space-id/",
            "Secure Team",
            "/dav/spaces/space-id/ciphertext",
            "different-name",
        );
        assert!(
            parse_listing(child.as_bytes(), &server, &space(), &root, &requested, "/").is_err()
        );
    }

    #[test]
    fn rejects_out_of_scope_duplicate_and_hostile_xml_metadata() {
        let (server, root, requested) = urls("/folder.vault");
        let hostile = xml(
            "/dav/spaces/space-id/folder.vault/",
            "folder.vault",
            "https://attacker.example/secret",
            "secret",
        );
        assert!(
            parse_listing(
                hostile.as_bytes(),
                &server,
                &space(),
                &root,
                &requested,
                "/folder.vault"
            )
            .is_err()
        );

        let duplicate = xml(
            "/dav/spaces/space-id/folder.vault/",
            "folder.vault",
            "/dav/spaces/space-id/folder.vault/secret.bin",
            "folder.vault",
        );
        assert!(
            parse_listing(
                duplicate.as_bytes(),
                &server,
                &space(),
                &root,
                &requested,
                "/folder.vault"
            )
            .is_err()
        );

        let dtd = format!(
            "<!DOCTYPE x [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>{}",
            hostile
        );
        assert!(
            parse_listing(
                dtd.as_bytes(),
                &server,
                &space(),
                &root,
                &requested,
                "/folder.vault"
            )
            .is_err()
        );

        let mut duplicate_property = xml(
            "/dav/spaces/space-id/folder.vault/",
            "folder.vault",
            "/dav/spaces/space-id/folder.vault/secret.bin",
            "secret.bin",
        );
        duplicate_property = duplicate_property.replace(
            "<d:resourcetype/><d:getcontentlength>",
            "<d:resourcetype/><oc:fileid>duplicate-id</oc:fileid><d:getcontentlength>",
        );
        assert!(
            parse_listing(
                duplicate_property.as_bytes(),
                &server,
                &space(),
                &root,
                &requested,
                "/folder.vault"
            )
            .is_err()
        );

        let mut repeated_root = xml(
            "/dav/spaces/space-id/folder.vault/",
            "folder.vault",
            "/dav/spaces/space-id/folder.vault/secret.bin",
            "secret.bin",
        );
        let root_response = r#"<d:response><d:href>/dav/spaces/space-id/folder.vault/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><oc:fileid>another-root</oc:fileid><oc:name>folder.vault</oc:name><oc:size>0</oc:size></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"#;
        repeated_root = repeated_root.replace(
            "</d:multistatus>",
            &format!("{root_response}</d:multistatus>"),
        );
        assert!(
            parse_listing(
                repeated_root.as_bytes(),
                &server,
                &space(),
                &root,
                &requested,
                "/folder.vault"
            )
            .is_err()
        );

        let mut nested_scalar = xml(
            "/dav/spaces/space-id/folder.vault/",
            "folder.vault",
            "/dav/spaces/space-id/folder.vault/secret.bin",
            "secret.bin",
        );
        nested_scalar = nested_scalar.replace(
            "<oc:fileid>child-id</oc:fileid>",
            "<oc:fileid><x>child-id</x></oc:fileid>",
        );
        assert!(
            parse_listing(
                nested_scalar.as_bytes(),
                &server,
                &space(),
                &root,
                &requested,
                "/folder.vault"
            )
            .is_err()
        );
    }

    #[test]
    fn logical_paths_reject_traversal_but_allow_trailing_slash() {
        for path in ["relative", "/../escape", "/a//b", "/a/./b", "/a\\b"] {
            assert!(validate_logical_path(path).is_err(), "accepted {path}");
        }
        assert!(validate_logical_path("/").is_ok());
        assert!(validate_logical_path("/a/b/").is_ok());
        let trailing_slash = Url::parse("https://cloud.example/dav/spaces/id/").unwrap();
        assert!(decoded_segments(&trailing_slash).is_ok());
        let duplicate_slash = Url::parse("https://cloud.example/dav//spaces/id/").unwrap();
        assert!(decoded_segments(&duplicate_slash).is_err());
        let repeated_trailing_slash = Url::parse("https://cloud.example/dav/spaces/id//").unwrap();
        assert!(decoded_segments(&repeated_trailing_slash).is_err());
    }

    #[test]
    fn appended_file_paths_do_not_gain_a_collection_slash() {
        let root = Url::parse("https://cloud.example/dav/spaces/space-id/").unwrap();
        let file = append_path(&root, "/ciphertext-name").unwrap();
        assert_eq!(file.path(), "/dav/spaces/space-id/ciphertext-name");

        let directory = append_path(&root, "/folder/").unwrap();
        assert_eq!(directory.path(), "/dav/spaces/space-id/folder/");

        let space_root = append_path(&root, "/").unwrap();
        assert_eq!(space_root.path(), "/dav/spaces/space-id/");
    }

    #[test]
    fn child_vault_markers_are_preserved_without_exposing_child_tokens() {
        let (server, root, requested) = urls("/");
        let mut body = xml(
            "/dav/spaces/space-id/",
            "space-id",
            "/dav/spaces/space-id/renamed-folder/",
            "renamed-folder",
        );
        body = body.replace(
            "<oc:name>renamed-folder</oc:name>",
            "<oc:name>renamed-folder</oc:name><d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype><ocrclone:integrity-id>child-token</ocrclone:integrity-id>",
        );
        body = body.replace(
            "<d:resourcetype/><d:getcontentlength>",
            "<d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>",
        );
        let listing =
            parse_listing(body.as_bytes(), &server, &space(), &root, &requested, "/").unwrap();
        let child = &listing.children[0];
        assert!(child.directory);
        assert!(child.vault_evidence.contains(&VaultEvidence::ContentType));
        assert!(
            child
                .vault_evidence
                .contains(&VaultEvidence::IntegrityProperty)
        );
        assert_eq!(listing.integrity_token.as_deref(), Some("opaque-token"));
    }
}

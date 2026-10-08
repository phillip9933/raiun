//! OpenCloud Graph and WebDAV client used by the desktop engine.
//!
//! The client is deliberately blocking: callers must run it on engine workers.
//! It never follows redirects, and keeps authorization values out of Debug output.

use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use percent_encoding::percent_decode_str;
use quick_xml::{NsReader, events::Event, name::ResolveResult};
use raiun_core::backend::{
    CloudBackend, CloudError, CloudSpace, ErrorKind, RemoteEntry, WriteCondition,
};
use reqwest::{
    Method, StatusCode,
    blocking::{Client, Response},
    header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, IF_MATCH, IF_NONE_MATCH},
};
use serde_json::Value;
use tempfile::NamedTempFile;
use url::Url;

const MAX_GRAPH_BODY: usize = 8 * 1024 * 1024;
const MAX_DAV_RESPONSE: u64 = 32 * 1024 * 1024;
const MAX_DAV_ENTRY: usize = 256 * 1024;
const MAX_ERROR_BODY: usize = 16 * 1024;
const MAX_ENTRIES: usize = 100_000;
const MAX_PAGES: usize = 1_000;
const VAULT_CONTENT_TYPE: &str = "application/vnd.opencloud.vault";
const TRANSFER_TIMEOUT_BASE_SECS: u64 = 120;
const TRANSFER_MIN_BYTES_PER_SECOND: u64 = 256 * 1024;
const TRANSFER_TIMEOUT_MAX_SECS: u64 = 24 * 60 * 60;

// Reqwest's blocking client has no configurable inactivity timeout. Keep
// metadata/control requests on the 120-second client timeout, and give body
// transfers a bounded total deadline based on a conservative 256 KiB/s floor,
// with a 120-second connection/response allowance and a 24-hour hard cap.
// This is a total deadline, not an idle timer. Transfers are not resumable;
// failures discard the staged download or leave the upload to the server's
// conditional-write semantics, and cancellation is only observed at operation
// boundaries or when this deadline expires.
fn transfer_timeout(bytes: u64) -> Duration {
    let transfer_seconds =
        bytes.saturating_add(TRANSFER_MIN_BYTES_PER_SECOND - 1) / TRANSFER_MIN_BYTES_PER_SECOND;
    Duration::from_secs(
        TRANSFER_TIMEOUT_BASE_SECS
            .saturating_add(transfer_seconds)
            .min(TRANSFER_TIMEOUT_MAX_SECS),
    )
}

#[derive(Clone)]
pub struct OpenCloudClient {
    server: Url,
    http: Client,
    token: Arc<Mutex<String>>,
    initiator_id: String,
}

impl std::fmt::Debug for OpenCloudClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenCloudClient")
            .field("server", &self.server)
            .field("token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl OpenCloudClient {
    /// Create a client for an HTTPS OpenCloud server. Plain HTTP is accepted
    /// only for literal IPv4 or IPv6 loopback addresses used by local fixtures.
    pub fn new(server: &str, bearer_token: String) -> Result<Self, CloudError> {
        let server = Url::parse(server).map_err(|_| invalid("server URL is invalid"))?;
        validate_server(&server)?;
        if bearer_token.trim().is_empty() || bearer_token.chars().any(char::is_control) {
            return Err(invalid("bearer token is empty or malformed"));
        }
        let http = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|_| {
                CloudError::new(ErrorKind::Offline, "could not initialize HTTPS client")
            })?;
        Ok(Self {
            server: normalized_server(server),
            http,
            token: Arc::new(Mutex::new(bearer_token)),
            initiator_id: format!("raiun-{}", std::process::id()),
        })
    }

    /// Replace the in-memory bearer token after an external auth layer refreshes it.
    pub fn set_bearer_token(&self, bearer_token: String) -> Result<(), CloudError> {
        if bearer_token.trim().is_empty() || bearer_token.chars().any(char::is_control) {
            return Err(invalid("bearer token is empty or malformed"));
        }
        *self
            .token
            .lock()
            .map_err(|_| invalid("authentication state unavailable"))? = bearer_token;
        Ok(())
    }

    fn token(&self) -> Result<String, CloudError> {
        self.token
            .lock()
            .map(|token| token.clone())
            .map_err(|_| invalid("authentication state unavailable"))
    }

    fn request(
        &self,
        method: Method,
        url: &Url,
    ) -> Result<(reqwest::blocking::RequestBuilder, String), CloudError> {
        if !same_origin(&self.server, url) {
            return Err(invalid(
                "server returned a URL outside the configured origin",
            ));
        }
        let token = self.token()?;
        let request = self
            .http
            .request(method, url.clone())
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header("Initiator-ID", &self.initiator_id)
            .header("X-Requested-With", "XMLHttpRequest");
        Ok((request, token))
    }

    fn graph_get(&self, url: &Url) -> Result<Vec<u8>, CloudError> {
        let (request, token) = self.request(Method::GET, url)?;
        let response = request
            .header("Accept", "application/json")
            .send()
            .map_err(network)?;
        let mut response = checked(response, &[StatusCode::OK], &token)?;
        read_bounded(&mut response, MAX_GRAPH_BODY)
    }

    fn resolve_dav(&self, space: &str, path: &str) -> Result<(CloudSpace, Url), CloudError> {
        let spaces = self.spaces()?;
        let selected = spaces
            .into_iter()
            .find(|candidate| candidate.id == space)
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "cloud space was not found"))?;
        let url = append_logical_path(
            &Url::parse(&selected.dav_url).map_err(|_| invalid("space DAV URL is invalid"))?,
            path,
        )?;
        if !same_origin(&self.server, &url) {
            return Err(invalid("space DAV URL is outside the configured origin"));
        }
        Ok((selected, url))
    }

    fn propfind(
        &self,
        url: &Url,
        depth: &str,
        logical_path: &str,
        visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
    ) -> Result<(), CloudError> {
        let body = b"<?xml version=\"1.0\" encoding=\"utf-8\"?><d:propfind xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\" xmlns:lg=\"http://graph.opencloud.eu/ns\"><d:prop><d:resourcetype/><d:getcontentlength/><d:getetag/><d:getlastmodified/><oc:fileid/><oc:permissions/><lg:encrypted/><lg:contentType/></d:prop></d:propfind>";
        let (request, token) =
            self.request(Method::from_bytes(b"PROPFIND").expect("static method"), url)?;
        let response = request
            .header("Depth", depth)
            .header(CONTENT_TYPE, "application/xml; charset=utf-8")
            .header("Initiator-ID", &self.initiator_id)
            .body(body.as_slice())
            .send()
            .map_err(network)?;
        let mut response = checked(response, &[StatusCode::MULTI_STATUS], &token)?;
        let bytes = read_bounded(&mut response, MAX_DAV_RESPONSE as usize)?;
        parse_multistatus(&bytes, url, logical_path, visit)
    }

    fn ensure_writable_target(
        &self,
        space: &CloudSpace,
        target_url: &Url,
        logical_path: &str,
    ) -> Result<(), CloudError> {
        if space.encrypted {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted Spaces do not accept plaintext writes",
            ));
        }
        if !space.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "OpenCloud Space is read only",
            ));
        }
        let mut entry = None;
        let target_result = self.propfind(target_url, "0", logical_path, &mut |value| {
            if entry.is_some() {
                return Err(invalid("DAV write check returned multiple entries"));
            }
            if value.path.trim_end_matches('/') != logical_path.trim_end_matches('/') {
                return Err(invalid(
                    "DAV write check returned an item other than the requested path",
                ));
            }
            entry = Some(value);
            Ok(())
        });
        let target = match target_result {
            Ok(()) => entry,
            Err(error) if error.kind == ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let checked_entry = if let Some(target) = target {
            target
        } else {
            let parent_path = logical_parent(logical_path);
            let root_url =
                Url::parse(&space.dav_url).map_err(|_| invalid("space DAV URL is invalid"))?;
            let parent_logical = if parent_path == "/" {
                parent_path.clone()
            } else {
                format!("{}/", parent_path)
            };
            let parent_url = append_logical_path(&root_url, &parent_logical)?;
            let mut parent = None;
            self.propfind(&parent_url, "0", &parent_path, &mut |value| {
                if parent.is_some() {
                    return Err(invalid("DAV parent check returned multiple entries"));
                }
                parent = Some(value);
                Ok(())
            })?;
            parent.ok_or_else(|| {
                CloudError::new(ErrorKind::NotFound, "remote parent folder was not found")
            })?
        };
        if checked_entry.encrypted {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted remote content does not accept plaintext writes",
            ));
        }
        if !checked_entry.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "remote folder or item is read only",
            ));
        }
        Ok(())
    }

    fn transfer_url(&self, space: &str, path: &str) -> Result<(CloudSpace, Url), CloudError> {
        self.resolve_dav(space, path)
    }
}

impl CloudBackend for OpenCloudClient {
    fn spaces(&self) -> Result<Vec<CloudSpace>, CloudError> {
        let start = self
            .server
            .join("graph/v1.0/me/drives")
            .map_err(|_| invalid("Graph endpoint is invalid"))?;
        let mut next = Some(start.clone());
        let mut visited = std::collections::HashSet::new();
        let mut ids = std::collections::HashSet::new();
        let mut result = Vec::new();
        while let Some(url) = next.take() {
            if !same_origin(&start, &url)
                || !visited.insert(url.as_str().to_owned())
                || visited.len() > MAX_PAGES
            {
                return Err(invalid("Graph pagination is invalid or exceeds its limit"));
            }
            let payload: Value = serde_json::from_slice(&self.graph_get(&url)?)
                .map_err(|_| invalid("Graph response is invalid JSON"))?;
            let records = payload
                .get("value")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("Graph response has no drive list"))?;
            for record in records {
                let id = required_string(record, "id")?;
                if !ids.insert(id.clone()) || ids.len() > MAX_ENTRIES {
                    return Err(invalid(
                        "Graph drive list contains duplicate IDs or exceeds its limit",
                    ));
                }
                let name = required_string(record, "name")?;
                let drive_type = record
                    .get("driveType")
                    .and_then(Value::as_str)
                    .unwrap_or("project");
                let root = record
                    .get("root")
                    .and_then(Value::as_object)
                    .ok_or_else(|| invalid("Graph drive root is missing"))?;
                let dav_url = root
                    .get("webDavUrl")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("Graph drive WebDAV URL is missing"))?;
                let dav_url = Url::parse(dav_url)
                    .map_err(|_| invalid("Graph drive WebDAV URL is invalid"))?;
                validate_server(&dav_url)?;
                if !same_origin(&self.server, &dav_url) {
                    return Err(invalid(
                        "Graph drive WebDAV URL is outside the configured origin",
                    ));
                }
                let permission_value = root
                    .get("permissions")
                    .or_else(|| root.get("@libre.graph.permissions"))
                    .or_else(|| record.get("@libre.graph.permissions"));
                let encrypted = record
                    .get("@libre.graph.contentType")
                    .and_then(Value::as_str)
                    == Some(VAULT_CONTENT_TYPE)
                    || root.get("@libre.graph.contentType").and_then(Value::as_str)
                        == Some(VAULT_CONTENT_TYPE)
                    || root.get("encrypted").and_then(Value::as_bool) == Some(true)
                    || root.get("contentType").and_then(Value::as_str) == Some(VAULT_CONTENT_TYPE)
                    || record.get("contentType").and_then(Value::as_str)
                        == Some(VAULT_CONTENT_TYPE)
                    || name == ".vault";
                result.push(CloudSpace {
                    id,
                    name: name.clone(),
                    dav_url: dav_url.to_string(),
                    personal: drive_type == "personal",
                    writable: permission_value
                        .map(graph_permissions_writable)
                        .unwrap_or(true),
                    encrypted,
                });
            }
            if let Some(link) = payload.get("@odata.nextLink").and_then(Value::as_str) {
                let url = url
                    .join(link)
                    .map_err(|_| invalid("Graph pagination link is invalid"))?;
                if !same_origin(&start, &url) {
                    return Err(invalid(
                        "Graph pagination link leaves the configured origin",
                    ));
                }
                next = Some(url);
            }
        }
        if !result.iter().any(|space| space.personal) {
            return Err(invalid("Graph response did not include the personal drive"));
        }
        result.sort_by(|a, b| {
            a.personal
                .cmp(&b.personal)
                .reverse()
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(result)
    }

    fn list(
        &self,
        space: &str,
        path: &str,
        visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
    ) -> Result<(), CloudError> {
        let (_, url) = self.transfer_url(space, path)?;
        let scope = path.trim_end_matches('/');
        let mut emitted = 0;
        self.propfind(&url, "1", path, &mut |entry| {
            if entry.path.trim_end_matches('/') == scope {
                return Ok(());
            }
            if !is_direct_child(scope, &entry.path) {
                return Err(invalid(
                    "DAV listing returned an item outside the requested directory",
                ));
            }
            emitted += 1;
            if emitted > MAX_ENTRIES {
                return Err(invalid("DAV listing exceeds its entry limit"));
            }
            visit(entry)
        })
    }

    fn stat(&self, space: &str, path: &str) -> Result<RemoteEntry, CloudError> {
        let (_, url) = self.transfer_url(space, path)?;
        let mut found = None;
        self.propfind(&url, "0", path, &mut |entry| {
            if found.is_some() {
                return Err(invalid("DAV stat returned multiple entries"));
            }
            found = Some(entry);
            Ok(())
        })?;
        let entry = found
            .ok_or_else(|| CloudError::new(ErrorKind::NotFound, "remote item was not found"))?;
        if entry.path.trim_end_matches('/') != path.trim_end_matches('/') {
            return Err(invalid(
                "DAV stat returned an item other than the requested path",
            ));
        }
        Ok(entry)
    }

    fn download(
        &self,
        space: &str,
        path: &str,
        expected_etag: Option<&str>,
        destination: &Path,
    ) -> Result<RemoteEntry, CloudError> {
        let (_, url) = self.transfer_url(space, path)?;
        let before = self.stat(space, path)?;
        if before.encrypted {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "encrypted remote content cannot be downloaded as plaintext",
            ));
        }
        if let Some(expected) = expected_etag {
            if expected != before.etag {
                return Err(conflict("remote item changed before download"));
            }
        }
        let (mut request, token) = self.request(Method::GET, &url)?;
        if let Some(etag) = expected_etag {
            request = request.header(IF_MATCH, etag);
        }
        let response = request
            .timeout(transfer_timeout(before.size))
            .send()
            .map_err(network)?;
        let response = checked(response, &[StatusCode::OK], &token)?;
        let advertised = response
            .content_length()
            .ok_or_else(|| invalid("download response omitted Content-Length"))?;
        if advertised != before.size {
            return Err(conflict("download size changed during transfer"));
        }
        let parent = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut staged = NamedTempFile::new_in(parent).map_err(io_error)?;
        let copied = io::copy(
            &mut response.take(advertised.saturating_add(1)),
            &mut staged,
        )
        .map_err(io_error)?;
        if copied != advertised {
            return Err(invalid("download size did not match Content-Length"));
        }
        staged.as_file_mut().flush().map_err(io_error)?;
        staged.as_file().sync_all().map_err(io_error)?;

        // Keep the caller's destination intact until the server confirms the
        // same revision is still present after the complete body is staged.
        let after = self.stat(space, path)?;
        if after.etag != before.etag || after.size != copied {
            return Err(conflict("remote item changed during download"));
        }
        staged
            .persist(destination)
            .map_err(|error| io_error(error.error))?;
        Ok(after)
    }

    fn upload(
        &self,
        space: &str,
        path: &str,
        source: &Path,
        condition: WriteCondition,
    ) -> Result<RemoteEntry, CloudError> {
        let (selected, url) = self.transfer_url(space, path)?;
        self.ensure_writable_target(&selected, &url, path)?;
        let file = File::open(source).map_err(io_error)?;
        let size = file.metadata().map_err(io_error)?.len();
        let (mut request, token) = self.request(Method::PUT, &url)?;
        request = request
            .header(CONTENT_LENGTH, size)
            .header(CONTENT_TYPE, "application/octet-stream");
        request = match condition {
            WriteCondition::Absent => request.header(IF_NONE_MATCH, "*"),
            WriteCondition::Match(etag) => request.header(IF_MATCH, etag),
        };
        let response = request
            .timeout(transfer_timeout(size))
            .body(reqwest::blocking::Body::new(file))
            .send()
            .map_err(network)?;
        checked(
            response,
            &[StatusCode::CREATED, StatusCode::NO_CONTENT],
            &token,
        )?;
        let entry = self.stat(space, path)?;
        if entry.size != size {
            return Err(invalid("uploaded file failed size verification"));
        }
        Ok(entry)
    }

    fn mkdir(&self, space: &str, path: &str) -> Result<RemoteEntry, CloudError> {
        let (selected, url) = self.transfer_url(space, path)?;
        self.ensure_writable_target(&selected, &url, path)?;
        let (request, token) =
            self.request(Method::from_bytes(b"MKCOL").expect("static method"), &url)?;
        let response = request.send().map_err(network)?;
        checked(response, &[StatusCode::CREATED], &token)?;
        self.stat(space, path)
    }

    fn delete(&self, space: &str, path: &str, expected_etag: &str) -> Result<(), CloudError> {
        let (selected, url) = self.transfer_url(space, path)?;
        self.ensure_writable_target(&selected, &url, path)?;
        let (request, token) = self.request(Method::DELETE, &url)?;
        let response = request
            .header(IF_MATCH, expected_etag)
            .send()
            .map_err(network)?;
        checked(response, &[StatusCode::NO_CONTENT, StatusCode::OK], &token)?;
        Ok(())
    }

    fn rename(
        &self,
        space: &str,
        from: &str,
        to: &str,
        expected_etag: &str,
    ) -> Result<RemoteEntry, CloudError> {
        let (selected, source) = self.transfer_url(space, from)?;
        let (_, destination) = self.transfer_url(space, to)?;
        if source == destination {
            return self.stat(space, from);
        }
        self.ensure_writable_target(&selected, &source, from)?;
        self.ensure_writable_target(&selected, &destination, to)?;
        let (request, token) =
            self.request(Method::from_bytes(b"MOVE").expect("static method"), &source)?;
        let response = request
            .header(IF_MATCH, expected_etag)
            .header("Destination", destination.as_str())
            .header("Overwrite", "F")
            .send()
            .map_err(network)?;
        checked(
            response,
            &[StatusCode::CREATED, StatusCode::NO_CONTENT],
            &token,
        )?;
        self.stat(space, to)
    }
}

fn validate_server(url: &Url) -> Result<(), CloudError> {
    let loopback = url.host_str().is_some_and(|host| {
        host.parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    });
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "server must be HTTPS; HTTP is allowed only for literal loopback test hosts",
        ));
    }
    Ok(())
}

fn normalized_server(mut url: Url) -> Url {
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    url
}
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

fn append_logical_path(root: &Url, path: &str) -> Result<Url, CloudError> {
    validate_logical_path(path)?;
    let mut out = root.clone();
    {
        let mut segments = out
            .path_segments_mut()
            .map_err(|_| invalid("DAV URL cannot contain paths"))?;
        segments.pop_if_empty();
        for part in path.split('/').filter(|part| !part.is_empty()) {
            segments.push(part);
        }
        if path.ends_with('/') || path == "/" {
            segments.push("");
        }
    }
    Ok(out)
}

fn validate_logical_path(path: &str) -> Result<(), CloudError> {
    if !path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path.split('/').any(|part| matches!(part, "." | ".."))
    {
        return Err(invalid(
            "remote path must be absolute and contain no traversal components",
        ));
    }
    Ok(())
}

#[derive(Default, Debug)]
struct DavItem {
    href: String,
    directory: bool,
    size: u64,
    etag: String,
    modified: i64,
    file_id: Option<String>,
    encrypted: bool,
    content_type: Option<String>,
    writable: Option<bool>,
}

fn parse_multistatus(
    bytes: &[u8],
    requested: &Url,
    logical_path: &str,
    visit: &mut dyn FnMut(RemoteEntry) -> Result<(), CloudError>,
) -> Result<(), CloudError> {
    let mut reader = NsReader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut entries = 0usize;
    let mut item: Option<DavItem> = None;
    let mut prop_values = DavItem::default();
    let mut field = String::new();
    let mut depth = 0usize;
    let mut in_prop = false;
    let mut propstat_ok = false;
    let mut saw_root = false;
    loop {
        match reader.read_resolved_event_into(&mut buf) {
            Ok((namespace, Event::Start(e))) => {
                let name = local_name(e.local_name().as_ref()).to_ascii_lowercase();
                let namespace_ok = expected_namespace(&name)
                    .is_some_and(|expected| namespace_is(&namespace, expected));
                if name == "multistatus" {
                    if saw_root || !namespace_is(&namespace, b"DAV:") {
                        return Err(invalid("DAV response has an invalid root element"));
                    }
                    saw_root = true;
                }
                if name == "response" && !namespace_is(&namespace, b"DAV:") {
                    return Err(invalid("DAV response element uses an invalid namespace"));
                }
                depth += 1;
                if name == "response" {
                    if item.is_some() {
                        return Err(invalid("nested DAV response"));
                    }
                    item = Some(DavItem::default());
                    depth = 1;
                }
                if namespace_is(&namespace, b"DAV:") && name == "propstat" {
                    propstat_ok = false;
                    prop_values = DavItem::default();
                }
                if namespace_is(&namespace, b"DAV:") && name == "prop" {
                    in_prop = true;
                }
                if item.is_some() {
                    if depth > 32 {
                        return Err(invalid("DAV entry nesting exceeds its limit"));
                    }
                    field = if namespace_ok {
                        name.clone()
                    } else {
                        String::new()
                    };
                    if namespace_is(&namespace, b"DAV:") && in_prop && name == "collection" {
                        prop_values.directory = true;
                    }
                    if namespace_is(&namespace, b"http://graph.opencloud.eu/ns")
                        && in_prop
                        && name == "encrypted"
                    {
                        prop_values.encrypted = true;
                    }
                }
            }
            Ok((namespace, Event::Empty(e))) => {
                let name = local_name(e.local_name().as_ref()).to_ascii_lowercase();
                if item.is_some() {
                    if namespace_is(&namespace, b"DAV:") && in_prop && name == "collection" {
                        prop_values.directory = true;
                    }
                    if namespace_is(&namespace, b"http://graph.opencloud.eu/ns")
                        && in_prop
                        && name == "encrypted"
                    {
                        prop_values.encrypted = true;
                    }
                }
            }
            Ok((_, Event::Text(e))) => {
                if let Some(ref mut current) = item {
                    let text = e
                        .decode()
                        .map_err(|_| invalid("DAV response contains invalid text"))?;
                    if text.len() > MAX_DAV_ENTRY {
                        return Err(invalid("DAV property exceeds its size limit"));
                    }
                    let value = text.trim();
                    match field.as_str() {
                        "href" if current.href.is_empty() => current.href = value.to_owned(),
                        "getcontentlength" if in_prop => {
                            prop_values.size = value
                                .parse()
                                .map_err(|_| invalid("DAV content length is invalid"))?
                        }
                        "getetag" if in_prop => prop_values.etag = value.to_owned(),
                        "getlastmodified" if in_prop => {
                            prop_values.modified = parse_http_date(value).unwrap_or(0)
                        }
                        "fileid" if in_prop => prop_values.file_id = Some(value.to_owned()),
                        "permissions" if in_prop => {
                            prop_values.writable = Some(dav_permissions_writable(value))
                        }
                        "encrypted" if in_prop => {
                            prop_values.encrypted = value.eq_ignore_ascii_case("true")
                        }
                        "contenttype" if in_prop => {
                            prop_values.content_type = Some(value.to_owned())
                        }
                        "status" if value.split_whitespace().nth(1) == Some("200") => {
                            propstat_ok = true
                        }
                        _ => {}
                    }
                }
            }
            Ok((namespace, Event::End(e))) => {
                let name = local_name(e.local_name().as_ref()).to_ascii_lowercase();
                let dav_element = namespace_is(&namespace, b"DAV:");
                if dav_element && name == "prop" {
                    in_prop = false;
                }
                if dav_element && name == "propstat" && propstat_ok {
                    if let Some(ref mut current) = item {
                        current.directory |= prop_values.directory;
                        current.encrypted |= prop_values.encrypted;
                        current.size = prop_values.size;
                        if !prop_values.etag.is_empty() {
                            current.etag = std::mem::take(&mut prop_values.etag);
                        }
                        current.modified = prop_values.modified;
                        current.file_id = prop_values
                            .file_id
                            .take()
                            .or_else(|| current.file_id.take());
                        current.content_type = prop_values
                            .content_type
                            .take()
                            .or_else(|| current.content_type.take());
                        current.writable = prop_values.writable.or(current.writable);
                    }
                }
                if dav_element && name == "response" {
                    let finished = item
                        .take()
                        .ok_or_else(|| invalid("DAV response structure is invalid"))?;
                    if !finished.href.is_empty() {
                        visit(to_remote_entry(finished, requested, logical_path)?)?;
                        entries += 1;
                        if entries > MAX_ENTRIES {
                            return Err(invalid("DAV response exceeds the entry limit"));
                        }
                    }
                    depth = 0;
                } else if item.is_some() {
                    depth = depth.saturating_sub(1);
                }
                field.clear();
            }
            Ok((_, Event::DocType(_))) => {
                return Err(invalid("DAV response contains a document type declaration"));
            }
            Ok((_, Event::Eof)) => break,
            Err(_) => return Err(invalid("DAV response is malformed XML")),
            _ => {}
        }
        buf.clear();
    }
    if !saw_root || item.is_some() {
        return Err(invalid("DAV response ended inside an entry"));
    }
    Ok(())
}

fn to_remote_entry(
    item: DavItem,
    requested: &Url,
    logical_path: &str,
) -> Result<RemoteEntry, CloudError> {
    let actual = requested
        .join(&item.href)
        .map_err(|_| invalid("DAV response contains an invalid href"))?;
    if !same_origin(requested, &actual) || actual.query().is_some() || actual.fragment().is_some() {
        return Err(invalid("DAV response href leaves the requested origin"));
    }
    let requested_segments: Vec<_> = requested
        .path_segments()
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty())
        .map(decode_safe_segment)
        .collect::<Result<_, _>>()?;
    let actual_segments: Vec<_> = actual
        .path_segments()
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty())
        .map(decode_safe_segment)
        .collect::<Result<_, _>>()?;
    if actual_segments.len() < requested_segments.len()
        || !actual_segments
            .iter()
            .zip(&requested_segments)
            .all(|(a, b)| a == b)
    {
        return Err(invalid("DAV response href is outside requested scope"));
    }
    let relative = &actual_segments[requested_segments.len()..];
    if relative.len() > 1 {
        return Err(invalid("DAV depth-one response returned a nested item"));
    }
    let prefix = if logical_path == "/" {
        String::new()
    } else {
        logical_path.trim_end_matches('/').to_owned()
    };
    let path = if relative.is_empty() {
        if prefix.is_empty() {
            "/".to_owned()
        } else {
            prefix
        }
    } else {
        format!("{prefix}/{}", relative[0])
    };
    let name = relative
        .first()
        .cloned()
        .unwrap_or_else(|| "root".to_owned());
    let etag = item.etag.trim().to_owned();
    if etag.is_empty() {
        return Err(invalid("DAV response omitted an entity tag"));
    }
    let encrypted = item.encrypted
        || item.content_type.as_deref() == Some(VAULT_CONTENT_TYPE)
        || name == ".vault";
    Ok(RemoteEntry {
        id: item
            .file_id
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| actual.to_string()),
        path,
        directory: item.directory,
        size: if item.directory { 0 } else { item.size },
        etag,
        modified_unix: item.modified,
        writable: item.writable.unwrap_or(true),
        encrypted,
    })
}

fn graph_permissions_writable(value: &Value) -> bool {
    fn writable_role(value: &str) -> bool {
        let normalized = value.to_ascii_lowercase();
        matches!(
            normalized.as_str(),
            "w" | "c" | "write" | "writer" | "owner" | "editor" | "create" | "update"
        ) || normalized.contains('w')
            || normalized.contains('c')
    }
    match value {
        Value::String(value) => writable_role(value),
        Value::Array(values) => values.iter().any(|value| {
            value.as_str().is_some_and(writable_role)
                || value.get("roles").is_some_and(graph_permissions_writable)
        }),
        Value::Object(values) => values
            .get("roles")
            .or_else(|| values.get("permissions"))
            .is_some_and(graph_permissions_writable),
        _ => false,
    }
}

fn dav_permissions_writable(value: &str) -> bool {
    let value = value.trim();
    if value.eq_ignore_ascii_case("read") || value.eq_ignore_ascii_case("readonly") {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if lower.contains("write") || lower.contains("update") || lower.contains("create") {
        return true;
    }
    value.contains('W') || value.contains('C')
}

fn logical_parent(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some(("", _)) | None => "/".to_owned(),
        Some((parent, _)) => parent.to_owned(),
    }
}

fn local_name(name: &[u8]) -> &str {
    std::str::from_utf8(name)
        .unwrap_or("")
        .rsplit(':')
        .next()
        .unwrap_or("")
}

fn namespace_is(namespace: &ResolveResult<'_>, expected: &[u8]) -> bool {
    matches!(namespace, ResolveResult::Bound(value) if value.as_ref() == expected)
}

fn expected_namespace(name: &str) -> Option<&'static [u8]> {
    match name {
        "multistatus" | "response" | "href" | "propstat" | "prop" | "status" | "resourcetype"
        | "collection" | "getcontentlength" | "getetag" | "getlastmodified" => Some(b"DAV:"),
        "fileid" | "permissions" => Some(b"http://owncloud.org/ns"),
        "encrypted" | "contenttype" => Some(b"http://graph.opencloud.eu/ns"),
        _ => None,
    }
}

fn decode_safe_segment(segment: &str) -> Result<String, CloudError> {
    let decoded = percent_decode_str(segment)
        .decode_utf8()
        .map_err(|_| invalid("DAV response href contains invalid UTF-8"))?
        .into_owned();
    if decoded.is_empty()
        || decoded == "."
        || decoded == ".."
        || decoded.contains('/')
        || decoded.contains('\\')
        || decoded.chars().any(char::is_control)
    {
        return Err(invalid("DAV response href contains an unsafe name"));
    }
    Ok(decoded)
}
fn is_direct_child(parent: &str, child: &str) -> bool {
    let parent = parent.trim_end_matches('/');
    let tail = child.strip_prefix(parent).unwrap_or("");
    tail.starts_with('/') && !tail[1..].is_empty() && !tail[1..].contains('/')
}
fn required_string(value: &Value, key: &str) -> Result<String, CloudError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid("Graph response omitted a required drive field"))
}
fn read_bounded(reader: &mut impl Read, limit: usize) -> Result<Vec<u8>, CloudError> {
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(response_body_error)?;
    if bytes.len() > limit {
        return Err(invalid("server response exceeds its size limit"));
    }
    Ok(bytes)
}

fn checked(
    mut response: Response,
    expected: &[StatusCode],
    bearer_token: &str,
) -> Result<Response, CloudError> {
    if expected.contains(&response.status()) {
        return Ok(response);
    }
    if response.status().is_redirection() {
        return Err(CloudError::new(
            ErrorKind::InvalidResponse,
            format!(
                "OpenCloud {} request returned redirect HTTP {}; redirects are not followed",
                endpoint_kind(response.url()),
                response.status().as_u16()
            ),
        ));
    }
    let status = response.status();
    let endpoint = endpoint_kind(response.url());
    let request_id = response_request_id(&response, Some(bearer_token));
    let error_code = response_error_code(&mut response, Some(bearer_token));
    let kind = match status {
        StatusCode::UNAUTHORIZED => ErrorKind::Unauthorized,
        StatusCode::FORBIDDEN => ErrorKind::Forbidden,
        StatusCode::NOT_FOUND => ErrorKind::NotFound,
        StatusCode::PRECONDITION_FAILED
        | StatusCode::CONFLICT
        | StatusCode::PRECONDITION_REQUIRED => ErrorKind::Conflict,
        StatusCode::TOO_MANY_REQUESTS
        | StatusCode::BAD_GATEWAY
        | StatusCode::SERVICE_UNAVAILABLE
        | StatusCode::GATEWAY_TIMEOUT => ErrorKind::Offline,
        _ => ErrorKind::InvalidResponse,
    };
    let mut message = format!(
        "OpenCloud {endpoint} request failed with HTTP {}",
        status.as_u16()
    );
    let mut diagnostics = Vec::new();
    if let Some(code) = error_code {
        diagnostics.push(format!("code={code}"));
    }
    if let Some(request_id) = request_id {
        diagnostics.push(format!("request_id={request_id}"));
    }
    if !diagnostics.is_empty() {
        message.push_str(" (");
        message.push_str(&diagnostics.join(", "));
        message.push(')');
    }
    Err(CloudError::new(kind, message))
}

fn endpoint_kind(url: &Url) -> &'static str {
    let segments: Vec<_> = url.path().split('/').collect();
    if segments
        .windows(2)
        .any(|pair| pair[0] == "graph" && pair[1] == "v1.0")
    {
        "Graph discovery"
    } else {
        "WebDAV"
    }
}

fn response_request_id(response: &Response, secret: Option<&str>) -> Option<String> {
    [
        "request-id",
        "x-request-id",
        "x-correlation-id",
        "oc-request-id",
        "x-ms-request-id",
    ]
    .iter()
    .find_map(|name| response.headers().get(*name)?.to_str().ok())
    .and_then(|value| safe_diagnostic_value(value, 128, secret))
}

fn response_error_code(response: &mut Response, secret: Option<&str>) -> Option<String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ERROR_BODY as u64)
    {
        return None;
    }
    let mut body = Vec::new();
    (&mut *response)
        .take(MAX_ERROR_BODY as u64 + 1)
        .read_to_end(&mut body)
        .ok()?;
    if body.len() > MAX_ERROR_BODY {
        return None;
    }
    let payload: Value = serde_json::from_slice(&body).ok()?;
    [
        payload.pointer("/error/code"),
        payload.get("code"),
        payload.pointer("/ocs/error/code"),
        payload.pointer("/ocs/meta/code"),
    ]
    .into_iter()
    .flatten()
    .find_map(Value::as_str)
    .and_then(|value| safe_diagnostic_value(value, 64, secret))
}

fn safe_diagnostic_value(value: &str, max_len: usize, secret: Option<&str>) -> Option<String> {
    if value.is_empty()
        || value.len() > max_len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        || secret.is_some_and(|secret| !secret.is_empty() && value.contains(secret))
    {
        return None;
    }
    Some(value.to_owned())
}

fn network(_: reqwest::Error) -> CloudError {
    CloudError::new(ErrorKind::Offline, "OpenCloud server could not be reached")
}
fn response_body_error(_: io::Error) -> CloudError {
    CloudError::new(ErrorKind::Offline, "OpenCloud response ended unexpectedly")
}
fn io_error(error: io::Error) -> CloudError {
    CloudError::new(
        ErrorKind::Io,
        format!("local file operation failed: {error}"),
    )
}
fn invalid(message: &str) -> CloudError {
    CloudError::new(ErrorKind::InvalidResponse, message)
}
fn conflict(message: &str) -> CloudError {
    CloudError::new(ErrorKind::Conflict, message)
}

fn parse_http_date(value: &str) -> Option<i64> {
    // HTTP-date parsing without an additional date dependency; invalid metadata is non-fatal.
    let parts: Vec<_> = value.split_whitespace().collect();
    if parts.len() != 6 {
        return None;
    }
    let day: i64 = parts[1].parse().ok()?;
    let month = match parts[2] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = parts[3].parse().ok()?;
    let mut time = parts[4].split(':');
    let h: i64 = time.next()?.parse().ok()?;
    let m: i64 = time.next()?.parse().ok()?;
    let s: i64 = time.next()?.parse().ok()?;
    if parts[5] != "GMT" {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    Some(days * 86_400 + h * 3_600 + m * 60 + s)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let y = year - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    #[test]
    fn transfer_timeout_scales_and_saturates_safely() {
        assert_eq!(transfer_timeout(0).as_secs(), TRANSFER_TIMEOUT_BASE_SECS);
        assert_eq!(
            transfer_timeout(1).as_secs(),
            TRANSFER_TIMEOUT_BASE_SECS + 1
        );
        assert_eq!(
            transfer_timeout(TRANSFER_MIN_BYTES_PER_SECOND).as_secs(),
            TRANSFER_TIMEOUT_BASE_SECS + 1
        );
        assert_eq!(
            transfer_timeout(TRANSFER_MIN_BYTES_PER_SECOND + 1).as_secs(),
            TRANSFER_TIMEOUT_BASE_SECS + 2
        );
        let bytes_at_cap = (TRANSFER_TIMEOUT_MAX_SECS - TRANSFER_TIMEOUT_BASE_SECS)
            * TRANSFER_MIN_BYTES_PER_SECOND;
        assert_eq!(
            transfer_timeout(bytes_at_cap).as_secs(),
            TRANSFER_TIMEOUT_MAX_SECS
        );
        assert_eq!(
            transfer_timeout(bytes_at_cap + 1).as_secs(),
            TRANSFER_TIMEOUT_MAX_SECS
        );
        assert_eq!(
            transfer_timeout(u64::MAX).as_secs(),
            TRANSFER_TIMEOUT_MAX_SECS
        );
    }

    fn fixture(
        responses: Vec<(&'static str, String)>,
    ) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_authority = address.to_string();
        let worker = thread::spawn(move || {
            let mut seen = Vec::new();
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut chunk).is_err() {
                        break;
                    }
                    request.push(chunk[0]);
                }
                let header = String::from_utf8_lossy(&request).to_string();
                let length = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                let mut rest = vec![0; length];
                if length > 0 {
                    let _ = stream.read_exact(&mut rest);
                }
                seen.push(format!("{header}\nBODY_BYTES={}", rest.len()));
                let body = body.replace("127.0.0.1:PORT", &server_authority);
                let response_body = body.as_bytes();
                write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n", response_body.len()).unwrap();
                stream.write_all(response_body).unwrap();
            }
            seen
        });
        (format!("http://{address}"), worker)
    }

    const GRAPH: &str = r#"{"value":[{"id":"drive-1","name":"Personal","driveType":"personal","root":{"id":"root","webDavUrl":"http://127.0.0.1:PORT/dav/personal/"}}]}"#;

    #[test]
    fn client_rejects_non_loopback_http_and_redacts_debug() {
        assert!(OpenCloudClient::new("http://example.com", "secret-token".into()).is_err());
        let client = OpenCloudClient::new("http://127.0.0.1:1234", "secret-token".into()).unwrap();
        assert!(!format!("{client:?}").contains("secret-token"));
    }

    #[test]
    fn paths_reject_traversal_and_parser_rejects_hostile_href() {
        assert!(validate_logical_path("/../../etc").is_err());
        let xml = br#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>http://evil.example/x</d:href><d:propstat><d:prop><d:resourcetype/><d:getetag>\"x\"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#;
        let requested = Url::parse("https://cloud.example/dav/").unwrap();
        assert!(parse_multistatus(xml, &requested, "/", &mut |_| Ok(())).is_err());
    }

    #[test]
    fn redirects_are_not_followed_and_graph_pages_are_origin_bound() {
        let (server, worker) = fixture(vec![("302 Found", String::new())]);
        let client = OpenCloudClient::new(&server, "secret-token".into()).unwrap();
        assert_eq!(
            client.spaces().unwrap_err().kind,
            ErrorKind::InvalidResponse
        );
        let requests = worker.join().unwrap();
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains("authorization: bearer secret-token")
        );
        assert!(requests[0].starts_with("GET /graph/v1.0/me/drives"));
    }

    #[test]
    fn list_stream_boundary_returns_only_direct_children_and_marks_vault_directory() {
        let xml = r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>"root"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/dav/personal/notes.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>3</d:getcontentlength><d:getetag>"a1"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/dav/personal/.vault/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>"vault"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", xml),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let mut entries = Vec::new();
        client
            .list("drive-1", "/", &mut |entry| {
                entries.push(entry);
                Ok(())
            })
            .unwrap();
        worker.join().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "/notes.txt");
        assert_eq!(entries[0].size, 3);
        assert!(entries[1].encrypted);
        assert_eq!(entries[1].path, "/.vault");
    }

    #[test]
    fn failed_listing_does_not_report_a_complete_snapshot() {
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("500 Internal Server Error", String::new()),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let mut emitted = 0;
        let result = client.list("drive-1", "/", &mut |_| {
            emitted += 1;
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(emitted, 0);
        worker.join().unwrap();
    }

    #[test]
    fn http_error_reports_only_safe_graph_code_and_request_id() {
        let body = r#"{"error":{"code":"InternalServerError","message":"request failed for bearer secret-token"}}"#.to_owned();
        let (server, worker) = fixture(vec![(
            "500 Internal Server Error\r\nX-Request-ID: req-7a21",
            body,
        )]);
        let client = OpenCloudClient::new(&server, "secret-token".into()).unwrap();
        let error = client.spaces().unwrap_err();
        worker.join().unwrap();
        assert!(error.message.contains("Graph discovery"));
        assert!(error.message.contains("HTTP 500"));
        assert!(error.message.contains("code=InternalServerError"));
        assert!(error.message.contains("request_id=req-7a21"));
        assert!(!error.message.contains("secret-token"));
        assert!(!error.message.contains("for bearer"));
    }

    #[test]
    fn malformed_or_oversized_error_body_is_not_reflected() {
        let malformed = "not-json secret-token".to_owned();
        let (server, worker) = fixture(vec![("500 Internal Server Error", malformed)]);
        let client = OpenCloudClient::new(&server, "secret-token".into()).unwrap();
        let error = client.spaces().unwrap_err();
        worker.join().unwrap();
        assert!(error.message.contains("Graph discovery"));
        assert!(!error.message.contains("not-json"));
        assert!(!error.message.contains("secret-token"));
        assert!(!error.message.contains("code="));

        let oversized = format!(
            r#"{{"error":{{"code":"ShouldNotBeParsed"}},"padding":"{}"}}"#,
            "x".repeat(MAX_ERROR_BODY)
        );
        let (server, worker) = fixture(vec![("500 Internal Server Error", oversized)]);
        let client = OpenCloudClient::new(&server, "another-secret".into()).unwrap();
        let error = client.spaces().unwrap_err();
        worker.join().unwrap();
        assert!(!error.message.contains("ShouldNotBeParsed"));
        assert!(!error.message.contains("padding"));

        let body = r#"{"error":{"code":"another-secret"}}"#.to_owned();
        let (server, worker) = fixture(vec![(
            "500 Internal Server Error\r\nX-Request-ID: another-secret",
            body,
        )]);
        let client = OpenCloudClient::new(&server, "another-secret".into()).unwrap();
        let error = client.spaces().unwrap_err();
        worker.join().unwrap();
        assert!(!error.message.contains("another-secret"));
        assert!(!error.message.contains("code="));
        assert!(!error.message.contains("request_id="));
    }

    #[test]
    fn conditional_delete_maps_etag_mismatch_to_conflict() {
        let writable_target = r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/stale.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>3</d:getcontentlength><d:getetag>"old"</d:getetag><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", writable_target),
            ("412 Precondition Failed", String::new()),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let error = client
            .delete("drive-1", "/stale.txt", "\"old\"")
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Conflict);
        assert!(
            error
                .message
                .contains("OpenCloud WebDAV request failed with HTTP 412")
        );
        let requests = worker.join().unwrap();
        assert!(
            requests[2]
                .to_ascii_lowercase()
                .contains("if-match: \"old\"")
        );
    }

    #[test]
    fn download_keeps_existing_destination_when_final_remote_stat_fails() {
        let stat = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/file.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>3</d:getcontentlength><d:getetag>"v1"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", stat),
            ("200 OK", "new".to_owned()),
            ("200 OK", GRAPH.to_owned()),
            ("500 Internal Server Error", String::new()),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("destination.txt");
        std::fs::write(&destination, b"keep").unwrap();
        assert!(
            client
                .download("drive-1", "/file.txt", Some("\"v1\""), &destination)
                .is_err()
        );
        assert_eq!(std::fs::read(&destination).unwrap(), b"keep");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        worker.join().unwrap();
    }

    #[test]
    fn stat_rejects_a_dav_response_for_a_different_path() {
        let wrong = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/other.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>1</d:getcontentlength><d:getetag>"v1"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", wrong),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        assert_eq!(
            client.stat("drive-1", "/requested.txt").unwrap_err().kind,
            ErrorKind::InvalidResponse
        );
        worker.join().unwrap();
    }

    #[test]
    fn spaces_report_root_permissions_and_vault_markers() {
        let graph = r#"{"value":[{"id":"drive-1","name":"Personal","driveType":"personal","root":{"id":"root","webDavUrl":"http://127.0.0.1:PORT/dav/personal/","permissions":"R"}},{"id":"vault","name":"Vault","root":{"id":"vault-root","webDavUrl":"http://127.0.0.1:PORT/dav/vault/","@libre.graph.contentType":"application/vnd.opencloud.vault"}}]}"#.to_owned();
        let (server, worker) = fixture(vec![("200 OK", graph)]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let spaces = client.spaces().unwrap();
        worker.join().unwrap();
        let personal = spaces.iter().find(|space| space.id == "drive-1").unwrap();
        let vault = spaces.iter().find(|space| space.id == "vault").unwrap();
        assert!(!personal.writable);
        assert!(vault.encrypted);
    }

    #[test]
    fn upload_rejects_a_dav_stat_marked_read_only() {
        let readonly = r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/upload.bin</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>0</d:getcontentlength><d:getetag>"old"</d:getetag><oc:permissions>R</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", readonly),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let source = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(
            client
                .upload(
                    "drive-1",
                    "/upload.bin",
                    source.path(),
                    WriteCondition::Match("old".into())
                )
                .unwrap_err()
                .kind,
            ErrorKind::Forbidden
        );
        worker.join().unwrap();
    }

    #[test]
    fn upload_rejects_a_read_only_space_before_webdav_mutation() {
        let graph = r#"{"value":[{"id":"drive-1","name":"Personal","driveType":"personal","root":{"id":"root","webDavUrl":"http://127.0.0.1:PORT/dav/personal/","permissions":"R"}}]}"#.to_owned();
        let (server, worker) = fixture(vec![("200 OK", graph)]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let source = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(
            client
                .upload(
                    "drive-1",
                    "/upload.bin",
                    source.path(),
                    WriteCondition::Absent
                )
                .unwrap_err()
                .kind,
            ErrorKind::Forbidden
        );
        worker.join().unwrap();
    }

    #[test]
    fn upload_streams_file_bytes_and_verifies_remote_size() {
        let xml = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/personal/upload.bin</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>524288</d:getcontentlength><d:getetag>"new"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let writable_root = r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>"root"</d:getetag><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#.to_owned();
        let (server, worker) = fixture(vec![
            ("200 OK", GRAPH.to_owned()),
            ("404 Not Found", String::new()),
            ("207 Multi-Status", writable_root),
            ("201 Created", String::new()),
            ("200 OK", GRAPH.to_owned()),
            ("207 Multi-Status", xml),
        ]);
        let client = OpenCloudClient::new(&server, "token".into()).unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        let payload = vec![0x5a; 512 * 1024];
        std::fs::write(file.path(), &payload).unwrap();
        let entry = client
            .upload(
                "drive-1",
                "/upload.bin",
                file.path(),
                WriteCondition::Absent,
            )
            .unwrap();
        assert_eq!(entry.size, payload.len() as u64);
        let requests = worker.join().unwrap();
        assert!(requests[3].starts_with("PUT /dav/personal/upload.bin"));
        assert!(
            requests[3]
                .to_ascii_lowercase()
                .contains("content-length: 524288")
        );
        assert!(requests[3].contains("BODY_BYTES=524288"));
    }
}

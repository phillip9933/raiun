//! OpenCloud 9 file and folder guest invitations through Graph permissions.
//!
//! This API deliberately does not use OCS share types or expose invitation URLs.

use super::{
    CloudBackend, OpenCloudClient, RangeReadContext, StatusCode, checked, invalid, network,
    read_bounded, same_origin,
};
use raiun_core::backend::{CloudError, ErrorKind};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

const METADATA_LIMIT: usize = 2 * 1024 * 1024;
const MAX_PERMISSIONS: usize = 1_000;
const MAX_ROLES: usize = 64;
const MAX_ID: usize = 4_096;

/// Opaque Graph item identity. DAV paths and public invitation URLs are not accepted.
#[derive(Clone, Debug)]
pub struct GuestShareTarget {
    drive_id: String,
    item_id: String,
    client_generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
    generation: u64,
    /// Set when the caller's selected Graph metadata identifies a Space root.
    is_space_root: bool,
    /// Set when the caller's selected metadata identifies encrypted content.
    encrypted: bool,
    /// Verified from the selected ordinary item metadata.
    is_folder: bool,
}

impl GuestShareTarget {
    fn new(
        client: &OpenCloudClient,
        drive_id: impl Into<String>,
        item_id: impl Into<String>,
    ) -> Result<Self, CloudError> {
        let value = Self {
            drive_id: drive_id.into(),
            item_id: item_id.into(),
            client_generation: client.token_generation.clone(),
            generation: client.token_generation(),
            is_space_root: false,
            encrypted: false,
            is_folder: false,
        };
        validate_segment(&value.drive_id)?;
        validate_segment(&value.item_id)?;
        Ok(value)
    }

    /// The validated Graph item identifier bound to this account generation.
    pub fn item_id(&self) -> &str {
        &self.item_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestRole {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestPermission {
    pub id: String,
    pub email: String,
    pub roles: Vec<String>,
    pub expiration_date_time: Option<String>,
    pub inherited: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestPermissions {
    pub guests: Vec<GuestPermission>,
    pub roles: Vec<GuestRole>,
}

/// Exact, read-only server flags used to gate the sender workflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestSharingCapabilities {
    pub files_sharing_enabled: bool,
    pub guest_links_enabled: bool,
}

/// Strict flags used by ordinary people/group and public-link operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharingCapabilities {
    pub files_sharing_enabled: bool,
    pub groups_enabled: bool,
    pub public_links_enabled: bool,
    pub public_link_creation_supported: bool,
    pub public_password_enforced: Option<bool>,
    pub public_password_required_for: Option<Vec<String>>,
    pub public_expiration_enabled: Option<bool>,
    pub public_expiration_enforced: Option<bool>,
    pub public_upload_enabled: Option<bool>,
    pub public_upload_only_enabled: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrdinaryRecipientKind {
    User,
    Group,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrdinaryShare {
    pub permission_id: String,
    pub recipient_kind: OrdinaryRecipientKind,
    pub recipient_id: String,
    pub display_name: Option<String>,
    pub roles: Vec<String>,
    pub expiration_date_time: Option<String>,
    pub inherited: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrdinaryRecipient {
    pub id: String,
    pub kind: OrdinaryRecipientKind,
    pub display_name: String,
    pub mail: Option<String>,
}

/// Share link metadata. The URL is intentionally excluded from Debug output.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicShareLink {
    pub permission_id: String,
    pub link_type: String,
    pub display_name: Option<String>,
    pub web_url: Option<String>,
    pub expiration_date_time: Option<String>,
    pub inherited: bool,
    pub password_protected: Option<bool>,
}

impl std::fmt::Debug for PublicShareLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicShareLink")
            .field("permission_id", &self.permission_id)
            .field("link_type", &self.link_type)
            .field("display_name", &self.display_name)
            .field("web_url", &"[redacted]")
            .field("expiration_date_time", &self.expiration_date_time)
            .field("inherited", &self.inherited)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrdinarySharingPermissions {
    pub roles: Vec<GuestRole>,
    pub people_and_groups: Vec<OrdinaryShare>,
    pub public_links: Vec<PublicShareLink>,
}

impl OpenCloudClient {
    /// Resolve a file/folder through the authenticated provider and reject roots,
    /// encrypted Spaces, encrypted ancestors, and encrypted leaves before creating
    /// the opaque Graph target. Call this from the account-bound UI/IPC layer.
    pub fn guest_share_target(
        &self,
        space: &str,
        path: &str,
    ) -> Result<GuestShareTarget, CloudError> {
        if path == "/" || path.trim_matches('/').is_empty() {
            return Err(invalid("guest invitations are unavailable for Space roots"));
        }
        let generation = self.token_generation();
        let (selected, _) = self.transfer_url(space, path)?;
        if selected.encrypted {
            return Err(invalid(
                "guest invitations are unavailable for encrypted Spaces",
            ));
        }
        self.ensure_plain_ancestors(&selected, path, false)?;
        let entry = CloudBackend::stat(self, space, path)?;
        if entry.encrypted {
            return Err(invalid(
                "guest invitations are unavailable for encrypted content",
            ));
        }
        if self.token_generation() != generation {
            return Err(invalid(
                "account session changed while resolving guest target",
            ));
        }
        let mut target = GuestShareTarget::new(self, selected.id, entry.id)?;
        target.generation = generation;
        target.is_folder = entry.directory;
        Ok(target)
    }

    /// Fetch item permissions and current server-allowed guest roles.
    pub fn guest_permissions(
        &self,
        target: &GuestShareTarget,
    ) -> Result<GuestPermissions, CloudError> {
        self.guest_permissions_at_generation(target, None)
    }

    /// Read the two explicit OCS capability booleans that gate guest sharing.
    /// No server-version heuristic or legacy truthy-string coercion is applied.
    pub fn guest_sharing_capabilities(&self) -> Result<GuestSharingCapabilities, CloudError> {
        self.fetch_guest_sharing_capabilities(self.token_generation())
    }

    /// Read ordinary sharing flags. The capability response is authoritative;
    /// missing or non-boolean fields never enable a sharing method.
    pub fn sharing_capabilities(&self) -> Result<SharingCapabilities, CloudError> {
        self.fetch_sharing_capabilities(self.token_generation())
    }

    /// Return the documented link types available for this verified item and
    /// the server's advertised upload/policy flags.
    pub fn supported_public_link_types(
        &self,
        target: &GuestShareTarget,
    ) -> Result<Vec<String>, CloudError> {
        let generation = self.require_target_generation(target)?;
        let caps = self.fetch_sharing_capabilities(generation)?;
        if !caps.public_link_creation_supported {
            return Err(unsupported_capabilities(
                "server public link capability is unavailable",
            ));
        }
        let mut types = vec!["view".to_owned(), "edit".to_owned()];
        if target.is_folder && caps.public_upload_enabled == Some(true) {
            types.push("upload".to_owned());
        }
        if target.is_folder && caps.public_upload_only_enabled == Some(true) {
            types.push("createOnly".to_owned());
        }
        Ok(types)
    }

    /// List all permissions the server returns for this one ordinary item.
    /// This is intentionally item-scoped, not an account-wide inventory.
    pub fn ordinary_sharing_permissions(
        &self,
        target: &GuestShareTarget,
    ) -> Result<OrdinarySharingPermissions, CloudError> {
        let generation = self.require_target_generation(target)?;
        let caps = self.fetch_sharing_capabilities(generation)?;
        if !caps.files_sharing_enabled {
            return Err(unsupported_capabilities(
                "server file sharing capability is unavailable",
            ));
        }
        let data = self.guest_request(
            target,
            &[],
            Method::GET,
            None,
            &[StatusCode::OK],
            Some(generation),
        )?;
        parse_ordinary_permissions(&data)
    }

    /// Create one user or group grant after a fresh permission/role read.
    /// This accepts server object IDs, not email addresses or OCS share types.
    pub fn invite_ordinary(
        &self,
        target: &GuestShareTarget,
        recipient_kind: OrdinaryRecipientKind,
        recipient_id: &str,
        role_id: &str,
        expiration: Option<&str>,
    ) -> Result<OrdinaryShare, CloudError> {
        let generation = self.require_target_generation(target)?;
        validate_segment(recipient_id)?;
        validate_requested_expiry(expiration)?;
        let current = self.ordinary_sharing_permissions(target)?;
        if recipient_kind == OrdinaryRecipientKind::Group {
            let caps = self.fetch_sharing_capabilities(generation)?;
            if !caps.groups_enabled {
                return Err(unsupported_capabilities(
                    "server group sharing capability is unavailable",
                ));
            }
        }
        require_role(role_id, &current.roles)?;
        self.verify_ordinary_recipient(generation, recipient_kind, recipient_id)?;
        let type_value = match recipient_kind {
            OrdinaryRecipientKind::User => "user",
            OrdinaryRecipientKind::Group => "group",
        };
        let mut body = json!({
            "recipients":[{"@libre.graph.recipient.type":type_value,"objectId":recipient_id}],
            "roles":[role_id]
        });
        if let Some(expiry) = expiration {
            body["expirationDateTime"] = json!(expiry);
        }
        let response = self.guest_request(
            target,
            &["invite"],
            Method::POST,
            Some(body),
            &[StatusCode::OK],
            Some(generation),
        )?;
        let row = single_permission(&response)?;
        let grant = parse_ordinary_share(row, &current.roles)?
            .ok_or_else(|| invalid("invitation response was not a user or group grant"))?;
        if grant.recipient_kind != recipient_kind
            || grant.recipient_id != recipient_id
            || grant.roles != [role_id]
        {
            return Err(invalid(
                "invitation response did not match the requested grant",
            ));
        }
        Ok(grant)
    }

    /// Change the role of an existing user/group grant. The Graph contract
    /// exposes roles as the mutable permission property; expiry editing is not
    /// assumed by this adapter.
    pub fn update_ordinary_role(
        &self,
        target: &GuestShareTarget,
        permission_id: &str,
        role_id: &str,
    ) -> Result<OrdinaryShare, CloudError> {
        let generation = self.require_target_generation(target)?;
        validate_segment(permission_id)?;
        let current = self.ordinary_sharing_permissions(target)?;
        let previous = current
            .people_and_groups
            .iter()
            .find(|share| share.permission_id == permission_id && !share.inherited)
            .ok_or_else(|| invalid("permission is not a current user or group grant"))?;
        require_role(role_id, &current.roles)?;
        let expected_kind = previous.recipient_kind;
        let expected_id = previous.recipient_id.clone();
        let response = self.guest_request(
            target,
            &[permission_id],
            Method::PATCH,
            Some(json!({"roles":[role_id]})),
            &[StatusCode::OK],
            Some(generation),
        )?;
        let updated = parse_ordinary_share(&response, &current.roles)?
            .ok_or_else(|| invalid("updated permission was not a user or group grant"))?;
        if updated.permission_id != permission_id
            || updated.inherited
            || updated.recipient_kind != expected_kind
            || updated.recipient_id != expected_id
            || updated.roles != [role_id]
        {
            return Err(invalid(
                "updated permission did not match the current grant",
            ));
        }
        Ok(updated)
    }

    /// Revoke a user/group grant only after a fresh item-scoped read.
    pub fn revoke_ordinary(
        &self,
        target: &GuestShareTarget,
        permission_id: &str,
    ) -> Result<(), CloudError> {
        let generation = self.require_target_generation(target)?;
        validate_segment(permission_id)?;
        let current = self.ordinary_sharing_permissions(target)?;
        if !current
            .people_and_groups
            .iter()
            .any(|share| share.permission_id == permission_id && !share.inherited)
        {
            return Err(invalid("permission is not a current user or group grant"));
        }
        self.guest_request(
            target,
            &[permission_id],
            Method::DELETE,
            None,
            &[StatusCode::NO_CONTENT],
            Some(generation),
        )?;
        Ok(())
    }

    /// Look up visible server users/groups for an explicit recipient search.
    /// OpenCloud documents list routes, not server-side search parameters, so
    /// this bounded operation filters a single bounded directory response.
    pub fn search_ordinary_recipients(
        &self,
        query: &str,
        kind: OrdinaryRecipientKind,
    ) -> Result<Vec<OrdinaryRecipient>, CloudError> {
        if query.trim().is_empty() || query.len() > 256 || query.chars().any(char::is_control) {
            return Err(invalid("recipient search query is invalid"));
        }
        let generation = self.token_generation();
        let caps = self.fetch_sharing_capabilities(generation)?;
        if !caps.files_sharing_enabled {
            return Err(unsupported_capabilities(
                "server file sharing capability is unavailable",
            ));
        }
        if kind == OrdinaryRecipientKind::Group && !caps.groups_enabled {
            return Err(unsupported_capabilities(
                "server group sharing capability is unavailable",
            ));
        }
        let segment = match kind {
            OrdinaryRecipientKind::User => "users",
            OrdinaryRecipientKind::Group => "groups",
        };
        let url = self
            .server
            .join(&format!("graph/v1.0/{segment}"))
            .map_err(|_| invalid("recipient directory endpoint is invalid"))?;
        if !same_origin(&self.server, &url) {
            return Err(invalid(
                "recipient directory endpoint left the configured origin",
            ));
        }
        let (request, token) = self.request_with_context(
            Method::GET,
            &url,
            Some(RangeReadContext {
                deadline: guest_deadline(),
                token_generation: generation,
            }),
        )?;
        let response = request
            .header("Accept", "application/json")
            .send()
            .map_err(network)?;
        let mut response = checked(response, &[StatusCode::OK], &token)?;
        let bytes = read_bounded(&mut response, METADATA_LIMIT)?;
        let document: Value = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("recipient directory response is invalid JSON"))?;
        let rows = collection(&document, false)?;
        let needle = query.to_lowercase();
        let recipients = rows
            .into_iter()
            .filter(|row| {
                kind != OrdinaryRecipientKind::User
                    || string(row, "@libre.graph.userType") != Some("Guest")
            })
            .map(|row| parse_recipient(row, kind))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(recipients
            .into_iter()
            .filter(|recipient| {
                recipient.display_name.to_lowercase().contains(&needle)
                    || recipient.id.to_lowercase().contains(&needle)
                    || recipient
                        .mail
                        .as_deref()
                        .is_some_and(|mail| mail.to_lowercase().contains(&needle))
            })
            .collect())
    }

    /// Create a public link with one of the Graph API's documented link types.
    pub fn create_public_link(
        &self,
        target: &GuestShareTarget,
        link_type: &str,
        display_name: Option<&str>,
        expiration: Option<&str>,
    ) -> Result<PublicShareLink, CloudError> {
        self.create_public_link_with_password(target, link_type, display_name, expiration, None)
    }

    /// Use a transient caller-supplied password without persisting it or
    /// including it in returned metadata.
    pub fn create_public_link_with_password(
        &self,
        target: &GuestShareTarget,
        link_type: &str,
        display_name: Option<&str>,
        expiration: Option<&str>,
        password: Option<&str>,
    ) -> Result<PublicShareLink, CloudError> {
        let generation = self.require_target_generation(target)?;
        validate_link_type(link_type)?;
        if link_type == "blocksDownload" {
            return Err(unsupported_capabilities(
                "secure-view link creation is not advertised by OpenCloud",
            ));
        }
        if matches!(link_type, "upload" | "createOnly") && !target.is_folder {
            return Err(invalid("upload-only links require a folder target"));
        }
        validate_display_name(display_name)?;
        validate_requested_expiry(expiration)?;
        let before = self.ordinary_sharing_permissions(target)?;
        let caps = self.fetch_sharing_capabilities(generation)?;
        if !caps.public_links_enabled {
            return Err(unsupported_capabilities(
                "server public link capability is unavailable",
            ));
        }
        let required = caps.public_password_required_for.as_ref().ok_or_else(|| {
            unsupported_capabilities("public-link password enforcement is unknown")
        })?;
        if password.is_some_and(|value| value.is_empty() || value.len() > 72) {
            return Err(invalid(
                "public-link passwords must contain 1 to 72 UTF-8 bytes",
            ));
        }
        if required.iter().any(|kind| kind == link_type) && password.is_none() {
            return Err(invalid("server requires a password for this public link"));
        }
        if !public_expiration_policy_known(
            caps.public_expiration_enabled,
            caps.public_expiration_enforced,
        ) {
            return Err(unsupported_capabilities(
                "server public-link expiration policy is unavailable",
            ));
        }
        if caps.public_expiration_enforced == Some(true) && expiration.is_none() {
            return Err(invalid("server requires an expiration for public links"));
        }
        if expiration.is_some() && caps.public_expiration_enabled != Some(true) {
            return Err(unsupported_capabilities(
                "server public link expiration support is disabled or unknown",
            ));
        }
        if link_type == "upload" && caps.public_upload_enabled != Some(true) {
            return Err(unsupported_capabilities(
                "server upload links are not explicitly enabled",
            ));
        }
        if link_type == "createOnly" && caps.public_upload_only_enabled != Some(true) {
            return Err(unsupported_capabilities(
                "server upload-only links are not explicitly enabled",
            ));
        }
        let mut body = json!({"type":link_type});
        if let Some(name) = display_name {
            body["displayName"] = json!(name);
        }
        if let Some(expiry) = expiration {
            body["expirationDateTime"] = json!(expiry);
        }
        if let Some(password) = password {
            body["password"] = json!(password);
        }
        let response = self.guest_request(
            target,
            &["createLink"],
            Method::POST,
            Some(body),
            &[StatusCode::OK],
            Some(generation),
        )?;
        let link = parse_public_link(single_permission(&response)?)?;
        if password.is_some() && link.password_protected == Some(false) {
            // Never present an explicitly unprotected result as a protected
            // link. Revoke only a demonstrably new, non-inherited grant from
            // this create response; preserve any pre-existing grant identity.
            if !link.inherited
                && !before
                    .public_links
                    .iter()
                    .any(|existing| existing.permission_id == link.permission_id)
            {
                let _ = self.revoke_public_link(target, &link.permission_id);
            }
            return Err(invalid(
                "server did not confirm the requested link password protection; refresh shares",
            ));
        }
        if link.link_type != link_type
            || link.inherited
            || display_name.is_some_and(|name| link.display_name.as_deref() != Some(name))
        {
            return Err(invalid("created link response did not match the request"));
        }
        Ok(link)
    }

    /// Revoke a public link only after a fresh item permission read confirms
    /// its link facet. No public URL is sent back to the server.
    pub fn revoke_public_link(
        &self,
        target: &GuestShareTarget,
        permission_id: &str,
    ) -> Result<(), CloudError> {
        let generation = self.require_target_generation(target)?;
        validate_segment(permission_id)?;
        let current = self.ordinary_sharing_permissions(target)?;
        if !current
            .public_links
            .iter()
            .any(|link| link.permission_id == permission_id && !link.inherited)
        {
            return Err(invalid("permission is not a current public link"));
        }
        self.guest_request(
            target,
            &[permission_id],
            Method::DELETE,
            None,
            &[StatusCode::NO_CONTENT],
            Some(generation),
        )?;
        Ok(())
    }

    fn require_target_generation(&self, target: &GuestShareTarget) -> Result<u64, CloudError> {
        if !std::sync::Arc::ptr_eq(&self.token_generation, &target.client_generation)
            || self.token_generation() != target.generation
        {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "sharing target belongs to a different or expired account session",
            ));
        }
        Ok(target.generation)
    }

    fn verify_ordinary_recipient(
        &self,
        generation: u64,
        kind: OrdinaryRecipientKind,
        id: &str,
    ) -> Result<(), CloudError> {
        let resource = match kind {
            OrdinaryRecipientKind::User => "users",
            OrdinaryRecipientKind::Group => "groups",
        };
        let mut url = self
            .server
            .join(&format!("graph/v1.0/{resource}/"))
            .map_err(|_| invalid("recipient endpoint is invalid"))?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| invalid("recipient endpoint is invalid"))?;
            segments.pop_if_empty();
            segments.push(id);
        }
        if !same_origin(&self.server, &url) {
            return Err(invalid("recipient endpoint left the configured origin"));
        }
        let (request, token) = self.request_with_context(
            Method::GET,
            &url,
            Some(RangeReadContext {
                deadline: guest_deadline(),
                token_generation: generation,
            }),
        )?;
        let response = request
            .header("Accept", "application/json")
            .send()
            .map_err(network)?;
        let mut response = checked(response, &[StatusCode::OK], &token)?;
        let bytes = read_bounded(&mut response, METADATA_LIMIT)?;
        let document: Value = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("recipient response is invalid JSON"))?;
        if string(&document, "id") != Some(id) {
            return Err(invalid("server recipient identity did not match"));
        }
        if kind == OrdinaryRecipientKind::User
            && let Some(user_type) = string(&document, "@libre.graph.userType")
            && user_type != "Member"
        {
            return Err(invalid("recipient is not an ordinary server user"));
        }
        Ok(())
    }

    fn fetch_sharing_capabilities(
        &self,
        generation: u64,
    ) -> Result<SharingCapabilities, CloudError> {
        let url = self
            .server
            .join("ocs/v1.php/cloud/capabilities?format=json")
            .map_err(|_| unsupported_capabilities("capabilities endpoint is invalid"))?;
        if !same_origin(&self.server, &url) {
            return Err(unsupported_capabilities(
                "capabilities endpoint left the configured origin",
            ));
        }
        let (request, token) = self.request_with_context(
            Method::GET,
            &url,
            Some(RangeReadContext {
                deadline: guest_deadline(),
                token_generation: generation,
            }),
        )?;
        let response = request
            .header("Accept", "application/json")
            .header("OCS-APIREQUEST", "true")
            .send()
            .map_err(network)?;
        let mut response = checked(response, &[StatusCode::OK], &token)?;
        let bytes = read_bounded(&mut response, METADATA_LIMIT)?;
        let document: Value = serde_json::from_slice(&bytes)
            .map_err(|_| unsupported_capabilities("capabilities response is malformed"))?;
        parse_sharing_capabilities(&document)
    }

    fn fetch_guest_sharing_capabilities(
        &self,
        generation: u64,
    ) -> Result<GuestSharingCapabilities, CloudError> {
        let url = self
            .server
            .join("ocs/v1.php/cloud/capabilities?format=json")
            .map_err(|_| invalid("capabilities endpoint is invalid"))?;
        if !same_origin(&self.server, &url) {
            return Err(invalid("capabilities endpoint left the configured origin"));
        }
        let (request, token) = self.request_with_context(
            Method::GET,
            &url,
            Some(RangeReadContext {
                deadline: guest_deadline(),
                token_generation: generation,
            }),
        )?;
        let response = request
            .header("Accept", "application/json")
            .header("OCS-APIREQUEST", "true")
            .send()
            .map_err(network)?;
        let mut response = checked(response, &[StatusCode::OK], &token)?;
        let bytes = read_bounded(&mut response, METADATA_LIMIT)?;
        let document: Value = serde_json::from_slice(&bytes)
            .map_err(|_| unsupported_capabilities("capabilities response is malformed"))?;
        parse_guest_sharing_capabilities(&document)
    }

    fn guest_permissions_at_generation(
        &self,
        target: &GuestShareTarget,
        generation: Option<u64>,
    ) -> Result<GuestPermissions, CloudError> {
        let generation = generation.unwrap_or(target.generation);
        if !std::sync::Arc::ptr_eq(&self.token_generation, &target.client_generation)
            || self.token_generation() != target.generation
        {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "guest target belongs to a different or expired account session",
            ));
        }
        let capabilities = self.fetch_guest_sharing_capabilities(generation)?;
        if !capabilities.files_sharing_enabled || !capabilities.guest_links_enabled {
            return Err(unsupported_capabilities(
                "server guest invitation capabilities are unavailable",
            ));
        }
        let data = self.guest_request(
            target,
            &[],
            Method::GET,
            None,
            &[StatusCode::OK],
            Some(generation),
        )?;
        parse_permission_list(&data)
    }

    /// Explicitly send one invitation after refreshing the server's current roles.
    pub fn invite_guest(
        &self,
        target: &GuestShareTarget,
        email: &str,
        role_id: &str,
        expiration: Option<&str>,
    ) -> Result<GuestPermission, CloudError> {
        let generation = self
            .token_generation
            .load(std::sync::atomic::Ordering::Acquire);
        validate_email(email)?;
        validate_requested_expiry(expiration)?;
        let current = self.guest_permissions_at_generation(target, Some(generation))?;
        require_role(role_id, &current.roles)?;
        let mut body = json!({"roles":[role_id], "recipients":[{"email":email}]});
        if let Some(expiry) = expiration {
            body["expirationDateTime"] = json!(expiry);
        }
        let data = self.guest_request(
            target,
            &["invite"],
            Method::POST,
            Some(body),
            &[StatusCode::OK],
            Some(generation),
        )?;
        // Invitation responses must still contain exactly one returned permission.
        let rows = collection(&data, false)?;
        if rows.len() != 1 {
            return Err(invalid(
                "invitation response did not contain one permission",
            ));
        }
        parse_guest(rows[0], &current.roles)?
            .filter(|p| !p.inherited && p.roles == [role_id] && p.email.eq_ignore_ascii_case(email))
            .ok_or_else(|| invalid("invitation response was not a matching guest"))
    }

    /// Change a known guest's role and expiry; `None` explicitly clears expiry.
    pub fn update_guest(
        &self,
        target: &GuestShareTarget,
        permission_id: &str,
        role_id: &str,
        expiration: Option<&str>,
    ) -> Result<GuestPermission, CloudError> {
        let generation = self
            .token_generation
            .load(std::sync::atomic::Ordering::Acquire);
        validate_segment(permission_id)?;
        validate_requested_expiry(expiration)?;
        let current = self.guest_permissions_at_generation(target, Some(generation))?;
        if !current
            .guests
            .iter()
            .any(|p| p.id == permission_id && !p.inherited)
        {
            return Err(invalid("permission is not a current guest"));
        }
        require_role(role_id, &current.roles)?;
        let data = self.guest_request(
            target,
            &[permission_id],
            Method::PATCH,
            Some(json!({"roles":[role_id], "expirationDateTime":expiration})),
            &[StatusCode::OK],
            Some(generation),
        )?;
        parse_guest(&data, &current.roles)?
            .filter(|p| !p.inherited && p.id == permission_id && p.roles == [role_id])
            .ok_or_else(|| invalid("updated permission response did not match the guest"))
    }

    /// Revoke a permission only after a fresh read confirms it is a guest.
    pub fn revoke_guest(
        &self,
        target: &GuestShareTarget,
        permission_id: &str,
    ) -> Result<(), CloudError> {
        let generation = self
            .token_generation
            .load(std::sync::atomic::Ordering::Acquire);
        validate_segment(permission_id)?;
        let current = self.guest_permissions_at_generation(target, Some(generation))?;
        if !current
            .guests
            .iter()
            .any(|p| p.id == permission_id && !p.inherited)
        {
            return Err(invalid("permission is not a current guest"));
        }
        self.guest_request(
            target,
            &[permission_id],
            Method::DELETE,
            None,
            &[StatusCode::NO_CONTENT],
            Some(generation),
        )?;
        Ok(())
    }

    fn guest_request(
        &self,
        target: &GuestShareTarget,
        suffix: &[&str],
        method: Method,
        body: Option<Value>,
        statuses: &[StatusCode],
        generation: Option<u64>,
    ) -> Result<Value, CloudError> {
        if !std::sync::Arc::ptr_eq(&self.token_generation, &target.client_generation)
            || self.token_generation() != target.generation
        {
            return Err(invalid(
                "guest target belongs to a different or expired account session",
            ));
        }
        if target.is_space_root || target.encrypted {
            return Err(invalid(
                "guest invitations are unavailable for Space roots or encrypted content",
            ));
        }
        validate_segment(&target.drive_id)?;
        validate_segment(&target.item_id)?;
        let mut url = self
            .server
            .join("graph/v1beta1/drives/")
            .map_err(|_| invalid("Graph endpoint is invalid"))?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| invalid("Graph endpoint is invalid"))?;
            segments.pop_if_empty();
            segments.extend([target.drive_id.as_str(), "items", target.item_id.as_str()]);
            if matches!(suffix.first(), Some(&"invite" | &"createLink")) {
                segments.push(suffix[0]);
            } else {
                segments.push("permissions");
                segments.extend(suffix.iter().copied());
            }
        }
        if !same_origin(&self.server, &url) {
            return Err(invalid("Graph endpoint left the configured origin"));
        }
        let (mut request, token) =
            if let Some(token_generation) = generation.or(Some(target.generation)) {
                self.request_with_context(
                    method.clone(),
                    &url,
                    Some(RangeReadContext {
                        deadline: guest_deadline(),
                        token_generation,
                    }),
                )?
            } else {
                self.request(method.clone(), &url)?
            };
        request = request.header("Accept", "application/json");
        if let Some(payload) = body {
            request = request.json(&payload);
        }
        let response = request.send().map_err(network)?;
        let mut response = checked(response, statuses, &token)?;
        if method == Method::DELETE {
            return Ok(Value::Null);
        }
        let bytes = read_bounded(&mut response, METADATA_LIMIT)?;
        serde_json::from_slice(&bytes)
            .map_err(|_| invalid("guest permission response is invalid JSON"))
    }
}

fn guest_deadline() -> Instant {
    let local = Instant::now() + Duration::from_secs(15);
    super::ACTIVE_RANGE_CONTEXT.with(|active| {
        active
            .get()
            .map_or(local, |context| context.deadline.min(local))
    })
}

fn validate_segment(s: &str) -> Result<(), CloudError> {
    if s.is_empty()
        || s.len() > MAX_ID
        || s == "."
        || s == ".."
        || s.contains('/')
        || s.contains('\\')
        || s.chars().any(char::is_control)
    {
        return Err(invalid("Graph identifier is invalid"));
    }
    Ok(())
}

fn unsupported_capabilities(message: &str) -> CloudError {
    CloudError::new(ErrorKind::Unsupported, message)
}

fn parse_guest_sharing_capabilities(
    document: &Value,
) -> Result<GuestSharingCapabilities, CloudError> {
    let ocs = document
        .get("ocs")
        .and_then(Value::as_object)
        .ok_or_else(|| unsupported_capabilities("capabilities response omitted OCS data"))?;
    if let Some(meta) = ocs.get("meta") {
        let code = meta
            .get("statuscode")
            .and_then(Value::as_i64)
            .ok_or_else(|| unsupported_capabilities("capabilities status is malformed"))?;
        if code == 403 {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "server denied capability discovery",
            ));
        }
        if !matches!(code, 100 | 200) {
            return Err(unsupported_capabilities(
                "server capability discovery is unavailable",
            ));
        }
    }
    let capabilities = ocs
        .get("data")
        .and_then(|v| v.get("capabilities"))
        .ok_or_else(|| unsupported_capabilities("capabilities data is missing"))?;
    let sharing = capabilities
        .get("files_sharing")
        .ok_or_else(|| unsupported_capabilities("files_sharing capabilities are missing"))?;
    let files_sharing_enabled = sharing
        .get("api_enabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| unsupported_capabilities("files_sharing api_enabled flag is malformed"))?;
    let guest_links_enabled = sharing
        .get("guest_links")
        .and_then(|v| v.get("enabled"))
        .and_then(Value::as_bool)
        .ok_or_else(|| unsupported_capabilities("guest_links enabled flag is malformed"))?;
    Ok(GuestSharingCapabilities {
        files_sharing_enabled,
        guest_links_enabled,
    })
}

fn parse_sharing_capabilities(document: &Value) -> Result<SharingCapabilities, CloudError> {
    let ocs = document
        .get("ocs")
        .and_then(Value::as_object)
        .ok_or_else(|| unsupported_capabilities("capabilities response omitted OCS data"))?;
    if let Some(meta) = ocs.get("meta") {
        let code = meta
            .get("statuscode")
            .and_then(Value::as_i64)
            .ok_or_else(|| unsupported_capabilities("capabilities status is malformed"))?;
        if code == 403 {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "server denied capability discovery",
            ));
        }
        if !matches!(code, 100 | 200) {
            return Err(unsupported_capabilities(
                "server capability discovery is unavailable",
            ));
        }
    }
    let sharing = ocs
        .get("data")
        .and_then(|v| v.get("capabilities"))
        .and_then(|v| v.get("files_sharing"))
        .ok_or_else(|| unsupported_capabilities("files_sharing capabilities are missing"))?;
    let exact_bool = |value: Option<&Value>, key: &str| {
        value.and_then(Value::as_bool).ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                format!("{key} capability is missing or malformed"),
            )
        })
    };
    let public = sharing.get("public");
    let optional_flag = |value: Option<&Value>, key: &str| -> Result<Option<bool>, CloudError> {
        match value {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Bool(value)) => Ok(Some(*value)),
            _ => Err(CloudError::new(
                ErrorKind::Unsupported,
                format!("{key} capability is malformed"),
            )),
        }
    };
    let files_sharing_enabled =
        exact_bool(sharing.get("api_enabled"), "files_sharing.api_enabled")?;
    let groups_enabled = exact_bool(sharing.get("group_sharing"), "files_sharing.group_sharing")?;
    let public_links_enabled = exact_bool(
        public.and_then(|v| v.get("enabled")),
        "files_sharing.public.enabled",
    )?;
    let public_password_enforced = optional_flag(
        public
            .and_then(|v| v.get("password"))
            .and_then(|v| v.get("enforced")),
        "files_sharing.public.password.enforced",
    )?;
    let public_expiration_enabled = optional_flag(
        public
            .and_then(|v| v.get("expire_date"))
            .and_then(|v| v.get("enabled")),
        "files_sharing.public.expire_date.enabled",
    )?;
    let public_expiration_enforced = optional_flag(
        public
            .and_then(|v| v.get("expire_date"))
            .and_then(|v| v.get("enforced")),
        "files_sharing.public.expire_date.enforced",
    )?;
    let public_password_required_for = password_requirements(
        public_password_enforced,
        public
            .and_then(|value| value.get("password"))
            .and_then(|value| value.get("enforced_for")),
    );
    Ok(SharingCapabilities {
        files_sharing_enabled,
        groups_enabled,
        public_links_enabled,
        public_link_creation_supported: files_sharing_enabled
            && public_links_enabled
            && public_password_required_for.is_some()
            && public_expiration_policy_known(
                public_expiration_enabled,
                public_expiration_enforced,
            ),
        public_password_enforced,
        public_password_required_for,
        public_expiration_enabled,
        public_expiration_enforced,
        public_upload_enabled: optional_flag(
            public.and_then(|v| v.get("upload")),
            "files_sharing.public.upload",
        )?,
        public_upload_only_enabled: optional_flag(
            public.and_then(|v| v.get("supports_upload_only")),
            "files_sharing.public.supports_upload_only",
        )?,
    })
}

// OpenCloud 9 emits the global flag independently of its per-role requirements.
// A write link is conservatively password-protected if any write category
// requires it; this cannot weaken a folder/file-specific server policy.
fn password_requirements(global: Option<bool>, categories: Option<&Value>) -> Option<Vec<String>> {
    let global = global?;
    let (read, write) = match categories {
        None => (global, global),
        Some(Value::Object(values)) => {
            let keys = [
                "read_only",
                "read_write",
                "read_write_delete",
                "upload_only",
            ];
            if values.len() != keys.len()
                || keys
                    .iter()
                    .any(|key| !values.get(*key).is_some_and(Value::is_boolean))
            {
                return None;
            }
            (
                global || values["read_only"].as_bool()?,
                global || keys[1..].iter().any(|key| values[*key] == true),
            )
        }
        _ => return None,
    };
    let mut required = Vec::new();
    if read {
        required.push("view".into());
        required.push("blocksDownload".into());
    }
    if write {
        required.extend(["edit".into(), "upload".into(), "createOnly".into()]);
    }
    Some(required)
}

fn validate_link_type(link_type: &str) -> Result<(), CloudError> {
    if matches!(
        link_type,
        "view" | "upload" | "edit" | "createOnly" | "blocksDownload"
    ) {
        Ok(())
    } else {
        Err(invalid("public link type is not supported by Graph"))
    }
}

fn validate_display_name(name: Option<&str>) -> Result<(), CloudError> {
    if name.is_some_and(|value| {
        value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
    }) {
        Err(invalid("sharing display name is invalid"))
    } else {
        Ok(())
    }
}

fn single_permission(response: &Value) -> Result<&Value, CloudError> {
    match response {
        Value::Object(object) if object.contains_key("id") => Ok(response),
        Value::Object(_) => {
            let rows = collection(response, false)?;
            if rows.len() == 1 {
                Ok(rows[0])
            } else {
                Err(invalid("sharing response did not contain one permission"))
            }
        }
        _ => Err(invalid("sharing response did not contain a permission")),
    }
}

fn identity_set(row: &Value) -> Option<&Value> {
    let granted = row.get("grantedToV2")?;
    match granted {
        Value::Array(values) if values.len() == 1 => values.first(),
        Value::Object(_) => Some(granted),
        _ => None,
    }
}

fn permission_roles(row: &Value, roles: &[GuestRole]) -> Result<Vec<String>, CloudError> {
    let Some(value) = row.get("roles") else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| invalid("server returned invalid sharing roles"))?;
    if values.len() > MAX_ROLES {
        return Err(invalid("server returned too many sharing roles"));
    }
    values
        .iter()
        .map(|value| {
            let id = value
                .as_str()
                .ok_or_else(|| invalid("server returned invalid sharing roles"))?;
            if !roles.iter().any(|role| role.id == id) {
                return Err(invalid("server returned an unknown sharing role"));
            }
            Ok(id.to_owned())
        })
        .collect()
}

fn optional_expiry(row: &Value) -> Result<Option<String>, CloudError> {
    match row.get("expirationDateTime") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            validate_expiry(Some(value))?;
            Ok(Some(value.clone()))
        }
        _ => Err(invalid("server returned invalid sharing expiry")),
    }
}

fn public_expiration_policy_known(enabled: Option<bool>, enforced: Option<bool>) -> bool {
    match (enabled, enforced) {
        (Some(false), Some(true)) | (None, _) => false,
        (Some(false), _) => true,
        (Some(true), Some(_)) => true,
        (Some(true), None) => false,
    }
}

fn permission_inherited(row: &Value) -> Result<bool, CloudError> {
    match row.get("inheritedFrom") {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Object(_)) => Ok(true),
        _ => Err(invalid(
            "server returned invalid permission source metadata",
        )),
    }
}

fn parse_ordinary_share(
    row: &Value,
    roles: &[GuestRole],
) -> Result<Option<OrdinaryShare>, CloudError> {
    if row.get("link").is_some() {
        return Ok(None);
    }
    let Some(identity) = identity_set(row) else {
        return Ok(None);
    };
    let (kind, principal) = if let Some(user) = identity.get("user") {
        (OrdinaryRecipientKind::User, user)
    } else if let Some(group) = identity.get("group") {
        (OrdinaryRecipientKind::Group, group)
    } else {
        return Ok(None);
    };
    if kind == OrdinaryRecipientKind::User
        && string(principal, "@libre.graph.userType") == Some("Guest")
    {
        return Ok(None);
    }
    let permission_id =
        string(row, "id").ok_or_else(|| invalid("server returned invalid sharing metadata"))?;
    let recipient_id = string(principal, "id")
        .ok_or_else(|| invalid("server returned invalid sharing recipient"))?;
    validate_segment(permission_id)?;
    validate_segment(recipient_id)?;
    let display_name = match principal.get("displayName") {
        None | Some(Value::Null) => None,
        Some(Value::String(value))
            if value.len() <= 512 && !value.chars().any(char::is_control) =>
        {
            Some(value.clone())
        }
        _ => return Err(invalid("server returned invalid sharing recipient")),
    };
    Ok(Some(OrdinaryShare {
        permission_id: permission_id.into(),
        recipient_kind: kind,
        recipient_id: recipient_id.into(),
        display_name,
        roles: permission_roles(row, roles)?,
        expiration_date_time: optional_expiry(row)?,
        inherited: permission_inherited(row)?,
    }))
}

fn parse_public_link(row: &Value) -> Result<PublicShareLink, CloudError> {
    let link = row
        .get("link")
        .ok_or_else(|| invalid("server response did not contain a public link"))?;
    let permission_id =
        string(row, "id").ok_or_else(|| invalid("server returned invalid link metadata"))?;
    let link_type =
        string(link, "type").ok_or_else(|| invalid("server returned invalid link metadata"))?;
    validate_segment(permission_id)?;
    validate_link_type(link_type)?;
    // LibreGraph names its response extension differently from createLink's
    // displayName input. Accept the legacy response alias only when it does
    // not conflict with the canonical field.
    let name = match (
        link.get("@libre.graph.displayName"),
        link.get("displayName"),
    ) {
        (Some(canonical), Some(legacy)) if canonical != legacy => {
            return Err(invalid("server returned conflicting link names"));
        }
        (Some(canonical), _) => Some(canonical),
        (None, legacy) => legacy,
    };
    let display_name = match name {
        None | Some(Value::Null) => None,
        Some(Value::String(value))
            if value.len() <= 256 && !value.chars().any(char::is_control) =>
        {
            Some(value.clone())
        }
        _ => return Err(invalid("server returned invalid link name")),
    };
    let web_url = match link.get("webUrl") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if value.len() <= 8_192 => {
            let parsed = reqwest::Url::parse(value)
                .map_err(|_| invalid("server returned invalid link URL"))?;
            if !matches!(parsed.scheme(), "https" | "http")
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.host_str().is_none()
            {
                return Err(invalid("server returned invalid link URL"));
            }
            Some(value.clone())
        }
        _ => return Err(invalid("server returned invalid link URL")),
    };
    Ok(PublicShareLink {
        permission_id: permission_id.into(),
        link_type: link_type.into(),
        display_name,
        web_url,
        expiration_date_time: optional_expiry(row)?,
        inherited: permission_inherited(row)?,
        password_protected: match row.get("hasPassword") {
            None | Some(Value::Null) => None,
            Some(Value::Bool(value)) => Some(*value),
            _ => {
                return Err(invalid(
                    "server returned invalid password-protection metadata",
                ));
            }
        },
    })
}

fn parse_recipient(
    row: &Value,
    kind: OrdinaryRecipientKind,
) -> Result<OrdinaryRecipient, CloudError> {
    let id =
        string(row, "id").ok_or_else(|| invalid("server returned invalid recipient metadata"))?;
    let display_name = string(row, "displayName")
        .ok_or_else(|| invalid("server returned invalid recipient metadata"))?;
    validate_segment(id)?;
    if display_name.is_empty()
        || display_name.len() > 512
        || display_name.chars().any(char::is_control)
    {
        return Err(invalid("server returned invalid recipient metadata"));
    }
    let mail = match row.get("mail") {
        None | Some(Value::Null) => None,
        Some(Value::String(value))
            if value.len() <= 254 && !value.chars().any(char::is_control) =>
        {
            Some(value.clone())
        }
        _ => return Err(invalid("server returned invalid recipient metadata")),
    };
    Ok(OrdinaryRecipient {
        id: id.into(),
        kind,
        display_name: display_name.into(),
        mail,
    })
}

fn parse_ordinary_permissions(data: &Value) -> Result<OrdinarySharingPermissions, CloudError> {
    let roles = parse_roles(data)?;
    let rows = collection(data, true)?;
    let mut people_and_groups = Vec::new();
    let mut public_links = Vec::new();
    for row in rows {
        if row.get("link").is_some() {
            public_links.push(parse_public_link(row)?);
        } else if let Some(share) = parse_ordinary_share(row, &roles)? {
            people_and_groups.push(share);
        }
    }
    let ids = people_and_groups
        .iter()
        .map(|v| &v.permission_id)
        .chain(public_links.iter().map(|v| &v.permission_id))
        .collect::<std::collections::HashSet<_>>();
    if ids.len() != people_and_groups.len() + public_links.len() {
        return Err(invalid("server returned duplicate sharing permission IDs"));
    }
    Ok(OrdinarySharingPermissions {
        roles,
        people_and_groups,
        public_links,
    })
}

fn validate_email(s: &str) -> Result<(), CloudError> {
    let (local, domain) = s
        .split_once('@')
        .ok_or_else(|| invalid("guest email is invalid"))?;
    if s.len() > 254
        || local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || domain.len() > 255
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+/=?^_`{|}~-".contains(&b))
        || !valid_guest_domain(domain)
    {
        return Err(invalid("guest email is invalid"));
    }
    Ok(())
}
fn valid_guest_domain(domain: &str) -> bool {
    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}
fn validate_expiry(s: Option<&str>) -> Result<(), CloudError> {
    if let Some(s) = s {
        if s.len() > 64 || chrono_free_rfc3339(s).is_none() {
            return Err(invalid("guest expiry is invalid"));
        }
    }
    Ok(())
}
fn validate_requested_expiry(s: Option<&str>) -> Result<(), CloudError> {
    validate_expiry(s)?;
    if let Some(s) = s {
        let expiry = chrono_free_rfc3339(s).ok_or_else(|| invalid("guest expiry is invalid"))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| invalid("system clock is invalid"))?
            .as_secs() as i64;
        if expiry <= now {
            return Err(invalid("requested expiry must be in the future"));
        }
    }
    Ok(())
}
fn chrono_free_rfc3339(s: &str) -> Option<i64> {
    let (date, time_zone) = s.split_once('T')?;
    let date = date.as_bytes();
    if date.len() != 10 || date[4] != b'-' || date[7] != b'-' {
        return None;
    }
    let y = std::str::from_utf8(&date[..4]).ok()?.parse::<u16>().ok()?;
    let m = std::str::from_utf8(&date[5..7]).ok()?.parse::<u8>().ok()?;
    let day = std::str::from_utf8(&date[8..10]).ok()?.parse::<u8>().ok()?;
    if y == 0 || !(1..=12).contains(&m) {
        return None;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > days[(m - 1) as usize] {
        return None;
    }
    let (time, zone) = if let Some(t) = time_zone.strip_suffix('Z') {
        (t, "Z")
    } else {
        let i = time_zone.rfind(['+', '-'])?;
        (&time_zone[..i], &time_zone[i..])
    };
    let offset_seconds = if zone == "Z" {
        0_i64
    } else {
        let signless = &zone[1..];
        if signless.len() != 5 || signless.as_bytes()[2] != b':' {
            return None;
        }
        let mut z = signless.split(':');
        let (zh, zm) = (z.next()?.parse::<u8>().ok()?, z.next()?.parse::<u8>().ok()?);
        if z.next().is_some() || zh > 23 || zm > 59 {
            return None;
        }
        let magnitude = i64::from(zh) * 3_600 + i64::from(zm) * 60;
        if zone.starts_with('-') {
            -magnitude
        } else {
            magnitude
        }
    };
    let time = time.as_bytes();
    if time.len() < 8 || time[2] != b':' || time[5] != b':' {
        return None;
    }
    let h = std::str::from_utf8(&time[..2]).ok()?.parse::<u8>().ok()?;
    let mi = std::str::from_utf8(&time[3..5]).ok()?.parse::<u8>().ok()?;
    let sec = std::str::from_utf8(&time[6..]).ok()?;
    let (whole, fraction) = sec.split_once('.').unwrap_or((sec, ""));
    let second = whole.parse::<u8>().ok()?;
    if whole.len() != 2
        || h > 23
        || mi > 59
        || second > 59
        || (!fraction.is_empty()
            && (!fraction.bytes().all(|b| b.is_ascii_digit()) || fraction.len() > 9))
        || sec.contains('.') && fraction.is_empty()
    {
        return None;
    }
    let year = i64::from(y) - if m <= 2 { 1 } else { 0 };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = i64::from(m) + if m > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days_since_epoch = era * 146_097 + day_of_era - 719_468;
    let local_seconds =
        days_since_epoch * 86_400 + i64::from(h) * 3_600 + i64::from(mi) * 60 + i64::from(second);
    Some(local_seconds - offset_seconds)
}
fn string<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key)?.as_str()
}
fn collection(v: &Value, absent_means_empty: bool) -> Result<Vec<&Value>, CloudError> {
    if v.get("@odata.nextLink").is_some() {
        return Err(invalid(
            "paginated Graph collection exceeds this request's scope",
        ));
    }
    let rows = match v.get("value") {
        Some(Value::Array(rows)) => rows,
        None if absent_means_empty => return Ok(Vec::new()),
        _ => return Err(invalid("guest permission response has invalid value")),
    };
    if rows.len() > MAX_PERMISSIONS {
        return Err(invalid("guest permission list exceeds its limit"));
    }
    Ok(rows.iter().collect())
}
fn parse_permission_list(data: &Value) -> Result<GuestPermissions, CloudError> {
    // Validate server role metadata before treating an omitted collection as empty.
    let roles = parse_roles(data)?;
    let rows = collection(data, true)?;
    let guests = rows
        .iter()
        .filter_map(|row| parse_guest(row, &roles).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    if guests.len()
        != guests
            .iter()
            .map(|p| &p.id)
            .collect::<std::collections::HashSet<_>>()
            .len()
    {
        return Err(invalid("guest permission metadata contains duplicate IDs"));
    }
    Ok(GuestPermissions { guests, roles })
}
fn parse_roles(v: &Value) -> Result<Vec<GuestRole>, CloudError> {
    let rows = v
        .get("@libre.graph.permissions.roles.allowedValues")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("server omitted allowed guest roles"))?;
    if rows.len() > MAX_ROLES {
        return Err(invalid("server returned too many guest roles"));
    }
    let roles = rows
        .iter()
        .map(|r| {
            let id =
                string(r, "id").ok_or_else(|| invalid("server returned invalid role metadata"))?;
            let name = string(r, "displayName")
                .ok_or_else(|| invalid("server returned invalid role metadata"))?;
            validate_segment(id)?;
            if !valid_role_id(id) {
                return Err(invalid("server returned invalid role metadata"));
            }
            if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
                return Err(invalid("server returned invalid role metadata"));
            }
            Ok(GuestRole {
                id: id.into(),
                name: name.into(),
            })
        })
        .collect::<Result<Vec<_>, CloudError>>()?;
    if roles
        .iter()
        .map(|r| &r.id)
        .collect::<std::collections::HashSet<_>>()
        .len()
        != roles.len()
    {
        return Err(invalid("server returned duplicate guest roles"));
    }
    Ok(roles)
}
fn valid_role_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}
fn parse_guest(row: &Value, roles: &[GuestRole]) -> Result<Option<GuestPermission>, CloudError> {
    if row.get("link").is_some() {
        return Ok(None);
    }
    let Some(user) = row.get("grantedToV2").and_then(|v| v.get("user")) else {
        return Ok(None);
    };
    if string(user, "@libre.graph.userType") != Some("Guest") {
        return Ok(None);
    }
    let id = string(row, "id").ok_or_else(|| invalid("server returned invalid guest metadata"))?;
    validate_segment(id)?;
    let email =
        string(user, "id").ok_or_else(|| invalid("server returned invalid guest metadata"))?;
    validate_email(email)?;
    let values = row
        .get("roles")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("server returned invalid guest metadata"))?;
    if values.is_empty() || values.len() > MAX_ROLES {
        return Err(invalid("server returned invalid guest metadata"));
    }
    let guest_roles = values
        .iter()
        .map(|v| {
            let id = v
                .as_str()
                .ok_or_else(|| invalid("server returned invalid guest metadata"))?;
            if !roles.iter().any(|r| r.id == id) {
                return Err(invalid("server returned an unknown guest role"));
            }
            Ok(id.to_owned())
        })
        .collect::<Result<Vec<_>, CloudError>>()?;
    let expiry = match row.get("expirationDateTime") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => {
            validate_expiry(Some(s))?;
            Some(s.clone())
        }
        _ => return Err(invalid("server returned invalid guest expiry")),
    };
    Ok(Some(GuestPermission {
        id: id.into(),
        email: email.into(),
        roles: guest_roles,
        expiration_date_time: expiry,
        inherited: permission_inherited(row)?,
    }))
}
fn require_role(id: &str, roles: &[GuestRole]) -> Result<(), CloudError> {
    if roles.iter().any(|r| r.id == id) {
        Ok(())
    } else {
        Err(invalid(
            "requested role is not currently allowed by the server",
        ))
    }
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
    fn targets_cannot_cross_accounts_or_survive_auth_rotation() {
        let client = OpenCloudClient::new("https://cloud.example/", "synthetic".into()).unwrap();
        let other =
            OpenCloudClient::new("https://cloud.example/", "synthetic-other".into()).unwrap();
        let target = GuestShareTarget::new(&client, "drive", "item").unwrap();
        assert!(
            other
                .guest_permissions(&target)
                .unwrap_err()
                .message
                .contains("account session")
        );
        client.set_bearer_token("new-synthetic".into()).unwrap();
        assert!(
            client
                .guest_permissions(&target)
                .unwrap_err()
                .message
                .contains("account session")
        );
    }
    #[test]
    fn parses_only_explicit_guest_rows_and_allowed_roles() {
        let data = json!({"@libre.graph.permissions.roles.allowedValues":[{"id":"00000000-0000-0000-0000-000000000001","displayName":"Viewer"}],"value":[
            {"id":"guest-1","roles":["00000000-0000-0000-0000-000000000001"],"grantedToV2":{"user":{"@libre.graph.userType":"Guest","id":"g@example.org"}}},
            {"id":"group-1","roles":["00000000-0000-0000-0000-000000000001"],"grantedToV2":{"group":{"id":"g"}}},
            {"id":"link-1","roles":["00000000-0000-0000-0000-000000000001"],"link":{"type":"view"}}]});
        let roles = parse_roles(&data).unwrap();
        let rows = collection(&data, false).unwrap();
        assert_eq!(
            parse_guest(rows[0], &roles).unwrap().unwrap().email,
            "g@example.org"
        );
        assert!(parse_guest(rows[1], &roles).unwrap().is_none());
        assert!(parse_guest(rows[2], &roles).unwrap().is_none());
    }

    #[test]
    fn empty_folder_and_file_permission_fixtures_may_omit_value() {
        // Source-derived shapes from OpenCloud v9.0.0 listPermissions.feature;
        // role IDs are the tagged server's UUIDs, not synthetic aliases.
        let folder: Value = serde_json::from_str(
            r#"{"@libre.graph.permissions.actions.allowedValues":["libre.graph/driveItem/permissions/read"],"@libre.graph.permissions.roles.allowedValues":[{"id":"b1e2218d-eef8-4d4c-b82d-0f1a1b48f3b5","displayName":"Viewer","description":"View and download.","@libre.graph.weight":1},{"id":"fb6c3e19-e378-47e5-b277-9732f9de6e21","displayName":"Editor","description":"View, download, upload, edit, add and delete.","@libre.graph.weight":2}]}"#,
        ).unwrap();
        let file: Value = serde_json::from_str(
            r#"{"@libre.graph.permissions.actions.allowedValues":["libre.graph/driveItem/permissions/read"],"@libre.graph.permissions.roles.allowedValues":[{"id":"b1e2218d-eef8-4d4c-b82d-0f1a1b48f3b5","displayName":"Viewer","description":"View and download.","@libre.graph.weight":1},{"id":"3d00ce52-1fc2-4dbc-8b95-a73b73395f5a","displayName":"File Editor","description":"View, download and edit.","@libre.graph.weight":2}]}"#,
        ).unwrap();
        for fixture in [&folder, &file] {
            let result = parse_permission_list(fixture).unwrap();
            assert!(result.guests.is_empty());
            assert!(!result.roles.is_empty());
        }
    }

    #[test]
    fn absent_value_is_list_only_and_requires_valid_roles() {
        let valid_roles = json!({
            "@libre.graph.permissions.roles.allowedValues":[
                {"id":"b1e2218d-eef8-4d4c-b82d-0f1a1b48f3b5","displayName":"Viewer"}
            ]
        });
        assert!(collection(&valid_roles, true).unwrap().is_empty());
        let explicit_null = json!({
            "@libre.graph.permissions.roles.allowedValues":[
                {"id":"b1e2218d-eef8-4d4c-b82d-0f1a1b48f3b5","displayName":"Viewer"}
            ],
            "value":null
        });
        assert!(collection(&explicit_null, true).is_err());
        let malformed_roles = json!({"value":null});
        assert!(parse_permission_list(&malformed_roles).is_err());
        assert!(collection(&valid_roles, false).is_err());
    }
    #[test]
    fn rejects_bad_target_email_expiry_and_unlisted_role() {
        let client = OpenCloudClient::new("https://cloud.example/", "synthetic".into()).unwrap();
        assert!(GuestShareTarget::new(&client, "drive/../escape", "item").is_err());
        assert!(validate_email(" bad@example.org").is_err());
        assert!(validate_email("a..b@example.org").is_err());
        assert!(validate_email("a@bad-.example.org").is_err());
        assert!(validate_expiry(Some("tomorrow")).is_err());
        assert!(validate_expiry(Some("2026-2-29T00:00:00Z")).is_err());
        assert!(validate_expiry(Some("2026-02-28T0:00:00Z")).is_err());
        assert!(validate_expiry(Some("2000-01-01T00:00:00Z")).is_ok());
        assert!(validate_requested_expiry(Some("2000-01-01T00:00:00Z")).is_err());
        assert!(validate_requested_expiry(Some("2099-01-01T00:00:00Z")).is_ok());
        assert!(
            require_role(
                "writer",
                &[GuestRole {
                    id: "viewer".into(),
                    name: "Viewer".into()
                }]
            )
            .is_err()
        );
    }

    #[test]
    fn capability_flags_require_exact_booleans_and_ignore_version_heuristics() {
        let enabled: Value = serde_json::from_str(CAPABILITIES).unwrap();
        assert_eq!(
            parse_guest_sharing_capabilities(&enabled).unwrap(),
            GuestSharingCapabilities {
                files_sharing_enabled: true,
                guest_links_enabled: true
            }
        );
        let missing = json!({"ocs":{"data":{"version":{"string":"9.0.0"},"capabilities":{"files_sharing":{"api_enabled":true}}}}});
        assert_eq!(
            parse_guest_sharing_capabilities(&missing).unwrap_err().kind,
            ErrorKind::Unsupported
        );
        let string_true = json!({"ocs":{"data":{"version":{"string":"9.0.0"},"capabilities":{"files_sharing":{"api_enabled":true,"guest_links":{"enabled":"true"}}}}}});
        assert_eq!(
            parse_guest_sharing_capabilities(&string_true)
                .unwrap_err()
                .kind,
            ErrorKind::Unsupported
        );
        let disabled: Value = serde_json::from_str(CAPABILITIES_DISABLED).unwrap();
        assert!(
            !parse_guest_sharing_capabilities(&disabled)
                .unwrap()
                .guest_links_enabled
        );
        let sharing_disabled = json!({"ocs":{"data":{"capabilities":{"files_sharing":{"api_enabled":false,"guest_links":{"enabled":true}}}}}});
        let sharing_disabled = parse_guest_sharing_capabilities(&sharing_disabled).unwrap();
        assert!(!sharing_disabled.files_sharing_enabled);
        assert!(sharing_disabled.guest_links_enabled);
        let malformed_api = json!({"ocs":{"data":{"capabilities":{"files_sharing":{"api_enabled":"true","guest_links":{"enabled":true}}}}}});
        assert_eq!(
            parse_guest_sharing_capabilities(&malformed_api)
                .unwrap_err()
                .kind,
            ErrorKind::Unsupported
        );
        let malformed = json!({"ocs":{"meta":{"statuscode":"200"},"data":{"capabilities":{}}}});
        assert_eq!(
            parse_guest_sharing_capabilities(&malformed)
                .unwrap_err()
                .kind,
            ErrorKind::Unsupported
        );
        let denied = json!({"ocs":{"meta":{"statuscode":403},"data":{"capabilities":{}}}});
        assert_eq!(
            parse_guest_sharing_capabilities(&denied).unwrap_err().kind,
            ErrorKind::Forbidden
        );
    }

    fn read_request(stream: &mut std::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut one = [0_u8; 1];
        while !bytes.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut one).unwrap();
            bytes.push(one[0]);
            assert!(bytes.len() < 16_384);
        }
        let header = String::from_utf8(bytes).unwrap();
        let len = header
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|n| n.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        let mut body = vec![0; len];
        stream.read_exact(&mut body).unwrap();
        format!("{header}{}", String::from_utf8(body).unwrap())
    }
    fn respond(stream: &mut std::net::TcpStream, code: &str, body: &str) {
        write!(stream,"HTTP/1.1 {code}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
    }
    const ROLES: &str = r#"{"@libre.graph.permissions.roles.allowedValues":[{"id":"00000000-0000-0000-0000-000000000001","displayName":"Viewer"}],"value":[]}"#;
    const CAPABILITIES: &str = r#"{"ocs":{"meta":{"statuscode":200},"data":{"version":{"string":"0.1.0"},"productname":"OpenCloud 9","capabilities":{"files_sharing":{"api_enabled":true,"guest_links":{"enabled":true}}}}}}"#;
    const CAPABILITIES_DISABLED: &str = r#"{"ocs":{"meta":{"statuscode":200},"data":{"version":{"string":"9.0.0"},"capabilities":{"files_sharing":{"api_enabled":true,"guest_links":{"enabled":false}}}}}}"#;
    const GUEST: &str = r#"{"id":"guest-1","roles":["00000000-0000-0000-0000-000000000001"],"grantedToV2":{"user":{"@libre.graph.userType":"Guest","id":"guest@example.org"}}}"#;

    #[test]
    fn invite_uses_graph_invite_route_after_fresh_role_read() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let first = read_request(&mut s);
            assert!(first.starts_with("GET /ocs/v1.php/cloud/capabilities?format=json HTTP/1.1"));
            assert!(first.to_ascii_lowercase().contains("ocs-apirequest: true"));
            respond(&mut s, "200 OK", CAPABILITIES);
            let (mut s, _) = listener.accept().unwrap();
            let first = read_request(&mut s);
            assert!(
                first
                    .starts_with("GET /graph/v1beta1/drives/drive/items/item/permissions HTTP/1.1")
            );
            respond(&mut s, "200 OK", ROLES);
            let (mut s, _) = listener.accept().unwrap();
            let second = read_request(&mut s);
            assert!(
                second.starts_with("POST /graph/v1beta1/drives/drive/items/item/invite HTTP/1.1")
            );
            assert!(second.contains("\"email\":\"guest@example.org\""));
            respond(&mut s, "200 OK", &format!("{{\"value\":[{GUEST}]}}"));
        });
        let client = OpenCloudClient::new_with_proxy(
            &format!("http://{addr}/"),
            "synthetic-token".into(),
            &super::super::ProxyConfig::Direct,
        )
        .unwrap();
        let target = GuestShareTarget::new(&client, "drive", "item").unwrap();
        let result = client
            .invite_guest(
                &target,
                "guest@example.org",
                "00000000-0000-0000-0000-000000000001",
                None,
            )
            .unwrap();
        assert_eq!(result.id, "guest-1");
        worker.join().unwrap();
    }

    #[test]
    fn invalid_role_and_non_guest_revoke_do_not_send_mutation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let request = read_request(&mut s);
            assert!(request.starts_with("GET /ocs/v1.php/cloud/capabilities?format=json HTTP/1.1"));
            respond(&mut s, "200 OK", CAPABILITIES);
            let (mut s, _) = listener.accept().unwrap();
            let request = read_request(&mut s);
            assert!(
                request
                    .starts_with("GET /graph/v1beta1/drives/drive/items/item/permissions HTTP/1.1")
            );
            respond(&mut s, "200 OK", ROLES);
            let (mut s, _) = listener.accept().unwrap();
            let request = read_request(&mut s);
            assert!(request.starts_with("GET /ocs/v1.php/cloud/capabilities?format=json HTTP/1.1"));
            respond(&mut s, "200 OK", CAPABILITIES);
            let (mut s, _) = listener.accept().unwrap();
            let request = read_request(&mut s);
            assert!(
                request
                    .starts_with("GET /graph/v1beta1/drives/drive/items/item/permissions HTTP/1.1")
            );
            let data = r#"{"@libre.graph.permissions.roles.allowedValues":[{"id":"00000000-0000-0000-0000-000000000001","displayName":"Viewer"}],"value":[{"id":"non-guest","roles":["00000000-0000-0000-0000-000000000001"],"grantedToV2":{"group":{"id":"group"}}}]}"#;
            respond(&mut s, "200 OK", data);
        });
        let client = OpenCloudClient::new_with_proxy(
            &format!("http://{addr}/"),
            "synthetic-token".into(),
            &super::super::ProxyConfig::Direct,
        )
        .unwrap();
        let target = GuestShareTarget::new(&client, "drive", "item").unwrap();
        assert!(
            client
                .invite_guest(&target, "g@example.org", "not-allowed", None)
                .is_err()
        );
        assert!(client.revoke_guest(&target, "non-guest").is_err());
        worker.join().unwrap();
    }

    #[test]
    fn disabled_guest_capability_stops_before_permission_read_or_post() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            assert!(request.starts_with("GET /ocs/v1.php/cloud/capabilities?format=json HTTP/1.1"));
            respond(&mut stream, "200 OK", CAPABILITIES_DISABLED);
        });
        let client = OpenCloudClient::new_with_proxy(
            &format!("http://{addr}/"),
            "synthetic-token".into(),
            &super::super::ProxyConfig::Direct,
        )
        .unwrap();
        let target = GuestShareTarget::new(&client, "drive", "item").unwrap();
        let error = client
            .invite_guest(
                &target,
                "guest@example.org",
                "00000000-0000-0000-0000-000000000001",
                None,
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unsupported);
        worker.join().unwrap();
    }

    const SHARING_CAPABILITIES: &str = r#"{"ocs":{"meta":{"statuscode":200},"data":{"version":{"string":"0.1.0"},"capabilities":{"files_sharing":{"api_enabled":true,"group_sharing":true,"public":{"enabled":true,"upload":true,"supports_upload_only":true,"password":{"enforced":false},"expire_date":{"enabled":false}}}}}}}"#;
    const ORDINARY_ROWS: &str = r#"{"@libre.graph.permissions.roles.allowedValues":[{"id":"00000000-0000-0000-0000-000000000001","displayName":"Viewer"},{"id":"00000000-0000-0000-0000-000000000002","displayName":"Editor"}],"value":[{"id":"person-1","roles":["00000000-0000-0000-0000-000000000001"],"grantedToV2":[{"user":{"id":"user-1","displayName":"Ada"}}]},{"id":"link-1","link":{"type":"view","displayName":"Trip","webUrl":"https://cloud.example/s/synthetic"}}]}"#;

    #[test]
    fn ordinary_permission_parser_splits_group_user_and_link_facets() {
        let data: Value = serde_json::from_str(ORDINARY_ROWS).unwrap();
        let parsed = parse_ordinary_permissions(&data).unwrap();
        assert_eq!(parsed.people_and_groups.len(), 1);
        assert_eq!(
            parsed.people_and_groups[0].recipient_kind,
            OrdinaryRecipientKind::User
        );
        assert_eq!(parsed.people_and_groups[0].recipient_id, "user-1");
        assert_eq!(parsed.public_links.len(), 1);
        assert_eq!(parsed.public_links[0].link_type, "view");
        assert!(!format!("{:?}", parsed.public_links[0]).contains("synthetic"));
        assert!(
            parse_sharing_capabilities(&serde_json::from_str(SHARING_CAPABILITIES).unwrap())
                .unwrap()
                .public_links_enabled
        );
    }

    #[test]
    fn public_link_names_accept_canonical_and_legacy_fields_without_ambiguity() {
        let base = json!({"id":"link-1","hasPassword":true,"link":{"type":"view"}});
        for fields in [
            json!({"@libre.graph.displayName":"Trip"}),
            json!({"displayName":"Trip"}),
            json!({"@libre.graph.displayName":"Trip","displayName":"Trip"}),
        ] {
            let mut row = base.clone();
            row["link"]
                .as_object_mut()
                .unwrap()
                .extend(fields.as_object().unwrap().clone());
            let link = parse_public_link(&row).unwrap();
            assert_eq!(link.display_name.as_deref(), Some("Trip"));
            assert_eq!(link.password_protected, Some(true));
        }
        for fields in [
            json!({"@libre.graph.displayName":"Trip","displayName":"Other"}),
            json!({"@libre.graph.displayName":null,"displayName":"Trip"}),
            json!({"@libre.graph.displayName":false}),
            json!({"@libre.graph.displayName":"x".repeat(257)}),
            json!({"@libre.graph.displayName":"bad\nname"}),
        ] {
            let mut row = base.clone();
            row["link"]
                .as_object_mut()
                .unwrap()
                .extend(fields.as_object().unwrap().clone());
            assert!(parse_public_link(&row).is_err());
        }
    }

    #[test]
    fn inherited_permissions_are_visible_but_marked_read_only() {
        let mut data: Value = serde_json::from_str(ORDINARY_ROWS).unwrap();
        data["value"][0]["inheritedFrom"] = json!({"driveId":"parent-drive","id":"parent-item"});
        data["value"][1]["inheritedFrom"] = json!({"driveId":"parent-drive","id":"parent-item"});
        let parsed = parse_ordinary_permissions(&data).unwrap();
        assert!(parsed.people_and_groups[0].inherited);
        assert!(parsed.public_links[0].inherited);
        data["value"][0]["inheritedFrom"] = json!("unknown");
        assert!(parse_ordinary_permissions(&data).is_err());
    }

    #[test]
    fn inherited_grants_cannot_be_revoked() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(&mut stream, "200 OK", SHARING_CAPABILITIES);
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            assert!(
                request
                    .starts_with("GET /graph/v1beta1/drives/drive/items/item/permissions HTTP/1.1")
            );
            let mut data: Value = serde_json::from_str(ORDINARY_ROWS).unwrap();
            data["value"][0]["inheritedFrom"] =
                json!({"driveId":"parent-drive","id":"parent-item"});
            respond(&mut stream, "200 OK", &data.to_string());
        });
        let client = OpenCloudClient::new_with_proxy(
            &format!("http://{addr}/"),
            "synthetic-token".into(),
            &super::super::ProxyConfig::Direct,
        )
        .unwrap();
        let target = GuestShareTarget::new(&client, "drive", "item").unwrap();
        assert!(client.revoke_ordinary(&target, "person-1").is_err());
        worker.join().unwrap();
    }

    #[test]
    fn ordinary_capabilities_fail_closed_for_missing_or_malformed_flags() {
        for document in [
            json!({"ocs":{"data":{"capabilities":{"files_sharing":{"api_enabled":true,"group_sharing":true}}}}}),
            json!({"ocs":{"data":{"capabilities":{"files_sharing":{"api_enabled":"true","group_sharing":true,"public":{"enabled":true}}}}}}),
            json!({"ocs":{"data":{"capabilities":{"files_sharing":{"api_enabled":true,"group_sharing":true,"public":{"enabled":"true"}}}}}}),
            json!({"ocs":{"data":{"capabilities":{"files_sharing":{"api_enabled":true,"public":{"enabled":true}}}}}}),
        ] {
            assert_eq!(
                parse_sharing_capabilities(&document).unwrap_err().kind,
                ErrorKind::Unsupported
            );
        }
        let disabled = json!({"ocs":{"data":{"capabilities":{"files_sharing":{"api_enabled":true,"group_sharing":false,"public":{"enabled":false}}}}}});
        let caps = parse_sharing_capabilities(&disabled).unwrap();
        assert!(!caps.groups_enabled && !caps.public_links_enabled);
    }

    #[test]
    fn disabled_expiry_with_omitted_enforcement_allows_non_expiring_links() {
        let capabilities: Value = serde_json::from_str(SHARING_CAPABILITIES).unwrap();
        let parsed = parse_sharing_capabilities(&capabilities).unwrap();
        assert!(parsed.public_link_creation_supported);
        assert_eq!(parsed.public_expiration_enabled, Some(false));
        assert_eq!(parsed.public_expiration_enforced, None);
        assert!(!public_expiration_policy_known(Some(true), None));
        assert!(!public_expiration_policy_known(Some(false), Some(true)));

        let missing_expiry_enabled = json!({"ocs":{"data":{"capabilities":{"files_sharing":{"api_enabled":true,"group_sharing":true,"public":{"enabled":true,"password":{"enforced":false},"expire_date":{"enforced":false}}}}}}});
        assert!(
            !parse_sharing_capabilities(&missing_expiry_enabled)
                .unwrap()
                .public_link_creation_supported
        );
    }

    #[test]
    fn role_specific_password_enforcement_overrides_false_global_flag() {
        let mut doc: Value = serde_json::from_str(SHARING_CAPABILITIES).unwrap();
        doc["ocs"]["data"]["capabilities"]["files_sharing"]["public"]["password"]["enforced_for"] =
            json!({"read_only":true,"read_write":true,"read_write_delete":true,"upload_only":true});
        let caps = parse_sharing_capabilities(&doc).unwrap();
        assert_eq!(caps.public_password_enforced, Some(false));
        assert!(caps.public_link_creation_supported);
        let required = caps.public_password_required_for.unwrap();
        assert!(
            ["view", "edit", "upload", "createOnly"]
                .iter()
                .all(|kind| required.iter().any(|value| value == kind))
        );
        doc["ocs"]["data"]["capabilities"]["files_sharing"]["public"]["password"]["enforced_for"]
            ["read_only"] = json!("true");
        let caps = parse_sharing_capabilities(&doc).unwrap();
        assert!(!caps.public_link_creation_supported);
        assert!(caps.public_password_required_for.is_none());
        assert!(password_requirements(Some(false), Some(&json!({"read_only":true}))).is_none());
        assert!(password_requirements(None, None).is_none());
        assert!(password_requirements(Some(false), Some(&Value::Null)).is_none());
    }

    #[test]
    fn protected_public_link_sends_password_only_in_create_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut caps: Value = serde_json::from_str(SHARING_CAPABILITIES).unwrap();
            caps["ocs"]["data"]["capabilities"]["files_sharing"]["public"]["password"]["enforced_for"] = json!({"read_only":true,"read_write":true,"read_write_delete":true,"upload_only":true});
            let caps_text = caps.to_string();
            for path in [
                "/ocs/v1.php/cloud/capabilities?format=json",
                "/graph/v1beta1/drives/drive/items/item/permissions",
                "/ocs/v1.php/cloud/capabilities?format=json",
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_request(&mut stream);
                assert!(request.starts_with(&format!("GET {path} HTTP/1.1")));
                assert!(!request.contains("synthetic-link-secret"));
                respond(
                    &mut stream,
                    "200 OK",
                    if path.starts_with("/ocs/") {
                        &caps_text
                    } else {
                        ORDINARY_ROWS
                    },
                );
            }
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            assert!(
                request
                    .starts_with("POST /graph/v1beta1/drives/drive/items/item/createLink HTTP/1.1")
            );
            let body: Value =
                serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(
                body,
                json!({"type":"view","displayName":"Trip","password":"synthetic-link-secret"})
            );
            respond(
                &mut stream,
                "200 OK",
                r#"{"id":"protected-link","hasPassword":true,"link":{"type":"view","@libre.graph.displayName":"Trip","webUrl":"https://cloud.example/s/protected"}}"#,
            );
        });
        let client = OpenCloudClient::new_with_proxy(
            &format!("http://{addr}/"),
            "synthetic-token".into(),
            &super::super::ProxyConfig::Direct,
        )
        .unwrap();
        let target = GuestShareTarget::new(&client, "drive", "item").unwrap();
        let link = client
            .create_public_link_with_password(
                &target,
                "view",
                Some("Trip"),
                None,
                Some("synthetic-link-secret"),
            )
            .unwrap();
        assert_eq!(link.password_protected, Some(true));
        assert_eq!(link.display_name.as_deref(), Some("Trip"));
        assert!(!format!("{link:?}").contains("synthetic-link-secret"));
        worker.join().unwrap();
    }

    #[test]
    fn explicitly_unprotected_create_result_revokes_only_the_new_grant() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            for path in [
                "/ocs/v1.php/cloud/capabilities?format=json",
                "/graph/v1beta1/drives/drive/items/item/permissions",
                "/ocs/v1.php/cloud/capabilities?format=json",
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                assert!(read_request(&mut stream).starts_with(&format!("GET {path} HTTP/1.1")));
                respond(
                    &mut stream,
                    "200 OK",
                    if path.starts_with("/ocs/") {
                        SHARING_CAPABILITIES
                    } else {
                        ORDINARY_ROWS
                    },
                );
            }
            let (mut stream, _) = listener.accept().unwrap();
            assert!(
                read_request(&mut stream)
                    .starts_with("POST /graph/v1beta1/drives/drive/items/item/createLink HTTP/1.1")
            );
            respond(
                &mut stream,
                "200 OK",
                r#"{"id":"new-unprotected-link","hasPassword":false,"link":{"type":"view","displayName":"Trip","webUrl":"https://cloud.example/s/unprotected"}}"#,
            );
            let (mut stream, _) = listener.accept().unwrap();
            assert!(
                read_request(&mut stream)
                    .starts_with("GET /ocs/v1.php/cloud/capabilities?format=json HTTP/1.1")
            );
            respond(&mut stream, "200 OK", SHARING_CAPABILITIES);
            let (mut stream, _) = listener.accept().unwrap();
            assert!(
                read_request(&mut stream)
                    .starts_with("GET /graph/v1beta1/drives/drive/items/item/permissions HTTP/1.1")
            );
            respond(
                &mut stream,
                "200 OK",
                &ORDINARY_ROWS.replace("link-1", "new-unprotected-link"),
            );
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            assert!(request.starts_with("DELETE /graph/v1beta1/drives/drive/items/item/permissions/new-unprotected-link HTTP/1.1"));
            assert!(!request.contains("synthetic-link-secret"));
            respond(&mut stream, "204 No Content", "");
        });
        let client = OpenCloudClient::new_with_proxy(
            &format!("http://{addr}/"),
            "synthetic-token".into(),
            &super::super::ProxyConfig::Direct,
        )
        .unwrap();
        let target = GuestShareTarget::new(&client, "drive", "item").unwrap();
        let error = client
            .create_public_link_with_password(
                &target,
                "view",
                Some("Trip"),
                None,
                Some("synthetic-link-secret"),
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidResponse);
        assert!(!error.message.contains("synthetic-link-secret"));
        worker.join().unwrap();
    }

    #[test]
    fn graph_ordinary_and_link_routes_are_item_scoped_and_validated() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let cap = |s: &mut std::net::TcpStream| {
                let request = read_request(s);
                assert!(
                    request.starts_with("GET /ocs/v1.php/cloud/capabilities?format=json HTTP/1.1")
                );
                respond(s, "200 OK", SHARING_CAPABILITIES);
            };
            let permissions = |s: &mut std::net::TcpStream, body: &str| {
                let request = read_request(s);
                assert!(request.starts_with(
                    "GET /graph/v1beta1/drives/drive/items/item/permissions HTTP/1.1"
                ));
                respond(s, "200 OK", body);
            };
            let (mut s, _) = listener.accept().unwrap();
            cap(&mut s);
            let (mut s, _) = listener.accept().unwrap();
            permissions(&mut s, ORDINARY_ROWS);
            let (mut s, _) = listener.accept().unwrap();
            cap(&mut s);
            let (mut s, _) = listener.accept().unwrap();
            permissions(&mut s, ORDINARY_ROWS);
            let (mut s, _) = listener.accept().unwrap();
            cap(&mut s);
            let (mut s, _) = listener.accept().unwrap();
            let request = read_request(&mut s);
            assert!(
                request
                    .starts_with("POST /graph/v1beta1/drives/drive/items/item/createLink HTTP/1.1"),
                "unexpected createLink request: {request}"
            );
            assert!(request.contains("\"type\":\"view\""));
            assert!(!request.contains("expirationDateTime"));
            respond(
                &mut s,
                "200 OK",
                r#"{"id":"new-link","link":{"type":"view","displayName":"Trip","webUrl":"https://cloud.example/s/new"}}"#,
            );
            let (mut s, _) = listener.accept().unwrap();
            cap(&mut s);
            let (mut s, _) = listener.accept().unwrap();
            permissions(&mut s, ORDINARY_ROWS);
            let (mut s, _) = listener.accept().unwrap();
            let request = read_request(&mut s);
            assert!(request.starts_with(
                "PATCH /graph/v1beta1/drives/drive/items/item/permissions/person-1 HTTP/1.1"
            ));
            assert!(request.contains("\"roles\":[\"00000000-0000-0000-0000-000000000002\"]"));
            respond(
                &mut s,
                "200 OK",
                r#"{"id":"person-1","roles":["00000000-0000-0000-0000-000000000002"],"grantedToV2":[{"user":{"id":"user-1","displayName":"Ada"}}]}"#,
            );
            let (mut s, _) = listener.accept().unwrap();
            cap(&mut s);
            let (mut s, _) = listener.accept().unwrap();
            permissions(&mut s, ORDINARY_ROWS);
            let (mut s, _) = listener.accept().unwrap();
            let request = read_request(&mut s);
            assert!(request.starts_with(
                "DELETE /graph/v1beta1/drives/drive/items/item/permissions/link-1 HTTP/1.1"
            ));
            respond(&mut s, "204 No Content", "");
        });
        let client = OpenCloudClient::new_with_proxy(
            &format!("http://{addr}/"),
            "synthetic-token".into(),
            &super::super::ProxyConfig::Direct,
        )
        .unwrap();
        let target = GuestShareTarget::new(&client, "drive", "item").unwrap();
        let listed = client.ordinary_sharing_permissions(&target).unwrap();
        assert_eq!(listed.people_and_groups.len(), 1);
        let link = client
            .create_public_link(&target, "view", Some("Trip"), None)
            .unwrap();
        assert_eq!(link.permission_id, "new-link");
        let updated = client
            .update_ordinary_role(&target, "person-1", "00000000-0000-0000-0000-000000000002")
            .unwrap();
        assert_eq!(updated.roles, ["00000000-0000-0000-0000-000000000002"]);
        client.revoke_public_link(&target, "link-1").unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn disabled_public_link_capability_prevents_create_post() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let request = read_request(&mut s);
            assert!(request.starts_with("GET /ocs/v1.php/cloud/capabilities?format=json HTTP/1.1"));
            respond(&mut s, "200 OK", SHARING_CAPABILITIES);
            let (mut s, _) = listener.accept().unwrap();
            let request = read_request(&mut s);
            assert!(
                request
                    .starts_with("GET /graph/v1beta1/drives/drive/items/item/permissions HTTP/1.1")
            );
            respond(&mut s, "200 OK", ORDINARY_ROWS);
            let (mut s, _) = listener.accept().unwrap();
            let request = read_request(&mut s);
            assert!(request.starts_with("GET /ocs/v1.php/cloud/capabilities?format=json HTTP/1.1"));
            let disabled = SHARING_CAPABILITIES.replace("\"enabled\":true", "\"enabled\":false");
            respond(&mut s, "200 OK", &disabled);
        });
        let client = OpenCloudClient::new_with_proxy(
            &format!("http://{addr}/"),
            "synthetic-token".into(),
            &super::super::ProxyConfig::Direct,
        )
        .unwrap();
        let target = GuestShareTarget::new(&client, "drive", "item").unwrap();
        assert_eq!(
            client
                .create_public_link(&target, "view", None, None)
                .unwrap_err()
                .kind,
            ErrorKind::Unsupported
        );
        worker.join().unwrap();
    }

    #[test]
    fn required_public_link_password_stops_before_link_creation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            read_request(&mut s);
            respond(&mut s, "200 OK", SHARING_CAPABILITIES);
            let (mut s, _) = listener.accept().unwrap();
            read_request(&mut s);
            respond(&mut s, "200 OK", ORDINARY_ROWS);
            let (mut s, _) = listener.accept().unwrap();
            read_request(&mut s);
            let enforced = SHARING_CAPABILITIES.replace(
                "\"password\":{\"enforced\":false}",
                "\"password\":{\"enforced\":true}",
            );
            respond(&mut s, "200 OK", &enforced);
        });
        let client = OpenCloudClient::new_with_proxy(
            &format!("http://{addr}/"),
            "synthetic-token".into(),
            &super::super::ProxyConfig::Direct,
        )
        .unwrap();
        let target = GuestShareTarget::new(&client, "drive", "item").unwrap();
        assert_eq!(
            client
                .create_public_link(&target, "view", None, None)
                .unwrap_err()
                .kind,
            ErrorKind::InvalidResponse
        );
        worker.join().unwrap();
    }

    #[test]
    fn ordinary_group_invite_uses_graph_object_id_and_fresh_server_role() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            read_request(&mut s);
            respond(&mut s, "200 OK", SHARING_CAPABILITIES);
            let (mut s, _) = listener.accept().unwrap();
            read_request(&mut s);
            respond(&mut s, "200 OK", ORDINARY_ROWS);
            let (mut s, _) = listener.accept().unwrap();
            let capabilities = read_request(&mut s);
            assert!(
                capabilities.starts_with("GET /ocs/v1.php/cloud/capabilities?format=json HTTP/1.1"),
                "unexpected group-capability request line: {}",
                capabilities
                    .lines()
                    .next()
                    .unwrap_or("<missing request line>")
            );
            respond(&mut s, "200 OK", SHARING_CAPABILITIES);
            let (mut s, _) = listener.accept().unwrap();
            let lookup = read_request(&mut s);
            assert!(
                lookup.starts_with("GET /graph/v1.0/groups/group-7 HTTP/1.1"),
                "unexpected group lookup request line: {}",
                lookup.lines().next().unwrap_or("<missing request line>")
            );
            respond(
                &mut s,
                "200 OK",
                r#"{"id":"group-7","displayName":"Editors"}"#,
            );
            let (mut s, _) = listener.accept().unwrap();
            let request = read_request(&mut s);
            assert!(
                request.starts_with("POST /graph/v1beta1/drives/drive/items/item/invite HTTP/1.1")
            );
            assert!(request.contains("\"@libre.graph.recipient.type\":\"group\""));
            assert!(request.contains("\"objectId\":\"group-7\""));
            assert!(request.contains("\"roles\":[\"00000000-0000-0000-0000-000000000001\"]"));
            respond(
                &mut s,
                "200 OK",
                r#"{"value":[{"id":"group-grant","roles":["00000000-0000-0000-0000-000000000001"],"grantedToV2":[{"group":{"id":"group-7","displayName":"Editors"}}]}]}"#,
            );
        });
        let client = OpenCloudClient::new_with_proxy(
            &format!("http://{addr}/"),
            "synthetic-token".into(),
            &super::super::ProxyConfig::Direct,
        )
        .unwrap();
        let target = GuestShareTarget::new(&client, "drive", "item").unwrap();
        let granted = client
            .invite_ordinary(
                &target,
                OrdinaryRecipientKind::Group,
                "group-7",
                "00000000-0000-0000-0000-000000000001",
                None,
            )
            .unwrap();
        assert_eq!(granted.recipient_id, "group-7");
        worker.join().unwrap();
    }

    #[test]
    fn ordinary_member_user_invite_checks_server_identity_and_posts_server_role() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            read_request(&mut s);
            respond(&mut s, "200 OK", SHARING_CAPABILITIES);
            let (mut s, _) = listener.accept().unwrap();
            read_request(&mut s);
            respond(&mut s, "200 OK", ORDINARY_ROWS);
            let (mut s, _) = listener.accept().unwrap();
            let lookup = read_request(&mut s);
            assert!(lookup.starts_with("GET /graph/v1.0/users/member-7 HTTP/1.1"));
            respond(
                &mut s,
                "200 OK",
                r#"{"id":"member-7","displayName":"Ada Lovelace","@libre.graph.userType":"Member"}"#,
            );
            let (mut s, _) = listener.accept().unwrap();
            let request = read_request(&mut s);
            assert!(
                request.starts_with("POST /graph/v1beta1/drives/drive/items/item/invite HTTP/1.1")
            );
            assert!(request.contains("\"@libre.graph.recipient.type\":\"user\""));
            assert!(request.contains("\"objectId\":\"member-7\""));
            assert!(request.contains("\"roles\":[\"00000000-0000-0000-0000-000000000001\"]"));
            respond(
                &mut s,
                "200 OK",
                r#"{"value":[{"id":"member-grant","roles":["00000000-0000-0000-0000-000000000001"],"grantedToV2":[{"user":{"id":"member-7","displayName":"Ada Lovelace"}}]}]}"#,
            );
        });
        let client = OpenCloudClient::new_with_proxy(
            &format!("http://{addr}/"),
            "synthetic-token".into(),
            &super::super::ProxyConfig::Direct,
        )
        .unwrap();
        let target = GuestShareTarget::new(&client, "drive", "item").unwrap();
        let granted = client
            .invite_ordinary(
                &target,
                OrdinaryRecipientKind::User,
                "member-7",
                "00000000-0000-0000-0000-000000000001",
                None,
            )
            .unwrap();
        assert_eq!(granted.permission_id, "member-grant");
        assert_eq!(granted.recipient_kind, OrdinaryRecipientKind::User);
        assert_eq!(granted.recipient_id, "member-7");
        worker.join().unwrap();
    }

    #[test]
    fn ordinary_user_invite_rejects_guest_identity_before_mutation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            read_request(&mut s);
            respond(&mut s, "200 OK", SHARING_CAPABILITIES);
            let (mut s, _) = listener.accept().unwrap();
            read_request(&mut s);
            respond(&mut s, "200 OK", ORDINARY_ROWS);
            let (mut s, _) = listener.accept().unwrap();
            let lookup = read_request(&mut s);
            assert!(lookup.starts_with("GET /graph/v1.0/users/guest-id HTTP/1.1"));
            respond(
                &mut s,
                "200 OK",
                r#"{"id":"guest-id","displayName":"Guest","@libre.graph.userType":"Guest"}"#,
            );
        });
        let client = OpenCloudClient::new_with_proxy(
            &format!("http://{addr}/"),
            "synthetic-token".into(),
            &super::super::ProxyConfig::Direct,
        )
        .unwrap();
        let target = GuestShareTarget::new(&client, "drive", "item").unwrap();
        assert!(
            client
                .invite_ordinary(
                    &target,
                    OrdinaryRecipientKind::User,
                    "guest-id",
                    "00000000-0000-0000-0000-000000000001",
                    None,
                )
                .is_err()
        );
        worker.join().unwrap();
    }

    #[test]
    fn explicit_recipient_lookup_uses_bounded_graph_directory_route() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            read_request(&mut s);
            respond(&mut s, "200 OK", SHARING_CAPABILITIES);
            let (mut s, _) = listener.accept().unwrap();
            let request = read_request(&mut s);
            assert!(request.starts_with("GET /graph/v1.0/users HTTP/1.1"));
            respond(
                &mut s,
                "200 OK",
                r#"{"value":[{"id":"user-1","displayName":"Ada Lovelace","mail":"ada@example.org"},{"id":"user-2","displayName":"Grace Hopper"}]}"#,
            );
        });
        let client = OpenCloudClient::new_with_proxy(
            &format!("http://{addr}/"),
            "synthetic-token".into(),
            &super::super::ProxyConfig::Direct,
        )
        .unwrap();
        let matches = client
            .search_ordinary_recipients("ada@", OrdinaryRecipientKind::User)
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, "user-1");
        worker.join().unwrap();
    }
}

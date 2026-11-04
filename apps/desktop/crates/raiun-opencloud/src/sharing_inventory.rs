//! Bounded, read-only discovery of incoming and outgoing OpenCloud shares.
//!
//! Incoming Graph shared items and outgoing OCS share grants are different
//! resource types with unrelated identifiers. This module keeps them separate
//! and never treats an OCS grant id as a Graph item or permission id.

use super::{
    OpenCloudClient, RangeContextGuard, RangeReadContext, StatusCode, checked, invalid, network,
    read_bounded, same_origin,
};
use raiun_core::backend::{CloudError, ErrorKind};
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashSet,
    fmt,
    time::{Duration, Instant},
};

const OCS_MAX_BYTES: usize = 4 * 1024 * 1024;
const GRAPH_MAX_PAGE_BYTES: usize = 4 * 1024 * 1024;
const GRAPH_MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_ITEMS: usize = 100_000;
const MAX_PAGES: usize = 1_000;
const MAX_TEXT: usize = 8_192;
const INVENTORY_TIMEOUT: Duration = Duration::from_secs(45);

/// Visible list requested by the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareInventoryCategory {
    SharedWithMe,
    SharedByMe,
    PublicLinks,
}

/// Metadata establishing which account/server snapshot a list belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryScope {
    /// Caller-owned account key, kept separate from every server resource id.
    pub account_id: String,
    pub server_url: String,
    pub token_generation: u64,
    /// True only when the complete server response(s) fit bounds and validate.
    /// This describes the response, not all grants hidden by server policy.
    pub response_complete: bool,
}

/// Complete incoming Graph shared-item inventory. Discovery does not prove
/// that the current account may browse or mutate the target item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IncomingShareInventory {
    pub scope: InventoryScope,
    pub items: Vec<IncomingSharedItem>,
}

/// Complete outgoing OCS grant inventory. The OCS share id is not a Graph id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OwnedShareInventory {
    pub scope: InventoryScope,
    pub category: ShareInventoryCategory,
    pub items: Vec<OwnedShare>,
}

/// Exact OCS state that must still match before a settings update is sent.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedShareBaseline {
    pub ocs_share_id: String,
    pub resource_id: String,
    pub space_id: Option<String>,
    pub owner_id: Option<String>,
    pub kind: OcsShareKind,
    pub recipient_id: Option<String>,
    pub path: Option<String>,
    pub file_target: Option<String>,
    pub item_type: Option<String>,
    pub permissions: Option<u64>,
    pub expires_at: Option<String>,
    pub label: Option<String>,
}

impl fmt::Debug for OwnedShareBaseline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // OpenCloud can use the public URL token as its OCS share ID. The
        // baseline must retain that identity for CAS, but never print it.
        f.debug_struct("OwnedShareBaseline")
            .field("ocs_share_id", &"[redacted]")
            .field("kind", &self.kind)
            .field("permissions", &self.permissions)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnedShareEditableField {
    Access,
    Expiration,
    Name,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedShareAccessChoice {
    pub id: String,
    pub name: String,
    pub permissions: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedShareEditSettings {
    pub scope: InventoryScope,
    pub category: ShareInventoryCategory,
    pub baseline: OwnedShareBaseline,
    pub share: OwnedShare,
    pub editable_fields: Vec<OwnedShareEditableField>,
    pub access_choices: Vec<OwnedShareAccessChoice>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExpirationUpdate {
    Keep,
    Clear,
    Set { value: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnedShareUpdate {
    UserOrGroup {
        permissions: Option<u64>,
        expiration: ExpirationUpdate,
    },
    PublicLink {
        permissions: Option<u64>,
        name: Option<String>,
        expiration: ExpirationUpdate,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnedShareUpdateOutcome {
    Updated,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedShareUpdateResult {
    pub outcome: OwnedShareUpdateOutcome,
    pub settings: Option<OwnedShareEditSettings>,
}

/// Graph `driveItem` returned by `/me/drive/sharedWithMe`.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct IncomingSharedItem {
    /// Graph shared-item/jail identity.
    pub shared_item_id: String,
    pub name: String,
    pub is_folder: bool,
    pub size: Option<u64>,
    pub last_modified_date_time: Option<String>,
    pub hidden: bool,
    /// Current effective action labels, if returned. Not an outgoing grant.
    pub effective_actions: Vec<String>,
    pub parent_reference: Option<ItemParentReference>,
    /// The remote item is the actual shared target, distinct from shared_item_id.
    pub remote_item: SharedRemoteItem,
}

impl fmt::Debug for IncomingSharedItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncomingSharedItem")
            .field("shared_item_id", &self.shared_item_id)
            .field("name", &self.name)
            .field("is_folder", &self.is_folder)
            .field("size", &self.size)
            .field("last_modified_date_time", &self.last_modified_date_time)
            .field("hidden", &self.hidden)
            .field("effective_actions", &self.effective_actions)
            .field("parent_reference", &self.parent_reference)
            .field("remote_item", &self.remote_item)
            .finish()
    }
}

/// Remote Graph target identity and metadata from `remoteItem`.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct SharedRemoteItem {
    pub id: String,
    pub name: Option<String>,
    pub is_folder: bool,
    pub size: Option<u64>,
    pub e_tag: Option<String>,
    pub parent_reference: Option<ItemParentReference>,
    /// A server-provided DAV locator for later validation; not a trusted URL.
    pub web_dav_url: Option<String>,
    pub permissions: Vec<IncomingPermission>,
    pub created_by: Option<IncomingRecipient>,
}

impl fmt::Debug for SharedRemoteItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedRemoteItem")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("is_folder", &self.is_folder)
            .field("size", &self.size)
            .field("e_tag", &self.e_tag)
            .field("parent_reference", &self.parent_reference)
            .field(
                "web_dav_url",
                &self.web_dav_url.as_ref().map(|_| "[redacted]"),
            )
            .field("permissions", &self.permissions)
            .field("created_by", &self.created_by)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ItemParentReference {
    pub drive_id: Option<String>,
    pub item_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IncomingPermission {
    pub id: Option<String>,
    /// Graph role ids; do not map to OCS permission bitmasks.
    pub roles: Vec<String>,
    pub actions: Vec<String>,
    pub granted_to: Option<IncomingRecipient>,
    pub invited_by: Option<IncomingRecipient>,
    pub created_date_time: Option<String>,
    pub expiration_date_time: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IncomingRecipient {
    pub user_id: Option<String>,
    pub user_display_name: Option<String>,
    pub group_id: Option<String>,
    pub group_display_name: Option<String>,
}

/// OCS share type values used by OpenCloud. Other numeric types are retained
/// and remain read-only so a future/server-specific type is not silently lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "code", rename_all = "snake_case")]
pub enum OcsShareKind {
    User,
    Group,
    PublicLink,
    Other(i64),
}

/// An outgoing OCS grant row, preserving OCS resource/Space identities.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedShare {
    /// OCS grant id. It must only be used with the OCS shares API.
    pub ocs_share_id: String,
    pub kind: OcsShareKind,
    pub path: Option<String>,
    pub file_target: Option<String>,
    /// OCS `item_source`/`file_source`; not a Graph drive or permission id.
    pub resource_id: Option<String>,
    /// OCS `space_id`, when provided, kept distinct from `resource_id`.
    pub space_id: Option<String>,
    pub space_alias: Option<String>,
    pub item_type: Option<String>,
    pub mime_type: Option<String>,
    pub permissions: Option<u64>,
    pub state: Option<i64>,
    pub shared_at_epoch_seconds: Option<u64>,
    pub expires_at: Option<String>,
    pub owner_id: Option<String>,
    pub owner_display_name: Option<String>,
    pub recipient_id: Option<String>,
    pub recipient_display_name: Option<String>,
    pub recipient_additional_info: Option<String>,
    pub recipient_user_type: Option<i64>,
    pub label: Option<String>,
    pub hidden: Option<bool>,
    pub quicklink: Option<bool>,
    /// Public-link access URL; held in memory only by callers and redacted in Debug.
    pub public_url: Option<String>,
}

impl fmt::Debug for OwnedShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedShare")
            .field("ocs_share_id", &"[redacted]")
            .field("kind", &self.kind)
            .field("path", &self.path)
            .field("file_target", &self.file_target)
            .field("resource_id", &self.resource_id)
            .field("space_id", &self.space_id)
            .field("space_alias", &self.space_alias)
            .field("item_type", &self.item_type)
            .field("mime_type", &self.mime_type)
            .field("permissions", &self.permissions)
            .field("state", &self.state)
            .field("shared_at_epoch_seconds", &self.shared_at_epoch_seconds)
            .field("expires_at", &self.expires_at)
            .field("owner_id", &self.owner_id)
            .field("owner_display_name", &self.owner_display_name)
            .field("recipient_id", &self.recipient_id)
            .field("recipient_display_name", &self.recipient_display_name)
            .field("recipient_additional_info", &self.recipient_additional_info)
            .field("recipient_user_type", &self.recipient_user_type)
            .field("label", &self.label)
            .field("hidden", &self.hidden)
            .field("quicklink", &self.quicklink)
            .field(
                "public_url",
                &self.public_url.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl OpenCloudClient {
    /// List all incoming shared items using Graph's paged endpoint. Any page,
    /// row, identity or response-bound failure rejects the whole snapshot.
    pub fn list_incoming_shares(
        &self,
        account_id: &str,
    ) -> Result<IncomingShareInventory, CloudError> {
        validate_account_id(account_id)?;
        let context = self.inventory_context()?;
        let _guard = RangeContextGuard::enter(context);
        let initial = append_server_path(
            &self.server,
            &["graph", "v1beta1", "me", "drive", "sharedWithMe"],
        )?;
        let mut next = Some(initial.clone());
        let mut visited = HashSet::new();
        let mut ids = HashSet::new();
        let mut total_bytes = 0usize;
        let mut items = Vec::new();
        while let Some(url) = next {
            if visited.len() >= MAX_PAGES || !visited.insert(url.as_str().to_owned()) {
                return Err(invalid("share inventory pagination is invalid"));
            }
            require_graph_page(&initial, &url)?;
            let bytes = self.get_inventory_page(&url, context, GRAPH_MAX_PAGE_BYTES, false)?;
            total_bytes = total_bytes
                .checked_add(bytes.len())
                .filter(|total| *total <= GRAPH_MAX_TOTAL_BYTES)
                .ok_or_else(|| invalid("share inventory exceeds its size limit"))?;
            let value = parse_json(&bytes)?;
            let page = parse_graph_page(&value)?;
            for row in page.items {
                let item = parse_incoming_item(row, &initial)?;
                if !ids.insert(item.shared_item_id.clone()) || ids.len() > MAX_ITEMS {
                    return Err(invalid(
                        "share inventory contains duplicate or excessive items",
                    ));
                }
                items.push(item);
            }
            next = match page.next_link {
                Some(link) => {
                    let resolved = url
                        .join(&link)
                        .map_err(|_| invalid("share inventory continuation is invalid"))?;
                    require_graph_page(&initial, &resolved)?;
                    Some(resolved)
                }
                None => None,
            };
        }
        self.ensure_inventory_generation(context)?;
        Ok(IncomingShareInventory {
            scope: self.inventory_scope(account_id, context, true),
            items,
        })
    }

    /// List the complete outgoing OCS share set. OpenCloud's current OCS
    /// endpoint returns one unpaged array; the adapter fails closed on size or
    /// row overflow rather than claiming a truncated result is complete.
    pub fn list_owned_shares(
        &self,
        account_id: &str,
        category: ShareInventoryCategory,
    ) -> Result<OwnedShareInventory, CloudError> {
        if category == ShareInventoryCategory::SharedWithMe {
            return Err(invalid("incoming shares use the Graph inventory API"));
        }
        validate_account_id(account_id)?;
        let context = self.inventory_context()?;
        let _guard = RangeContextGuard::enter(context);
        let mut url = append_server_path(
            &self.server,
            &[
                "ocs",
                "v2.php",
                "apps",
                "files_sharing",
                "api",
                "v1",
                "shares",
            ],
        )?;
        url.query_pairs_mut().append_pair("format", "json");
        if category == ShareInventoryCategory::PublicLinks {
            url.query_pairs_mut().append_pair("share_types", "3");
        }
        let bytes = self.get_inventory_page(&url, context, OCS_MAX_BYTES, true)?;
        let response = parse_json(&bytes)?;
        let rows = parse_ocs_data(&response)?;
        if rows.len() > MAX_ITEMS {
            return Err(invalid("share inventory contains too many items"));
        }
        let mut ids = HashSet::new();
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let item = parse_owned_share(row)?;
            if !ids.insert(item.ocs_share_id.clone()) {
                return Err(invalid("share inventory contains duplicate OCS ids"));
            }
            match (category, item.kind) {
                (ShareInventoryCategory::SharedByMe, OcsShareKind::PublicLink) => continue,
                (ShareInventoryCategory::PublicLinks, OcsShareKind::PublicLink) => {}
                (ShareInventoryCategory::PublicLinks, _) => {
                    return Err(invalid(
                        "server returned a non-link in the public-link list",
                    ));
                }
                _ => {}
            }
            items.push(item);
        }
        self.ensure_inventory_generation(context)?;
        Ok(OwnedShareInventory {
            scope: self.inventory_scope(account_id, context, true),
            category,
            items,
        })
    }

    /// Reload settings for one owned OCS grant. The returned baseline is the
    /// exact state callers must present when submitting an edit.
    pub fn get_owned_share_edit_settings(
        &self,
        account_id: &str,
        category: ShareInventoryCategory,
        ocs_share_id: &str,
        expected_resource_id: &str,
    ) -> Result<OwnedShareEditSettings, CloudError> {
        let context = self.guest_sharing_context()?;
        let _operation_guard = RangeContextGuard::enter(context);
        let generation = context.token_generation;
        let row =
            self.fresh_owned_share(account_id, category, ocs_share_id, expected_resource_id)?;
        let settings = self.settings_for_owned_share(account_id, category, row, generation)?;
        if settings.scope.token_generation != generation || self.token_generation() != generation {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        Ok(settings)
    }

    /// Update one account-owned OCS grant after a fresh list and exact baseline
    /// comparison. The operation is sent once; any lost or incomplete response
    /// is reported as unknown and must be resolved by refreshing the inventory.
    pub fn update_owned_share(
        &self,
        account_id: &str,
        category: ShareInventoryCategory,
        ocs_share_id: &str,
        expected_resource_id: &str,
        baseline: &OwnedShareBaseline,
        update: &OwnedShareUpdate,
    ) -> Result<OwnedShareUpdateResult, CloudError> {
        let operation_context = self.guest_sharing_context()?;
        let _operation_guard = RangeContextGuard::enter(operation_context);
        let expected_generation = operation_context.token_generation;
        let row =
            self.fresh_owned_share(account_id, category, ocs_share_id, expected_resource_id)?;
        if self.token_generation() != expected_generation {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        if matches!(row.kind, OcsShareKind::User | OcsShareKind::Group)
            && row.recipient_id.as_deref().is_none_or(str::is_empty)
        {
            return Err(invalid("share recipient identity is unavailable"));
        }
        if baseline_for(&row) != *baseline {
            return Err(invalid("share settings changed; refresh before editing"));
        }

        let capabilities = self.sharing_capabilities()?;
        if !capabilities.files_sharing_enabled {
            return Err(unsupported_capabilities(
                "server file sharing capability is unavailable",
            ));
        }
        let mut form = Vec::<(String, String)>::new();
        match (row.kind, update) {
            (
                OcsShareKind::User | OcsShareKind::Group,
                OwnedShareUpdate::UserOrGroup {
                    permissions,
                    expiration,
                },
            ) => {
                let current = row
                    .permissions
                    .ok_or_else(|| invalid("server omitted current share permissions"))?;
                let selected = (*permissions).unwrap_or(current);
                if permissions.is_some()
                    && !ordinary_permission_choices(row.item_type.as_deref())
                        .iter()
                        .any(|choice| choice.permissions == selected)
                {
                    return Err(invalid("requested share access is unsupported"));
                }
                // The OpenCloud 9 handler always parses permissions, even for
                // expiry-only updates. Sending the fresh value preserves it.
                form.push(("permissions".into(), selected.to_string()));
                append_expiration(&mut form, expiration, false, None)?;
            }
            (
                OcsShareKind::PublicLink,
                OwnedShareUpdate::PublicLink {
                    permissions,
                    name,
                    expiration,
                },
            ) => {
                if !capabilities.public_links_enabled {
                    return Err(unsupported_capabilities(
                        "server public link capability is unavailable",
                    ));
                }
                if capabilities.public_password_required_for.is_none() {
                    return Err(unsupported_capabilities(
                        "public link settings cannot be changed without a known password policy",
                    ));
                }
                if let Some(permission) = permissions {
                    if !public_permission_choices(&row, &capabilities)
                        .iter()
                        .any(|choice| choice.permissions == *permission)
                    {
                        return Err(invalid("requested public link access is unsupported"));
                    }
                    form.push(("permissions".into(), permission.to_string()));
                }
                if let Some(name) = name {
                    if name.is_empty() || name.len() > 256 || has_control(name) {
                        return Err(invalid("public link name is invalid"));
                    }
                    form.push(("name".into(), name.clone()));
                }
                append_expiration(&mut form, expiration, true, Some(&capabilities))?;
            }
            _ => return Err(invalid("share update does not match the grant type")),
        }
        if form.is_empty() {
            return Err(invalid("share update contains no changes"));
        }
        if self.token_generation() != expected_generation {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }

        let context = self.inventory_context()?;
        if context.token_generation != expected_generation {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        let _guard = RangeContextGuard::enter(context);
        let mut url = append_server_path(
            &self.server,
            &[
                "ocs",
                "v2.php",
                "apps",
                "files_sharing",
                "api",
                "v1",
                "shares",
            ],
        )?;
        url.path_segments_mut()
            .map_err(|_| invalid("share URL cannot contain a path"))?
            .push(ocs_share_id);
        url.query_pairs_mut().append_pair("format", "json");
        let (request, token) = self.request_with_context(Method::PUT, &url, Some(context))?;
        let response = request
            .header("Accept", "application/json")
            .header("OCS-APIREQUEST", "true")
            .form(&form)
            .send()
            .map_err(|_| {
                CloudError::new(
                    ErrorKind::Offline,
                    "share update outcome is unknown; refresh before retry",
                )
            })?;
        if response.status().is_server_error() {
            return Err(CloudError::new(
                ErrorKind::Offline,
                "share update outcome is unknown; refresh before retry",
            ));
        }
        let mut response = checked(response, &[StatusCode::OK], &token)?;
        let bytes = read_bounded(&mut response, 64 * 1024).map_err(|_| {
            CloudError::new(
                ErrorKind::InvalidResponse,
                "share update outcome is unknown; refresh before retry",
            )
        })?;
        let envelope = parse_json(&bytes).map_err(|_| {
            CloudError::new(
                ErrorKind::InvalidResponse,
                "share update outcome is unknown; refresh before retry",
            )
        })?;
        match parse_ocs_status(&envelope) {
            Ok(100 | 200) => {}
            _ => {
                return Err(CloudError::new(
                    ErrorKind::InvalidResponse,
                    "share update was not confirmed; refresh before retry",
                ));
            }
        }
        if self.token_generation() != expected_generation {
            return Err(CloudError::new(
                ErrorKind::Offline,
                "share update outcome is unknown after authentication changed; refresh before retry",
            ));
        }
        let fresh = match self.fresh_owned_share(
            account_id,
            category,
            ocs_share_id,
            expected_resource_id,
        ) {
            Ok(fresh) => fresh,
            Err(_) => {
                return Ok(OwnedShareUpdateResult {
                    outcome: OwnedShareUpdateOutcome::Unknown,
                    settings: None,
                });
            }
        };
        let settings =
            match self.settings_for_owned_share(account_id, category, fresh, expected_generation) {
                Ok(settings) => settings,
                Err(_) => {
                    return Ok(OwnedShareUpdateResult {
                        outcome: OwnedShareUpdateOutcome::Unknown,
                        settings: None,
                    });
                }
            };
        if settings.scope.token_generation != expected_generation
            || !updated_state_matches(&settings.share, &row, baseline, &form)
        {
            return Ok(OwnedShareUpdateResult {
                outcome: OwnedShareUpdateOutcome::Unknown,
                settings: Some(settings),
            });
        }
        Ok(OwnedShareUpdateResult {
            outcome: OwnedShareUpdateOutcome::Updated,
            settings: Some(settings),
        })
    }

    fn fresh_owned_share(
        &self,
        account_id: &str,
        category: ShareInventoryCategory,
        ocs_share_id: &str,
        expected_resource_id: &str,
    ) -> Result<OwnedShare, CloudError> {
        if category == ShareInventoryCategory::SharedWithMe {
            return Err(invalid(
                "incoming shares cannot be edited as owned OCS grants",
            ));
        }
        validate_account_id(account_id)?;
        validate_ocs_identifier(ocs_share_id, "share id")?;
        validate_ocs_identifier(expected_resource_id, "resource id")?;
        let generation = self.token_generation();
        let fresh = self.list_owned_shares(account_id, category)?;
        if fresh.scope.token_generation != generation || self.token_generation() != generation {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        let row = fresh
            .items
            .into_iter()
            .find(|row| row.ocs_share_id == ocs_share_id)
            .ok_or_else(|| invalid("share is no longer present in this server list"))?;
        let category_matches = match category {
            ShareInventoryCategory::SharedByMe => {
                matches!(row.kind, OcsShareKind::User | OcsShareKind::Group)
            }
            ShareInventoryCategory::PublicLinks => row.kind == OcsShareKind::PublicLink,
            ShareInventoryCategory::SharedWithMe => false,
        };
        if !category_matches || row.resource_id.as_deref() != Some(expected_resource_id) {
            return Err(invalid(
                "share identity or resource changed; refresh before editing",
            ));
        }
        if row.resource_id.as_deref().is_none_or(str::is_empty) {
            return Err(invalid("share resource identity is unavailable"));
        }
        Ok(row)
    }

    fn settings_for_owned_share(
        &self,
        account_id: &str,
        category: ShareInventoryCategory,
        row: OwnedShare,
        expected_generation: u64,
    ) -> Result<OwnedShareEditSettings, CloudError> {
        let caps = self.sharing_capabilities()?;
        if self.token_generation() != expected_generation {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        let mut fields = Vec::new();
        let mut choices = Vec::new();
        if caps.files_sharing_enabled {
            match row.kind {
                OcsShareKind::User | OcsShareKind::Group
                    if row.permissions.is_some()
                        && row.recipient_id.as_deref().is_some_and(|id| !id.is_empty()) =>
                {
                    choices = ordinary_permission_choices(row.item_type.as_deref());
                    if !choices.is_empty() {
                        fields.push(OwnedShareEditableField::Access);
                    }
                    fields.push(OwnedShareEditableField::Expiration);
                }
                OcsShareKind::PublicLink
                    if caps.public_links_enabled && caps.public_password_required_for.is_some() =>
                {
                    fields.push(OwnedShareEditableField::Name);
                    choices = public_permission_choices(&row, &caps);
                    if caps.public_password_required_for.is_some() && !choices.is_empty() {
                        fields.push(OwnedShareEditableField::Access);
                    }
                    if caps.public_expiration_enabled == Some(true)
                        && public_expiration_policy_known(
                            caps.public_expiration_enabled,
                            caps.public_expiration_enforced,
                        )
                    {
                        fields.push(OwnedShareEditableField::Expiration);
                    }
                }
                _ => {}
            }
        }
        let context = self.inventory_context()?;
        if context.token_generation != expected_generation {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        Ok(OwnedShareEditSettings {
            scope: self.inventory_scope(account_id, context, true),
            category,
            baseline: baseline_for(&row),
            share: row,
            editable_fields: fields,
            access_choices: choices,
        })
    }

    /// Revoke an owned OCS user/group/public share after re-reading the exact
    /// account-wide category and proving its OCS id still targets the expected
    /// resource. Incoming Graph shares, unknown share types, and rows without a
    /// resource id cannot reach DELETE. Callers must confirm with the user.
    pub fn revoke_owned_share(
        &self,
        account_id: &str,
        category: ShareInventoryCategory,
        ocs_share_id: &str,
        expected_resource_id: &str,
    ) -> Result<(), CloudError> {
        if category == ShareInventoryCategory::SharedWithMe {
            return Err(invalid(
                "incoming shares cannot be revoked as owned OCS grants",
            ));
        }
        validate_account_id(account_id)?;
        validate_ocs_identifier(ocs_share_id, "share id")?;
        validate_ocs_identifier(expected_resource_id, "resource id")?;
        let expected_generation = self.token_generation();
        let fresh = self.list_owned_shares(account_id, category)?;
        if fresh.scope.token_generation != expected_generation
            || self.token_generation() != expected_generation
        {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        let row = fresh
            .items
            .iter()
            .find(|row| row.ocs_share_id == ocs_share_id)
            .ok_or_else(|| invalid("share is no longer present in this server list"))?;
        let permitted_kind = match category {
            ShareInventoryCategory::SharedByMe => {
                matches!(row.kind, OcsShareKind::User | OcsShareKind::Group)
            }
            ShareInventoryCategory::PublicLinks => row.kind == OcsShareKind::PublicLink,
            ShareInventoryCategory::SharedWithMe => false,
        };
        if !permitted_kind
            || row.resource_id.as_deref() != Some(expected_resource_id)
            || row.resource_id.as_deref().is_none_or(str::is_empty)
        {
            return Err(invalid(
                "share identity or resource changed; refresh before retry",
            ));
        }

        let context = RangeReadContext {
            deadline: Instant::now()
                .checked_add(INVENTORY_TIMEOUT)
                .ok_or_else(|| invalid("share revocation deadline is invalid"))?,
            token_generation: expected_generation,
        };
        let _guard = RangeContextGuard::enter(context);
        let mut url = append_server_path(
            &self.server,
            &[
                "ocs",
                "v2.php",
                "apps",
                "files_sharing",
                "api",
                "v1",
                "shares",
            ],
        )?;
        url.path_segments_mut()
            .map_err(|_| invalid("share URL cannot contain a path"))?
            .push(ocs_share_id);
        url.query_pairs_mut().append_pair("format", "json");
        let (request, token) = self.request_with_context(Method::DELETE, &url, Some(context))?;
        let response = request
            .header("Accept", "application/json")
            .header("OCS-APIREQUEST", "true")
            .send()
            .map_err(|_| {
                CloudError::new(
                    ErrorKind::Offline,
                    "share revocation outcome is unknown; refresh shares before retry",
                )
            })?;
        if response.status().is_server_error() {
            return Err(CloudError::new(
                ErrorKind::Offline,
                "share revocation outcome is unknown; refresh shares before retry",
            ));
        }
        let status = response.status();
        let mut response = checked(response, &[StatusCode::OK, StatusCode::NO_CONTENT], &token)?;
        if status == StatusCode::NO_CONTENT {
            return Ok(());
        }
        let body = read_bounded(&mut response, 64 * 1024).map_err(|_| {
            CloudError::new(
                ErrorKind::InvalidResponse,
                "share revocation outcome is unknown; refresh shares before retry",
            )
        })?;
        let envelope = parse_json(&body).map_err(|_| {
            CloudError::new(
                ErrorKind::InvalidResponse,
                "share revocation outcome is unknown; refresh shares before retry",
            )
        })?;
        match parse_ocs_status(&envelope) {
            Ok(100 | 200) => Ok(()),
            Ok(_) => Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "server did not confirm share revocation; refresh shares before retry",
            )),
            Err(_) => Err(CloudError::new(
                ErrorKind::InvalidResponse,
                "share revocation outcome is unknown; refresh shares before retry",
            )),
        }
    }

    fn inventory_context(&self) -> Result<RangeReadContext, CloudError> {
        if let Some(active) = super::ACTIVE_RANGE_CONTEXT.with(std::cell::Cell::get) {
            if active.token_generation != self.token_generation() {
                return Err(CloudError::new(
                    ErrorKind::Unauthorized,
                    "authenticated provider generation changed",
                ));
            }
            return Ok(active);
        }
        Ok(RangeReadContext {
            deadline: Instant::now()
                .checked_add(INVENTORY_TIMEOUT)
                .ok_or_else(|| invalid("share inventory deadline is invalid"))?,
            token_generation: self.token_generation(),
        })
    }

    fn guest_sharing_context(&self) -> Result<RangeReadContext, CloudError> {
        let generation = self.token_generation();
        let local_deadline = Instant::now()
            .checked_add(Duration::from_secs(15))
            .ok_or_else(|| invalid("sharing operation deadline is invalid"))?;
        let deadline = super::ACTIVE_RANGE_CONTEXT
            .with(std::cell::Cell::get)
            .map_or(local_deadline, |active| {
                if active.token_generation != generation {
                    return active.deadline;
                }
                active.deadline.min(local_deadline)
            });
        if super::ACTIVE_RANGE_CONTEXT
            .with(std::cell::Cell::get)
            .is_some_and(|active| active.token_generation != generation)
        {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        if deadline <= Instant::now() {
            return Err(CloudError::new(
                ErrorKind::Offline,
                "sharing operation deadline elapsed",
            ));
        }
        Ok(RangeReadContext {
            deadline,
            token_generation: generation,
        })
    }

    fn inventory_scope(
        &self,
        account_id: &str,
        context: RangeReadContext,
        response_complete: bool,
    ) -> InventoryScope {
        InventoryScope {
            account_id: account_id.to_owned(),
            server_url: self.server.as_str().trim_end_matches('/').to_owned(),
            token_generation: context.token_generation,
            response_complete,
        }
    }

    fn ensure_inventory_generation(&self, context: RangeReadContext) -> Result<(), CloudError> {
        if self.token_generation() != context.token_generation {
            return Err(CloudError::new(
                ErrorKind::Unauthorized,
                "authenticated provider generation changed",
            ));
        }
        Ok(())
    }

    fn get_inventory_page(
        &self,
        url: &Url,
        context: RangeReadContext,
        limit: usize,
        ocs: bool,
    ) -> Result<Vec<u8>, CloudError> {
        let (mut request, token) = self.request_with_context(Method::GET, url, Some(context))?;
        request = request.header("Accept", "application/json");
        if ocs {
            request = request.header("OCS-APIREQUEST", "true");
        }
        let response = request.send().map_err(network)?;
        let mut response = checked(response, &[StatusCode::OK], &token)?;
        let body = read_bounded(&mut response, limit)?;
        self.ensure_inventory_generation(context)?;
        Ok(body)
    }
}

struct GraphPage<'a> {
    items: &'a [Value],
    next_link: Option<String>,
}

fn append_server_path(root: &Url, segments: &[&str]) -> Result<Url, CloudError> {
    let mut url = root.clone();
    let mut path = url
        .path_segments_mut()
        .map_err(|_| invalid("server URL cannot contain a path"))?;
    path.pop_if_empty();
    path.extend(segments.iter().copied());
    drop(path);
    Ok(url)
}

fn validate_account_id(value: &str) -> Result<(), CloudError> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(invalid("share inventory account identity is invalid"));
    }
    Ok(())
}

fn require_graph_page(initial: &Url, page: &Url) -> Result<(), CloudError> {
    if !same_origin(initial, page)
        || initial.path() != page.path()
        || !page.username().is_empty()
        || page.password().is_some()
        || page.fragment().is_some()
    {
        return Err(invalid("share inventory continuation left its endpoint"));
    }
    Ok(())
}

fn parse_graph_page(value: &Value) -> Result<GraphPage<'_>, CloudError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("server returned invalid shared-item metadata"))?;
    let items = object
        .get("value")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("server returned invalid shared-item collection"))?;
    let next_link = match object.get("@odata.nextLink") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if value.len() <= MAX_TEXT && !has_control(value) => {
            Some(value.clone())
        }
        _ => return Err(invalid("server returned invalid shared-item continuation")),
    };
    Ok(GraphPage { items, next_link })
}

fn parse_incoming_item(value: &Value, origin: &Url) -> Result<IncomingSharedItem, CloudError> {
    let shared_item_id = required_string(value, "id")?;
    let remote_value = value
        .get("remoteItem")
        .filter(|value| value.is_object())
        .ok_or_else(|| invalid("server returned invalid shared target metadata"))?;
    let remote_id = required_string(remote_value, "id")?;
    let local_folder = optional_object(value, "folder")?;
    let local_file = optional_object(value, "file")?;
    let remote_folder = optional_object(remote_value, "folder")?;
    let remote_file = optional_object(remote_value, "file")?;
    let is_folder = choose_item_kind(local_folder, local_file, remote_folder, remote_file)?;
    let name = optional_string(value, "name")?
        .or(optional_string(remote_value, "name")?)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invalid("server returned shared item without a name"))?;
    let parent_reference = parse_parent_reference(value.get("parentReference"))?;
    let permissions = parse_incoming_permissions(remote_value.get("permissions"))?;
    let created_by = parse_recipient(remote_value.get("createdBy"))?;
    let web_dav_url = optional_string(remote_value, "webDavUrl")?;
    if let Some(url) = &web_dav_url {
        let parsed =
            Url::parse(url).map_err(|_| invalid("server returned invalid shared DAV URL"))?;
        if url.len() > MAX_TEXT
            || !same_origin(origin, &parsed)
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(invalid("server returned an untrusted shared DAV URL"));
        }
    }
    let remote_item = SharedRemoteItem {
        id: remote_id,
        name: optional_string(remote_value, "name")?,
        is_folder: choose_item_kind(None, None, remote_folder, remote_file)?,
        size: optional_u64(remote_value, "size")?,
        e_tag: optional_string(remote_value, "eTag")?,
        parent_reference: parse_parent_reference(remote_value.get("parentReference"))?,
        web_dav_url,
        permissions,
        created_by,
    };
    let effective_actions =
        optional_string_array(value, "@libre.graph.permissions.actions.allowedValues")?
            .unwrap_or_default();
    let hidden = optional_bool(value, "@UI.Hidden")?.unwrap_or(false);
    Ok(IncomingSharedItem {
        shared_item_id,
        name,
        is_folder,
        size: optional_u64(value, "size")?,
        last_modified_date_time: optional_string(value, "lastModifiedDateTime")?,
        hidden,
        effective_actions,
        parent_reference,
        remote_item,
    })
}

fn choose_item_kind(
    local_folder: Option<&serde_json::Map<String, Value>>,
    local_file: Option<&serde_json::Map<String, Value>>,
    remote_folder: Option<&serde_json::Map<String, Value>>,
    remote_file: Option<&serde_json::Map<String, Value>>,
) -> Result<bool, CloudError> {
    let has_folder = local_folder.is_some() || remote_folder.is_some();
    let has_file = local_file.is_some() || remote_file.is_some();
    match (has_folder, has_file) {
        (true, false) => Ok(true),
        (false, true) => Ok(false),
        _ => Err(invalid("server returned ambiguous shared item type")),
    }
}

fn parse_parent_reference(
    value: Option<&Value>,
) -> Result<Option<ItemParentReference>, CloudError> {
    let Some(value) = value else { return Ok(None) };
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_object()
        .ok_or_else(|| invalid("server returned invalid item parent identity"))?;
    Ok(Some(ItemParentReference {
        drive_id: optional_string(value, "driveId")?,
        item_id: optional_string(value, "id")?,
    }))
}

fn parse_incoming_permissions(
    value: Option<&Value>,
) -> Result<Vec<IncomingPermission>, CloudError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let rows = value
        .as_array()
        .ok_or_else(|| invalid("server returned invalid incoming permissions"))?;
    if rows.len() > 1_000 {
        return Err(invalid("server returned too many incoming permissions"));
    }
    rows.iter()
        .map(|row| {
            Ok(IncomingPermission {
                id: optional_string(row, "id")?,
                roles: optional_string_array(row, "roles")?.unwrap_or_default(),
                actions: optional_string_array(row, "@libre.graph.permissions.actions")?
                    .unwrap_or_default(),
                granted_to: parse_recipient(row.get("grantedToV2"))?,
                invited_by: row
                    .get("invitation")
                    .and_then(|invitation| invitation.get("invitedBy"))
                    .map(|recipient| parse_recipient(Some(recipient)))
                    .transpose()?
                    .flatten(),
                created_date_time: optional_string(row, "createdDateTime")?,
                expiration_date_time: optional_string(row, "expirationDateTime")?,
            })
        })
        .collect()
}

fn parse_recipient(value: Option<&Value>) -> Result<Option<IncomingRecipient>, CloudError> {
    let Some(value) = value else { return Ok(None) };
    if value.is_null() {
        return Ok(None);
    }
    let object = value
        .as_object()
        .ok_or_else(|| invalid("server returned invalid share recipient"))?;
    let user = object.get("user").filter(|value| !value.is_null());
    let group = object.get("group").filter(|value| !value.is_null());
    if user.is_some() && group.is_some() {
        return Err(invalid("server returned ambiguous share recipient"));
    }
    let user_id = user
        .map(|identity| required_string(identity, "id"))
        .transpose()?;
    let user_display_name = user
        .map(|identity| optional_string(identity, "displayName"))
        .transpose()?
        .flatten();
    let group_id = group
        .map(|identity| required_string(identity, "id"))
        .transpose()?;
    let group_display_name = group
        .map(|identity| optional_string(identity, "displayName"))
        .transpose()?
        .flatten();
    if user_id.is_none() && group_id.is_none() {
        return Ok(None);
    }
    Ok(Some(IncomingRecipient {
        user_id,
        user_display_name,
        group_id,
        group_display_name,
    }))
}

fn parse_ocs_data(value: &Value) -> Result<&[Value], CloudError> {
    if !matches!(parse_ocs_status(value)?, 100 | 200) {
        return Err(CloudError::new(
            ErrorKind::InvalidResponse,
            "OpenCloud rejected the share inventory request",
        ));
    }
    value
        .get("ocs")
        .and_then(|ocs| ocs.get("data"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid("server returned invalid OCS share collection"))
}

fn parse_ocs_status(value: &Value) -> Result<i64, CloudError> {
    let meta = value
        .get("ocs")
        .and_then(|ocs| ocs.get("meta"))
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("server returned invalid OCS response metadata"))?;
    let status = meta
        .get("statuscode")
        .and_then(number_or_string_i64)
        .ok_or_else(|| invalid("server returned invalid OCS response status"))?;
    if !matches!(status, 100 | 200) {
        return Ok(status);
    }
    Ok(status)
}

fn baseline_for(row: &OwnedShare) -> OwnedShareBaseline {
    OwnedShareBaseline {
        ocs_share_id: row.ocs_share_id.clone(),
        resource_id: row.resource_id.clone().unwrap_or_default(),
        space_id: row.space_id.clone(),
        owner_id: row.owner_id.clone(),
        kind: row.kind,
        recipient_id: row.recipient_id.clone(),
        path: row.path.clone(),
        file_target: row.file_target.clone(),
        item_type: row.item_type.clone(),
        permissions: row.permissions,
        expires_at: row.expires_at.clone(),
        label: row.label.clone(),
    }
}

fn ordinary_permission_choices(item_type: Option<&str>) -> Vec<OwnedShareAccessChoice> {
    let choices: &[(u64, &str)] = match item_type {
        Some("file") => &[(1, "View"), (3, "View and edit")],
        Some("folder") => &[
            (1, "View"),
            (3, "View and edit"),
            (15, "Edit and manage files"),
            (31, "Full access"),
        ],
        _ => return Vec::new(),
    };
    choices
        .iter()
        .copied()
        .map(|(permissions, name)| OwnedShareAccessChoice {
            id: permissions.to_string(),
            name: name.to_owned(),
            permissions,
        })
        .collect()
}

fn public_permission_choices(
    row: &OwnedShare,
    capabilities: &crate::guest_permissions::SharingCapabilities,
) -> Vec<OwnedShareAccessChoice> {
    if row.item_type.as_deref() == Some("file") {
        return vec![
            OwnedShareAccessChoice {
                id: "1".into(),
                name: "View".into(),
                permissions: 1,
            },
            OwnedShareAccessChoice {
                id: "3".into(),
                name: "View and edit".into(),
                permissions: 3,
            },
        ];
    }
    if row.item_type.as_deref() != Some("folder") {
        return Vec::new();
    }
    let mut choices = vec![(1, "View"), (3, "View and edit")];
    if capabilities.public_upload_enabled == Some(true) {
        choices.push((15, "Edit and upload"));
        choices.push((5, "View and upload"));
    }
    if capabilities.public_upload_only_enabled == Some(true) {
        choices.push((4, "Upload only"));
    }
    choices
        .into_iter()
        .map(|(permissions, name)| OwnedShareAccessChoice {
            id: permissions.to_string(),
            name: name.to_owned(),
            permissions,
        })
        .collect()
}

fn public_expiration_policy_known(enabled: Option<bool>, enforced: Option<bool>) -> bool {
    matches!(
        (enabled, enforced),
        (Some(false), None | Some(false)) | (Some(true), Some(false) | Some(true))
    )
}

fn unsupported_capabilities(message: &str) -> CloudError {
    CloudError::new(ErrorKind::Unsupported, message)
}

fn append_expiration(
    form: &mut Vec<(String, String)>,
    update: &ExpirationUpdate,
    public_link: bool,
    capabilities: Option<&crate::guest_permissions::SharingCapabilities>,
) -> Result<(), CloudError> {
    match update {
        ExpirationUpdate::Keep => Ok(()),
        ExpirationUpdate::Clear => {
            if public_link
                && !capabilities.is_some_and(|caps| {
                    public_expiration_policy_known(
                        caps.public_expiration_enabled,
                        caps.public_expiration_enforced,
                    )
                })
            {
                return Err(unsupported_capabilities(
                    "public link expiration policy is unavailable",
                ));
            }
            form.push(("expireDate".into(), String::new()));
            Ok(())
        }
        ExpirationUpdate::Set { value } => {
            if value.len() > 64 || parse_rfc3339_epoch(value).is_none() {
                return Err(invalid("share expiration is invalid"));
            }
            if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                if parse_rfc3339_epoch(value)
                    .is_some_and(|expiration| expiration <= now.as_secs() as i64)
                {
                    return Err(invalid("share expiration must be in the future"));
                }
            }
            if public_link
                && !capabilities.is_some_and(|caps| {
                    caps.public_expiration_enabled == Some(true)
                        && public_expiration_policy_known(
                            caps.public_expiration_enabled,
                            caps.public_expiration_enforced,
                        )
                })
            {
                return Err(unsupported_capabilities(
                    "public link expiration is unavailable",
                ));
            }
            form.push(("expireDate".into(), value.clone()));
            Ok(())
        }
    }
}

fn parse_rfc3339_epoch(value: &str) -> Option<i64> {
    let (date, time_zone) = value.split_once('T')?;
    let date = date.as_bytes();
    if date.len() != 10 || date[4] != b'-' || date[7] != b'-' {
        return None;
    }
    let y = std::str::from_utf8(&date[..4]).ok()?.parse::<u16>().ok()?;
    let m = std::str::from_utf8(&date[5..7]).ok()?.parse::<u8>().ok()?;
    let d = std::str::from_utf8(&date[8..10]).ok()?.parse::<u8>().ok()?;
    if y == 0 || !(1..=12).contains(&m) {
        return None;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let mdays = [
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
    if d == 0 || d > mdays[(m - 1) as usize] {
        return None;
    }
    let (clock, zone) = if let Some(clock) = time_zone.strip_suffix('Z') {
        (clock, "Z")
    } else {
        let i = time_zone.rfind(['+', '-'])?;
        (&time_zone[..i], &time_zone[i..])
    };
    let offset = if zone == "Z" {
        0
    } else {
        let z = &zone[1..];
        if z.len() != 5 || z.as_bytes()[2] != b':' {
            return None;
        }
        let h = z[..2].parse::<u8>().ok()?;
        let min = z[3..].parse::<u8>().ok()?;
        if h > 23 || min > 59 {
            return None;
        }
        let amount = i64::from(h) * 3600 + i64::from(min) * 60;
        if zone.starts_with('-') {
            -amount
        } else {
            amount
        }
    };
    let (clock, fraction) = clock.split_once('.').unwrap_or((clock, ""));
    if clock.len() != 8
        || clock.as_bytes()[2] != b':'
        || clock.as_bytes()[5] != b':'
        || fraction.len() > 9
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let h = clock[..2].parse::<u8>().ok()?;
    let min = clock[3..5].parse::<u8>().ok()?;
    let sec = clock[6..].parse::<u8>().ok()?;
    if h > 23 || min > 59 || sec > 59 {
        return None;
    }
    let year = i64::from(y) - if m <= 2 { 1 } else { 0 };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let sm = i64::from(m) + if m > 2 { -3 } else { 9 };
    let doy = (153 * sm + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(
        (era * 146_097 + doe - 719_468) * 86_400
            + i64::from(h) * 3600
            + i64::from(min) * 60
            + i64::from(sec)
            - offset,
    )
}

fn updated_state_matches(
    row: &OwnedShare,
    before: &OwnedShare,
    baseline: &OwnedShareBaseline,
    form: &[(String, String)],
) -> bool {
    row.ocs_share_id == baseline.ocs_share_id
        && row.resource_id.as_deref() == Some(baseline.resource_id.as_str())
        && row.space_id == baseline.space_id
        && row.owner_id == baseline.owner_id
        && row.kind == baseline.kind
        && row.recipient_id == baseline.recipient_id
        && row.path == baseline.path
        && row.file_target == baseline.file_target
        && row.item_type == baseline.item_type
        && row.public_url == before.public_url
        && (form.iter().any(|(key, _)| key == "permissions")
            || row.permissions == baseline.permissions)
        && (form.iter().any(|(key, _)| key == "name") || row.label == baseline.label)
        && (form.iter().any(|(key, _)| key == "expireDate")
            || row.expires_at == baseline.expires_at)
        && form.iter().all(|(key, value)| match key.as_str() {
            "permissions" => row.permissions == value.parse::<u64>().ok(),
            "name" => row.label.as_deref() == Some(value.as_str()),
            "expireDate" if value.is_empty() => row.expires_at.as_deref().is_none_or(str::is_empty),
            "expireDate" => {
                row.expires_at.as_deref().and_then(parse_rfc3339_epoch)
                    == parse_rfc3339_epoch(value)
            }
            _ => false,
        })
}

fn validate_ocs_identifier(value: &str, label: &str) -> Result<(), CloudError> {
    if value.is_empty()
        || value.len() > MAX_TEXT
        || value == "."
        || value == ".."
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\' | '?' | '#'))
    {
        let message = match label {
            "share id" => "OCS share id is invalid",
            _ => "share resource id is invalid",
        };
        return Err(invalid(message));
    }
    Ok(())
}

fn parse_owned_share(row: &Value) -> Result<OwnedShare, CloudError> {
    let id = required_string(row, "id")?;
    let code = row
        .get("share_type")
        .and_then(number_or_string_i64)
        .ok_or_else(|| invalid("server returned invalid OCS share type"))?;
    let kind = match code {
        0 => OcsShareKind::User,
        1 => OcsShareKind::Group,
        3 => OcsShareKind::PublicLink,
        other => OcsShareKind::Other(other),
    };
    let public_url = if kind == OcsShareKind::PublicLink {
        optional_string(row, "url")?
            .filter(|url| !url.is_empty())
            .map(validate_public_url)
            .transpose()?
    } else {
        None
    };
    Ok(OwnedShare {
        ocs_share_id: id,
        kind,
        path: optional_string(row, "path")?,
        file_target: optional_string(row, "file_target")?,
        resource_id: optional_string(row, "item_source")?.or(optional_string(row, "file_source")?),
        space_id: optional_string(row, "space_id")?,
        space_alias: optional_string(row, "space_alias")?,
        item_type: optional_string(row, "item_type")?,
        mime_type: optional_string(row, "mimetype")?,
        permissions: optional_u64(row, "permissions")?,
        state: optional_i64(row, "state")?,
        shared_at_epoch_seconds: optional_u64(row, "stime")?,
        expires_at: optional_string(row, "expiration")?.filter(|value| !value.is_empty()),
        owner_id: optional_string(row, "uid_owner")?,
        owner_display_name: optional_string(row, "displayname_owner")?,
        recipient_id: optional_string(row, "share_with")?,
        recipient_display_name: optional_string(row, "share_with_displayname")?,
        recipient_additional_info: optional_string(row, "share_with_additional_info")?,
        recipient_user_type: optional_i64(row, "share_with_user_type")?,
        label: optional_string(row, "name")?,
        hidden: optional_bool(row, "hidden")?,
        quicklink: optional_bool(row, "quicklink")?,
        public_url,
    })
}

fn validate_public_url(value: String) -> Result<String, CloudError> {
    if value.len() > MAX_TEXT || has_control(&value) {
        return Err(invalid("server returned invalid public link metadata"));
    }
    let parsed =
        Url::parse(&value).map_err(|_| invalid("server returned invalid public link metadata"))?;
    if !matches!(parsed.scheme(), "https" | "http")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(invalid("server returned invalid public link metadata"));
    }
    Ok(value)
}

fn parse_json(bytes: &[u8]) -> Result<Value, CloudError> {
    serde_json::from_slice(bytes).map_err(|_| invalid("server returned invalid share metadata"))
}

fn required_string(value: &Value, key: &str) -> Result<String, CloudError> {
    optional_string(value, key)?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("server omitted required share identity"))
}

fn optional_string(value: &Value, key: &str) -> Result<Option<String>, CloudError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.len() <= MAX_TEXT && !has_control(value) => {
            Ok(Some(value.clone()))
        }
        _ => Err(invalid("server returned invalid share text metadata")),
    }
}

fn optional_object<'a>(
    value: &'a Value,
    key: &str,
) -> Result<Option<&'a serde_json::Map<String, Value>>, CloudError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(object)) => Ok(Some(object)),
        _ => Err(invalid("server returned invalid shared item type metadata")),
    }
}

fn optional_string_array(value: &Value, key: &str) -> Result<Option<Vec<String>>, CloudError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(values)) if values.len() <= 1_000 => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|text| text.len() <= MAX_TEXT && !has_control(text))
                    .map(str::to_owned)
                    .ok_or_else(|| invalid("server returned invalid share action metadata"))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        _ => Err(invalid("server returned invalid share action metadata")),
    }
}

fn optional_bool(value: &Value, key: &str) -> Result<Option<bool>, CloudError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        _ => Err(invalid("server returned invalid share state metadata")),
    }
}

fn optional_u64(value: &Value, key: &str) -> Result<Option<u64>, CloudError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => number_or_string_u64(value)
            .map(Some)
            .ok_or_else(|| invalid("server returned invalid numeric share metadata")),
    }
}

fn optional_i64(value: &Value, key: &str) -> Result<Option<i64>, CloudError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => number_or_string_i64(value)
            .map(Some)
            .ok_or_else(|| invalid("server returned invalid numeric share metadata")),
    }
}

fn number_or_string_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str()?.parse::<u64>().ok())
}

fn number_or_string_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str()?.parse::<i64>().ok())
}

fn has_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProxyConfig;
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread,
    };

    fn client(addr: std::net::SocketAddr) -> OpenCloudClient {
        OpenCloudClient::new_with_proxy(
            &format!("http://{addr}/"),
            "synthetic-token".into(),
            &ProxyConfig::Direct,
        )
        .unwrap()
    }

    fn read_request(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut byte = [0; 1];
        while !bytes.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            bytes.push(byte[0]);
            assert!(bytes.len() < 16 * 1024);
        }
        String::from_utf8(bytes).unwrap()
    }

    fn read_request_with_body(stream: &mut TcpStream) -> (String, String) {
        let header = read_request(stream);
        let length = header
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        (header, String::from_utf8(body).unwrap())
    }

    fn respond(stream: &mut TcpStream, status: &str, body: &str) {
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        stream.flush().unwrap();
    }

    const INCOMING: &str = r#"{"value":[{"id":"shared-entry","name":"Design notes","parentReference":{"driveId":"incoming-drive","id":"jail-parent"},"remoteItem":{"id":"target-file","name":"Design notes","file":{},"size":42,"eTag":"etag-1","parentReference":{"driveId":"origin-drive","id":"origin-parent"},"permissions":[{"id":"grant-1","roles":["viewer"],"@libre.graph.permissions.actions":["read"],"grantedToV2":{"user":{"id":"owner","displayName":"Owner"}}}],"createdBy":{"user":{"id":"owner","displayName":"Owner"}}}}],"@odata.nextLink":"?page=2"}"#;
    const INCOMING_PAGE_TWO: &str = r#"{"value":[{"id":"shared-folder","name":"Team folder","folder":{},"remoteItem":{"id":"target-folder","name":"Team folder","folder":{},"parentReference":{"driveId":"origin-drive"}}}]}"#;
    const OCS_ROWS: &str = r#"{"ocs":{"meta":{"status":"ok","statuscode":100,"message":"OK"},"data":[{"id":"ocs-user-grant","share_type":0,"path":"/Projects/Plan.txt","item_source":"space!resource-file","space_id":"space!resource-root","space_alias":"Projects","item_type":"file","mimetype":"text/plain","permissions":1,"state":0,"stime":1761600000,"expiration":"","uid_owner":"owner-id","displayname_owner":"Owner","share_with":"recipient-id","share_with_displayname":"Recipient","share_with_additional_info":"recipient@example.org","share_with_user_type":1,"hidden":true,"quicklink":false,"name":""},{"id":"ocs-link-grant","share_type":"3","path":"/Projects/Plan.txt","item_source":"space!resource-file","space_id":"space!resource-root","item_type":"file","permissions":"1","state":"0","url":"https://cloud.example/s/secret-link","name":"Review"},{"id":"ocs-other-grant","share_type":9,"path":"/Projects/Plan.txt","item_source":"space!resource-file","permissions":1}]}}"#;
    const SHARE_CAPABILITIES: &str = r#"{"ocs":{"meta":{"status":"ok","statuscode":100},"data":{"capabilities":{"files_sharing":{"api_enabled":true,"group_sharing":true,"public":{"enabled":true,"password":{"enforced":false},"expire_date":{"enabled":true,"enforced":false}}}}}}}"#;
    const OCS_PUBLIC_ROW: &str = r#"{"ocs":{"meta":{"status":"ok","statuscode":100},"data":[{"id":"ocs-link-grant","share_type":3,"path":"/Projects/Plan.txt","item_source":"space!resource-file","space_id":"space!resource-root","item_type":"file","permissions":"1","state":"0","url":"https://cloud.example/s/secret-link","name":"Review"}]}}"#;
    const OCS_GROUP_ROW: &str = r#"{"ocs":{"meta":{"status":"ok","statuscode":100},"data":[{"id":"ocs-group-grant","share_type":1,"path":"/Projects","item_source":"space!resource-folder","space_id":"space!resource-root","item_type":"folder","permissions":15,"expiration":"2035-10-28T03:30:17Z","uid_owner":"owner-id","share_with":"group-7","share_with_displayname":"Editors","name":""}]}}"#;

    fn updated_ocs_rows() -> String {
        OCS_ROWS.replacen("\"permissions\":1", "\"permissions\":3", 1)
    }

    fn fixture_owned_row(id: &str) -> OwnedShare {
        let envelope = parse_json(OCS_ROWS.as_bytes()).unwrap();
        let row = parse_ocs_data(&envelope)
            .unwrap()
            .iter()
            .find(|row| row.get("id").and_then(Value::as_str) == Some(id))
            .unwrap();
        parse_owned_share(row).unwrap()
    }

    #[test]
    fn incoming_listing_follows_bounded_same_endpoint_pages_and_preserves_ids() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let first = read_request(&mut stream);
            assert!(first.starts_with("GET /graph/v1beta1/me/drive/sharedWithMe HTTP/1.1"));
            assert!(first.contains("authorization: Bearer synthetic-token"));
            respond(&mut stream, "200 OK", INCOMING);
            let (mut stream, _) = listener.accept().unwrap();
            let second = read_request(&mut stream);
            assert!(second.starts_with("GET /graph/v1beta1/me/drive/sharedWithMe?page=2 HTTP/1.1"));
            respond(&mut stream, "200 OK", INCOMING_PAGE_TWO);
        });
        let result = client(addr).list_incoming_shares("account-1").unwrap();
        assert!(result.scope.response_complete);
        assert_eq!(result.scope.account_id, "account-1");
        assert_eq!(result.items.len(), 2);
        assert_eq!(result.items[0].shared_item_id, "shared-entry");
        assert_eq!(result.items[0].remote_item.id, "target-file");
        assert_eq!(
            result.items[0]
                .parent_reference
                .as_ref()
                .unwrap()
                .drive_id
                .as_deref(),
            Some("incoming-drive")
        );
        assert_eq!(
            result.items[0]
                .remote_item
                .parent_reference
                .as_ref()
                .unwrap()
                .drive_id
                .as_deref(),
            Some("origin-drive")
        );
        assert!(!result.items[0].is_folder);
        assert_eq!(result.items[0].remote_item.permissions[0].roles, ["viewer"]);
        worker.join().unwrap();
    }

    #[test]
    fn incoming_dav_locator_must_be_same_origin_without_url_credentials_or_query() {
        let origin = Url::parse("https://cloud.example/").unwrap();
        let mut item = serde_json::json!({
            "id":"share-entry",
            "name":"Shared file",
            "remoteItem":{
                "id":"target-file",
                "name":"Shared file",
                "file":{},
                "webDavUrl":"https://cloud.example/dav/spaces/target-file"
            }
        });
        assert!(parse_incoming_item(&item, &origin).is_ok());
        for url in [
            "https://attacker.example/dav/target",
            "https://user@cloud.example/dav/target",
            "https://cloud.example/dav/target?token=secret",
            "https://cloud.example/dav/target#fragment",
        ] {
            item["remoteItem"]["webDavUrl"] = Value::String(url.to_owned());
            assert!(parse_incoming_item(&item, &origin).is_err());
        }
    }

    #[test]
    fn continuation_to_another_origin_is_rejected_before_second_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            let body = format!(
                "{{\"value\":[],\"@odata.nextLink\":\"http://{}/graph/v1beta1/me/drive/sharedWithMe?page=2\"}}",
                "127.0.0.1:9"
            );
            respond(&mut stream, "200 OK", &body);
        });
        assert!(client(addr).list_incoming_shares("account-1").is_err());
        worker.join().unwrap();
    }

    #[test]
    fn owned_list_keeps_ocs_and_space_ids_distinct_and_redacts_link_url() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            assert!(request.starts_with(
                "GET /ocs/v2.php/apps/files_sharing/api/v1/shares?format=json HTTP/1.1"
            ));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("ocs-apirequest: true")
            );
            respond(&mut stream, "200 OK", OCS_ROWS);

            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            assert!(request.starts_with("GET /ocs/v2.php/apps/files_sharing/api/v1/shares?format=json&share_types=3 HTTP/1.1"));
            respond(
                &mut stream,
                "200 OK",
                &format!(
                    "{{\"ocs\":{{\"meta\":{{\"statuscode\":100}},\"data\":[{}]}}}}",
                    serde_json::from_str::<Value>(OCS_ROWS).unwrap()["ocs"]["data"][1]
                ),
            );
        });
        let api = client(addr);
        let owned = api
            .list_owned_shares("account-1", ShareInventoryCategory::SharedByMe)
            .unwrap();
        assert!(owned.scope.response_complete);
        assert_eq!(owned.items.len(), 2);
        assert_eq!(owned.items[0].ocs_share_id, "ocs-user-grant");
        assert_eq!(
            owned.items[0].resource_id.as_deref(),
            Some("space!resource-file")
        );
        assert_eq!(
            owned.items[0].space_id.as_deref(),
            Some("space!resource-root")
        );
        assert_eq!(owned.items[0].mime_type.as_deref(), Some("text/plain"));
        assert_eq!(owned.items[0].recipient_user_type, Some(1));
        assert_eq!(owned.items[0].hidden, Some(true));
        assert_eq!(owned.items[0].quicklink, Some(false));
        assert_ne!(
            owned.items[0].ocs_share_id,
            owned.items[0].resource_id.as_deref().unwrap()
        );
        assert_eq!(owned.items[1].kind, OcsShareKind::Other(9));
        assert!(!format!("{:?}", owned.items[1]).contains("secret-link"));

        let links = api
            .list_owned_shares("account-1", ShareInventoryCategory::PublicLinks)
            .unwrap();
        assert_eq!(links.items.len(), 1);
        assert_eq!(links.items[0].kind, OcsShareKind::PublicLink);
        assert!(!format!("{:?}", links.items[0]).contains("secret-link"));
        worker.join().unwrap();
    }

    #[test]
    fn public_capability_share_ids_are_redacted_in_debug_but_preserved_for_cas() {
        let mut row = fixture_owned_row("ocs-link-grant");
        row.kind = OcsShareKind::PublicLink;
        row.ocs_share_id = "synthetic-public-token".into();
        row.public_url = Some("https://cloud.example/s/synthetic-public-token".into());
        let baseline = baseline_for(&row);
        assert!(!format!("{row:?}").contains("synthetic-public-token"));
        assert!(!format!("{baseline:?}").contains("synthetic-public-token"));
        assert_eq!(baseline.ocs_share_id, row.ocs_share_id);
        assert_eq!(
            serde_json::to_value(&baseline).unwrap()["ocs_share_id"],
            row.ocs_share_id
        );
    }

    #[test]
    fn malformed_row_prevents_complete_inventory_snapshot() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(
                &mut stream,
                "200 OK",
                r#"{"ocs":{"meta":{"statuscode":100},"data":[{"id":"valid","share_type":0},{"id":"invalid","share_type":"bad"}]}}"#,
            );
        });
        assert!(
            client(addr)
                .list_owned_shares("account-1", ShareInventoryCategory::SharedByMe)
                .is_err()
        );
        worker.join().unwrap();
    }

    #[test]
    fn owned_revoke_revalidates_resource_then_uses_exact_ocs_delete_route() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert!(read_request(&mut stream).starts_with(
                "GET /ocs/v2.php/apps/files_sharing/api/v1/shares?format=json HTTP/1.1"
            ));
            respond(&mut stream, "200 OK", OCS_ROWS);
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            assert!(request.starts_with(
                "DELETE /ocs/v2.php/apps/files_sharing/api/v1/shares/ocs-user-grant?format=json HTTP/1.1"
            ));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("ocs-apirequest: true")
            );
            respond(
                &mut stream,
                "200 OK",
                r#"{"ocs":{"meta":{"status":"ok","statuscode":100},"data":null}}"#,
            );
        });
        client(addr)
            .revoke_owned_share(
                "account-1",
                ShareInventoryCategory::SharedByMe,
                "ocs-user-grant",
                "space!resource-file",
            )
            .unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn changed_resource_and_incoming_id_never_reach_ocs_delete() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let api = client(addr);
        assert!(
            api.revoke_owned_share(
                "account-1",
                ShareInventoryCategory::SharedWithMe,
                "graph-shared-item",
                "target-file",
            )
            .is_err()
        );
        let no_request = listener.try_clone().unwrap();
        no_request.set_nonblocking(true).unwrap();
        assert!(matches!(
            no_request.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        listener.set_nonblocking(false).unwrap();

        let revoker = thread::spawn(move || {
            api.revoke_owned_share(
                "account-1",
                ShareInventoryCategory::SharedByMe,
                "ocs-user-grant",
                "other-resource",
            )
        });
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        respond(&mut stream, "200 OK", OCS_ROWS);
        assert!(revoker.join().unwrap().is_err());
        listener.set_nonblocking(true).unwrap();
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn unknown_types_and_rows_without_resource_identity_cannot_be_revoked() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let observer = listener.try_clone().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert!(read_request(&mut stream).starts_with(
                "GET /ocs/v2.php/apps/files_sharing/api/v1/shares?format=json HTTP/1.1"
            ));
            respond(&mut stream, "200 OK", OCS_ROWS);
            let (mut stream, _) = listener.accept().unwrap();
            assert!(read_request(&mut stream).starts_with(
                "GET /ocs/v2.php/apps/files_sharing/api/v1/shares?format=json HTTP/1.1"
            ));
            respond(
                &mut stream,
                "200 OK",
                r#"{"ocs":{"meta":{"statuscode":100},"data":[{"id":"missing-resource","share_type":0}]}}"#,
            );
        });
        let api = client(addr);
        assert!(
            api.revoke_owned_share(
                "account-1",
                ShareInventoryCategory::SharedByMe,
                "ocs-other-grant",
                "space!resource-file",
            )
            .is_err()
        );
        assert!(
            api.revoke_owned_share(
                "account-1",
                ShareInventoryCategory::SharedByMe,
                "missing-resource",
                "some-resource",
            )
            .is_err()
        );
        worker.join().unwrap();
        observer.set_nonblocking(true).unwrap();
        assert!(matches!(
            observer.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn dropped_revoke_ack_is_reported_uncertain_without_retry() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let api = client(addr);
        let revoker = thread::spawn(move || {
            api.revoke_owned_share(
                "account-1",
                ShareInventoryCategory::SharedByMe,
                "ocs-user-grant",
                "space!resource-file",
            )
        });
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        respond(&mut stream, "200 OK", OCS_ROWS);
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        assert!(request.starts_with(
            "DELETE /ocs/v2.php/apps/files_sharing/api/v1/shares/ocs-user-grant?format=json HTTP/1.1"
        ));
        drop(stream);
        let error = revoker.join().unwrap().unwrap_err();
        assert_eq!(error.kind, ErrorKind::Offline);
        assert!(error.message.contains("outcome is unknown"));
        listener.set_nonblocking(true).unwrap();
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn settings_read_returns_baseline_and_source_defined_access_choices() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(&mut stream, "200 OK", OCS_ROWS);
            let (mut stream, _) = listener.accept().unwrap();
            assert!(
                read_request(&mut stream)
                    .starts_with("GET /ocs/v1.php/cloud/capabilities?format=json HTTP/1.1")
            );
            respond(&mut stream, "200 OK", SHARE_CAPABILITIES);
        });
        let settings = client(addr)
            .get_owned_share_edit_settings(
                "account-1",
                ShareInventoryCategory::SharedByMe,
                "ocs-user-grant",
                "space!resource-file",
            )
            .unwrap();
        assert_eq!(settings.baseline.permissions, Some(1));
        assert_eq!(
            settings.baseline.recipient_id.as_deref(),
            Some("recipient-id")
        );
        assert!(
            settings
                .editable_fields
                .contains(&OwnedShareEditableField::Access)
        );
        assert_eq!(
            settings
                .access_choices
                .iter()
                .map(|c| c.permissions)
                .collect::<Vec<_>>(),
            [1, 3]
        );
        worker.join().unwrap();
    }

    #[test]
    fn disabled_public_expiration_is_not_offered_in_the_editor() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            let caps = SHARE_CAPABILITIES.replace(
                "\"expire_date\":{\"enabled\":true,\"enforced\":false}",
                "\"expire_date\":{\"enabled\":false}",
            );
            respond(&mut stream, "200 OK", &caps);
        });
        let rows: Value = serde_json::from_str(OCS_ROWS).unwrap();
        let row = parse_owned_share(&rows["ocs"]["data"][1]).unwrap();
        let api = client(addr);
        let settings = api
            .settings_for_owned_share(
                "account-1",
                ShareInventoryCategory::PublicLinks,
                row,
                api.token_generation(),
            )
            .unwrap();
        assert!(
            settings
                .editable_fields
                .contains(&OwnedShareEditableField::Name)
        );
        assert!(
            !settings
                .editable_fields
                .contains(&OwnedShareEditableField::Expiration)
        );
        worker.join().unwrap();
    }

    #[test]
    fn stale_settings_baseline_is_rejected_before_put() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let observer = listener.try_clone().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(&mut stream, "200 OK", OCS_ROWS);
        });
        let mut baseline = baseline_for(&fixture_owned_row("ocs-user-grant"));
        baseline.permissions = Some(3);
        let result = client(addr).update_owned_share(
            "account-1",
            ShareInventoryCategory::SharedByMe,
            "ocs-user-grant",
            "space!resource-file",
            &baseline,
            &OwnedShareUpdate::UserOrGroup {
                permissions: Some(3),
                expiration: ExpirationUpdate::Keep,
            },
        );
        assert!(result.is_err());
        worker.join().unwrap();
        observer.set_nonblocking(true).unwrap();
        assert!(
            matches!(observer.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }

    #[test]
    fn ordinary_update_preserves_scope_and_verifies_fresh_state() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            for response in [OCS_ROWS, SHARE_CAPABILITIES] {
                let (mut stream, _) = listener.accept().unwrap();
                read_request(&mut stream);
                respond(&mut stream, "200 OK", response);
            }
            let (mut stream, _) = listener.accept().unwrap();
            let (headers, body) = read_request_with_body(&mut stream);
            assert!(headers.starts_with("PUT /ocs/v2.php/apps/files_sharing/api/v1/shares/ocs-user-grant?format=json HTTP/1.1"));
            assert!(
                headers
                    .to_ascii_lowercase()
                    .contains("content-type: application/x-www-form-urlencoded")
            );
            assert!(body.contains("permissions=3"));
            assert!(!body.contains("expireDate"));
            assert!(!body.contains("password"));
            respond(
                &mut stream,
                "200 OK",
                r#"{"ocs":{"meta":{"status":"ok","statuscode":100},"data":[]}}"#,
            );
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            let changed = updated_ocs_rows();
            respond(&mut stream, "200 OK", &changed);
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(&mut stream, "200 OK", SHARE_CAPABILITIES);
        });
        let row = fixture_owned_row("ocs-user-grant");
        let baseline = baseline_for(&row);
        let result = client(addr)
            .update_owned_share(
                "account-1",
                ShareInventoryCategory::SharedByMe,
                "ocs-user-grant",
                "space!resource-file",
                &baseline,
                &OwnedShareUpdate::UserOrGroup {
                    permissions: Some(3),
                    expiration: ExpirationUpdate::Keep,
                },
            )
            .unwrap();
        assert_eq!(result.outcome, OwnedShareUpdateOutcome::Updated);
        assert_eq!(result.settings.unwrap().share.permissions, Some(3));
        worker.join().unwrap();
    }

    #[test]
    fn public_link_name_update_omits_password_and_preserves_access_url() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert!(read_request(&mut stream).starts_with(
                "GET /ocs/v2.php/apps/files_sharing/api/v1/shares?format=json&share_types=3 HTTP/1.1"
            ));
            respond(&mut stream, "200 OK", OCS_PUBLIC_ROW);
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(&mut stream, "200 OK", SHARE_CAPABILITIES);
            let (mut stream, _) = listener.accept().unwrap();
            let (headers, body) = read_request_with_body(&mut stream);
            assert!(headers.starts_with("PUT /ocs/v2.php/apps/files_sharing/api/v1/shares/ocs-link-grant?format=json HTTP/1.1"));
            assert!(body.contains("name=Renamed"));
            assert!(!body.contains("password"));
            assert!(!body.contains("permissions"));
            assert!(!body.contains("expireDate"));
            respond(
                &mut stream,
                "200 OK",
                r#"{"ocs":{"meta":{"status":"ok","statuscode":100},"data":[]}}"#,
            );
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            let changed = OCS_PUBLIC_ROW.replacen("\"name\":\"Review\"", "\"name\":\"Renamed\"", 1);
            respond(&mut stream, "200 OK", &changed);
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(&mut stream, "200 OK", SHARE_CAPABILITIES);
        });
        let row = fixture_owned_row("ocs-link-grant");
        let baseline = baseline_for(&row);
        let result = client(addr)
            .update_owned_share(
                "account-1",
                ShareInventoryCategory::PublicLinks,
                "ocs-link-grant",
                "space!resource-file",
                &baseline,
                &OwnedShareUpdate::PublicLink {
                    permissions: None,
                    name: Some("Renamed".into()),
                    expiration: ExpirationUpdate::Keep,
                },
            )
            .unwrap();
        assert_eq!(result.outcome, OwnedShareUpdateOutcome::Updated);
        let updated = result.settings.unwrap().share;
        assert_eq!(updated.label.as_deref(), Some("Renamed"));
        assert_eq!(
            updated.public_url.as_deref(),
            Some("https://cloud.example/s/secret-link")
        );
        worker.join().unwrap();
    }

    #[test]
    fn public_link_access_update_preserves_expiration_and_exact_url() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(&mut stream, "200 OK", OCS_PUBLIC_ROW);
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(&mut stream, "200 OK", SHARE_CAPABILITIES);
            let (mut stream, _) = listener.accept().unwrap();
            let (headers, body) = read_request_with_body(&mut stream);
            assert!(headers.starts_with("PUT /ocs/v2.php/apps/files_sharing/api/v1/shares/ocs-link-grant?format=json HTTP/1.1"));
            assert!(body.contains("permissions=3"));
            assert!(!body.contains("password"));
            assert!(!body.contains("expireDate"));
            respond(
                &mut stream,
                "200 OK",
                r#"{"ocs":{"meta":{"status":"ok","statuscode":100},"data":[]}}"#,
            );
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            let changed = OCS_PUBLIC_ROW.replace("\"permissions\":\"1\"", "\"permissions\":\"3\"");
            respond(&mut stream, "200 OK", &changed);
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(&mut stream, "200 OK", SHARE_CAPABILITIES);
        });
        let row = fixture_owned_row("ocs-link-grant");
        let result = client(addr)
            .update_owned_share(
                "account-1",
                ShareInventoryCategory::PublicLinks,
                "ocs-link-grant",
                "space!resource-file",
                &baseline_for(&row),
                &OwnedShareUpdate::PublicLink {
                    permissions: Some(3),
                    name: None,
                    expiration: ExpirationUpdate::Keep,
                },
            )
            .unwrap();
        assert_eq!(result.outcome, OwnedShareUpdateOutcome::Updated);
        let updated = result.settings.unwrap().share;
        assert_eq!(updated.permissions, Some(3));
        assert_eq!(updated.public_url, row.public_url);
        worker.join().unwrap();
    }

    #[test]
    fn public_inventory_revoke_uses_only_the_fresh_ocs_link_identity() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert!(read_request(&mut stream).starts_with(
                "GET /ocs/v2.php/apps/files_sharing/api/v1/shares?format=json&share_types=3 HTTP/1.1"
            ));
            respond(&mut stream, "200 OK", OCS_PUBLIC_ROW);
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            assert!(request.starts_with(
                "DELETE /ocs/v2.php/apps/files_sharing/api/v1/shares/ocs-link-grant?format=json HTTP/1.1"
            ));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("ocs-apirequest: true")
            );
            respond(&mut stream, "204 No Content", "");
        });
        client(addr)
            .revoke_owned_share(
                "account-1",
                ShareInventoryCategory::PublicLinks,
                "ocs-link-grant",
                "space!resource-file",
            )
            .unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn group_share_expiration_clear_keeps_current_access_mask() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(&mut stream, "200 OK", OCS_GROUP_ROW);
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(&mut stream, "200 OK", SHARE_CAPABILITIES);
            let (mut stream, _) = listener.accept().unwrap();
            let (headers, body) = read_request_with_body(&mut stream);
            assert!(headers.starts_with("PUT /ocs/v2.php/apps/files_sharing/api/v1/shares/ocs-group-grant?format=json HTTP/1.1"));
            assert!(body.contains("permissions=15"));
            assert!(body.contains("expireDate="));
            respond(
                &mut stream,
                "200 OK",
                r#"{"ocs":{"meta":{"status":"ok","statuscode":100},"data":[]}}"#,
            );
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            let changed = OCS_GROUP_ROW.replace("2035-10-28T03:30:17Z", "");
            respond(&mut stream, "200 OK", &changed);
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(&mut stream, "200 OK", SHARE_CAPABILITIES);
        });
        let row = parse_owned_share(&serde_json::from_str::<Value>(
            r#"{"id":"ocs-group-grant","share_type":1,"path":"/Projects","item_source":"space!resource-folder","space_id":"space!resource-root","item_type":"folder","permissions":15,"expiration":"2035-10-28T03:30:17Z","uid_owner":"owner-id","share_with":"group-7","share_with_displayname":"Editors","name":""}"#,
        ).unwrap()).unwrap();
        let result = client(addr)
            .update_owned_share(
                "account-1",
                ShareInventoryCategory::SharedByMe,
                "ocs-group-grant",
                "space!resource-folder",
                &baseline_for(&row),
                &OwnedShareUpdate::UserOrGroup {
                    permissions: None,
                    expiration: ExpirationUpdate::Clear,
                },
            )
            .unwrap();
        assert_eq!(result.outcome, OwnedShareUpdateOutcome::Updated);
        assert_eq!(result.settings.unwrap().share.permissions, Some(15));
        worker.join().unwrap();
    }

    #[test]
    fn invalid_access_update_never_reaches_put() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let observer = listener.try_clone().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(&mut stream, "200 OK", OCS_ROWS);
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(&mut stream, "200 OK", SHARE_CAPABILITIES);
        });
        let row = fixture_owned_row("ocs-user-grant");
        let result = client(addr).update_owned_share(
            "account-1",
            ShareInventoryCategory::SharedByMe,
            "ocs-user-grant",
            "space!resource-file",
            &baseline_for(&row),
            &OwnedShareUpdate::UserOrGroup {
                permissions: Some(99),
                expiration: ExpirationUpdate::Keep,
            },
        );
        assert!(result.is_err());
        worker.join().unwrap();
        observer.set_nonblocking(true).unwrap();
        assert!(
            matches!(observer.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }

    #[test]
    fn malformed_expiration_never_reaches_put() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let observer = listener.try_clone().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(&mut stream, "200 OK", OCS_ROWS);
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            respond(&mut stream, "200 OK", SHARE_CAPABILITIES);
        });
        let row = fixture_owned_row("ocs-user-grant");
        let result = client(addr).update_owned_share(
            "account-1",
            ShareInventoryCategory::SharedByMe,
            "ocs-user-grant",
            "space!resource-file",
            &baseline_for(&row),
            &OwnedShareUpdate::UserOrGroup {
                permissions: None,
                expiration: ExpirationUpdate::Set {
                    value: "tomorrow".into(),
                },
            },
        );
        assert!(result.is_err());
        worker.join().unwrap();
        observer.set_nonblocking(true).unwrap();
        assert!(
            matches!(observer.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }

    #[test]
    fn dropped_update_ack_is_unknown_and_is_never_retried() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let api = client(addr);
        let updater = thread::spawn(move || {
            let row = fixture_owned_row("ocs-user-grant");
            api.update_owned_share(
                "account-1",
                ShareInventoryCategory::SharedByMe,
                "ocs-user-grant",
                "space!resource-file",
                &baseline_for(&row),
                &OwnedShareUpdate::UserOrGroup {
                    permissions: Some(3),
                    expiration: ExpirationUpdate::Keep,
                },
            )
        });
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        respond(&mut stream, "200 OK", OCS_ROWS);
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        respond(&mut stream, "200 OK", SHARE_CAPABILITIES);
        let (mut stream, _) = listener.accept().unwrap();
        let (headers, _) = read_request_with_body(&mut stream);
        assert!(headers.starts_with(
            "PUT /ocs/v2.php/apps/files_sharing/api/v1/shares/ocs-user-grant?format=json HTTP/1.1"
        ));
        drop(stream);
        let result = updater.join().unwrap().unwrap_err();
        assert_eq!(result.kind, ErrorKind::Offline);
        assert!(result.message.contains("outcome is unknown"));
        listener.set_nonblocking(true).unwrap();
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
}

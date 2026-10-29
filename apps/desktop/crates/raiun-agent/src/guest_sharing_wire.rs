//! Account-bound sender requests. No invitation secrets or guest cookies enter this API.
use raiun_core::backend::{CloudError, ErrorKind};
use raiun_opencloud::OpenCloudClient;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub action: String,
    pub profile_id: String,
    pub expected_auth_generation: u64,
    space_id: String,
    path: String,
    expected_item_id: Option<String>,
    email: Option<String>,
    role_id: Option<String>,
    permission_id: Option<String>,
    expiration_date_time: Option<String>,
}

impl Request {
    pub fn parse(value: &Value) -> Result<Self, String> {
        let request: Self =
            serde_json::from_value(value.clone()).map_err(|_| "Invalid guest access request")?;
        if !matches!(
            request.action.as_str(),
            "guest_permissions" | "guest_invite" | "guest_update" | "guest_revoke"
        ) || request.profile_id.is_empty()
            || request.profile_id.len() > 256
            || request.space_id.is_empty()
            || request.space_id.len() > 4096
            || request.path.len() > 16_384
            || !request.path.starts_with('/')
            || request.path.trim_matches('/').is_empty()
            || request.path.chars().any(char::is_control)
        {
            return Err("Choose an ordinary file or folder for guest access".into());
        }
        if request.mutating()
            && request
                .expected_item_id
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return Err("Refresh guest access before changing an invitation".into());
        }
        if matches!(request.action.as_str(), "guest_invite" | "guest_update")
            && request.role_id.as_deref().is_none_or(str::is_empty)
        {
            return Err("Choose a server-provided guest role".into());
        }
        if request.action == "guest_invite" && request.email.as_deref().is_none_or(str::is_empty) {
            return Err("Enter the invitation recipient".into());
        }
        if matches!(request.action.as_str(), "guest_update" | "guest_revoke")
            && request.permission_id.as_deref().is_none_or(str::is_empty)
        {
            return Err("Choose a guest invitation".into());
        }
        Ok(request)
    }

    pub fn mutating(&self) -> bool {
        self.action != "guest_permissions"
    }

    pub fn execute(&self, client: &OpenCloudClient) -> Result<Value, String> {
        client.with_guest_sharing_deadline(|| self.execute_scoped(client))
    }

    fn execute_scoped(&self, client: &OpenCloudClient) -> Result<Value, String> {
        let available = match client.guest_sharing_capabilities() {
            Ok(flags) => flags.files_sharing_enabled && flags.guest_links_enabled,
            Err(error) if error.kind == ErrorKind::Unsupported => false,
            Err(error) => return Err(error_text(error, false)),
        };
        if !available {
            if self.mutating() {
                return Err("Guest invitations are unavailable on this server".into());
            }
            return Ok(
                json!({"profile_id": self.profile_id, "auth_generation": self.expected_auth_generation,
                "available":false,"item_id":"","guests":[],"roles":[]}),
            );
        }
        let target = client
            .guest_share_target(&self.space_id, &self.path)
            .map_err(|e| error_text(e, false))?;
        if self.mutating() && self.expected_item_id.as_deref() != Some(target.item_id()) {
            return Err(
                "This file or folder changed; refresh guest access before continuing".into(),
            );
        }
        // Mutations return an acknowledgement only. A separate explicit refresh
        // must not make a successful email/revoke appear to have failed.
        match self.action.as_str() {
            "guest_invite" => {
                client
                    .invite_guest(
                        &target,
                        self.email.as_deref().unwrap_or_default(),
                        self.role_id.as_deref().unwrap_or_default(),
                        self.expiration_date_time.as_deref(),
                    )
                    .map_err(|e| error_text(e, true))?;
            }
            "guest_update" => {
                client
                    .update_guest(
                        &target,
                        self.permission_id.as_deref().unwrap_or_default(),
                        self.role_id.as_deref().unwrap_or_default(),
                        self.expiration_date_time.as_deref(),
                    )
                    .map_err(|e| error_text(e, true))?;
            }
            "guest_revoke" => {
                client
                    .revoke_guest(&target, self.permission_id.as_deref().unwrap_or_default())
                    .map_err(|e| error_text(e, true))?;
            }
            "guest_permissions" => {
                let list = client
                    .guest_permissions(&target)
                    .map_err(|e| error_text(e, false))?;
                return Ok(
                    json!({"profile_id":self.profile_id,"auth_generation":self.expected_auth_generation,
                    "available":true,"item_id":target.item_id(),"guests":list.guests,"roles":list.roles}),
                );
            }
            _ => return Err("Invalid guest access action".into()),
        }
        Ok(
            json!({"profile_id":self.profile_id,"auth_generation":self.expected_auth_generation,"accepted":true}),
        )
    }
}

fn error_text(error: CloudError, mutating: bool) -> String {
    match error.kind {
        ErrorKind::Forbidden => "Server denied guest access".into(),
        ErrorKind::Unauthorized => "Reconnect this account before managing guest access".into(),
        ErrorKind::Unsupported => "Guest invitations are unavailable on this server or item".into(),
        ErrorKind::NotFound => "This item or guest invitation is no longer available".into(),
        ErrorKind::Offline | ErrorKind::InvalidResponse if mutating => "The invitation result could not be confirmed. Refresh guest access before trying again; the server may already have applied the change".into(),
        ErrorKind::Offline => "Could not connect to load guest access".into(),
        _ => "Could not complete guest access. Refresh the item and review the server's roles and expiration settings".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mutations_require_exact_profile_generation_target_and_selection() {
        let mut request = json!({"action":"guest_invite","profile_id":"p","expected_auth_generation":2,"space_id":"s","path":"/file","email":"g@example.test","role_id":"role"});
        assert!(Request::parse(&request).is_err());
        request["expected_item_id"] = json!("resource");
        assert!(Request::parse(&request).unwrap().mutating());
        request["path"] = json!("/");
        assert!(Request::parse(&request).is_err());
        request["path"] = json!("/file");
        request["token"] = json!("not-an-account-token");
        assert!(Request::parse(&request).is_err());
    }
    #[test]
    fn unavailable_is_distinct_from_denial_and_uncertain_mutations() {
        assert!(
            error_text(
                CloudError::new(ErrorKind::Forbidden, "private-server-details"),
                false
            )
            .contains("denied")
        );
        assert!(
            error_text(
                CloudError::new(ErrorKind::Unsupported, "private-server-details"),
                false
            )
            .contains("unavailable")
        );
        assert!(
            error_text(
                CloudError::new(ErrorKind::Offline, "private-server-details"),
                true
            )
            .contains("already")
        );
        assert!(
            !error_text(
                CloudError::new(ErrorKind::Offline, "private-server-details"),
                true
            )
            .contains("private-server")
        );
    }
}

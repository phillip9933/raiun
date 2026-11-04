//! Account-bound ordinary sharing operations. Guest grants keep their separate wire API.
use raiun_core::backend::{CloudError, ErrorKind};
use raiun_opencloud::{
    OpenCloudClient,
    guest_permissions::OrdinaryRecipientKind,
    sharing_inventory::{OwnedShareBaseline, OwnedShareUpdate},
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub action: String,
    pub profile_id: String,
    pub expected_auth_generation: u64,
    space_id: Option<String>,
    path: Option<String>,
    expected_item_id: Option<String>,
    role_id: Option<String>,
    permission_id: Option<String>,
    recipient_id: Option<String>,
    recipient_kind: Option<OrdinaryRecipientKind>,
    link_type: Option<String>,
    display_name: Option<String>,
    expiration_date_time: Option<String>,
    password: Option<String>,
    query: Option<String>,
    inventory: Option<String>,
    expected_resource_id: Option<String>,
    baseline: Option<OwnedShareBaseline>,
    update: Option<OwnedShareUpdate>,
}
impl Request {
    // Unix account routing extracts the raw password into a wiping owner
    // before resolving profiles. Transfer that allocation into this typed
    // request (whose Drop wipes it), without weakening the vault boundary.
    #[cfg(unix)]
    pub(crate) fn with_public_link_password(
        mut self,
        password: Option<zeroize::Zeroizing<String>>,
    ) -> Result<Self, String> {
        if self.action != "sharing_link_create" || self.password.is_some() {
            return Err("A link password is accepted only when creating a public link".into());
        }
        self.password = password.map(|mut value| std::mem::take(&mut *value));
        if self
            .password
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 72)
        {
            return Err("A link password must contain 1 to 72 UTF-8 bytes".into());
        }
        Ok(self)
    }

    pub fn parse(value: &Value) -> Result<Self, String> {
        if value.get("password").is_some_and(|password| {
            password
                .as_str()
                .is_none_or(|value| value.is_empty() || value.len() > 72)
        }) {
            return Err("A link password must contain 1 to 72 UTF-8 bytes".into());
        }
        let mut fields = value.clone();
        // Own the parser copy before any remaining field can fail validation.
        // The caller retains and wipes its original IPC request separately.
        let password = match fields
            .as_object_mut()
            .and_then(|fields| fields.remove("password"))
        {
            Some(Value::String(value)) => Some(zeroize::Zeroizing::new(value)),
            Some(_) => return Err("A link password must be text".into()),
            None => None,
        };
        let mut r: Self = serde_json::from_value(fields).map_err(|_| "Invalid sharing request")?;
        r.password = password.map(|mut value| std::mem::take(&mut *value));
        if !matches!(
            r.action.as_str(),
            "sharing_capabilities"
                | "sharing_inventory"
                | "sharing_owned_settings"
                | "sharing_owned_update"
                | "sharing_owned_revoke"
                | "sharing_permissions"
                | "sharing_recipients"
                | "sharing_invite"
                | "sharing_update"
                | "sharing_revoke"
                | "sharing_link_create"
                | "sharing_link_revoke"
        ) || !valid(&r.profile_id, 256)
        {
            return Err("Invalid sharing request".into());
        }
        if !matches!(
            r.action.as_str(),
            "sharing_capabilities"
                | "sharing_recipients"
                | "sharing_inventory"
                | "sharing_owned_settings"
                | "sharing_owned_update"
                | "sharing_owned_revoke"
        ) && (!r.space_id.as_deref().is_some_and(|s| valid(s, 4096))
            || !r.path.as_deref().is_some_and(|p| {
                valid(p, 16_384) && p.starts_with('/') && !p.trim_matches('/').is_empty()
            }))
        {
            return Err("Choose an ordinary file or folder".into());
        }
        if r.action == "sharing_inventory"
            && !matches!(
                r.inventory.as_deref(),
                Some("with-me" | "by-me" | "public-links")
            )
        {
            return Err("Choose a sharing list".into());
        }
        if matches!(
            r.action.as_str(),
            "sharing_owned_revoke" | "sharing_owned_settings" | "sharing_owned_update"
        ) && (!matches!(r.inventory.as_deref(), Some("by-me" | "public-links"))
            || !r.permission_id.as_deref().is_some_and(|s| valid(s, 8192))
            || !r
                .expected_resource_id
                .as_deref()
                .is_some_and(|s| valid(s, 8192)))
        {
            return Err("Refresh the owned share before managing access".into());
        }
        if r.mutating()
            && !matches!(
                r.action.as_str(),
                "sharing_owned_revoke" | "sharing_owned_update"
            )
            && !r
                .expected_item_id
                .as_deref()
                .is_some_and(|s| valid(s, 4096))
        {
            return Err("Refresh this item before changing access".into());
        }
        if matches!(r.action.as_str(), "sharing_invite" | "sharing_update")
            && !r.role_id.as_deref().is_some_and(|s| valid(s, 4096))
        {
            return Err("Choose a server-provided permission".into());
        }
        if matches!(
            r.action.as_str(),
            "sharing_update" | "sharing_revoke" | "sharing_link_revoke"
        ) && !r.permission_id.as_deref().is_some_and(|s| valid(s, 4096))
        {
            return Err("Choose a current share".into());
        }
        if r.action == "sharing_invite"
            && (r.recipient_kind.is_none()
                || !r.recipient_id.as_deref().is_some_and(|s| valid(s, 4096)))
        {
            return Err("Choose a server user or group".into());
        }
        if r.action == "sharing_link_create"
            && !r.link_type.as_deref().is_some_and(|s| valid(s, 128))
        {
            return Err("Choose a link permission".into());
        }
        if r.password.as_ref().is_some_and(|password| {
            r.action != "sharing_link_create" || password.is_empty() || password.len() > 72
        }) {
            return Err("A link password is accepted only when creating a public link and must contain 1 to 72 UTF-8 bytes".into());
        }
        if r.action == "sharing_owned_update" && (r.baseline.is_none() || r.update.is_none()) {
            return Err("Refresh this share before changing its settings".into());
        }
        if r.query
            .as_deref()
            .is_some_and(|s| s.len() > 256 || s.chars().any(char::is_control))
        {
            return Err("Search text is invalid".into());
        }
        Ok(r)
    }
    pub fn mutating(&self) -> bool {
        !matches!(
            self.action.as_str(),
            "sharing_capabilities"
                | "sharing_permissions"
                | "sharing_recipients"
                | "sharing_inventory"
                | "sharing_owned_settings"
        )
    }
    pub fn execute(&self, client: &OpenCloudClient) -> Result<Value, String> {
        client.with_guest_sharing_deadline(|| self.execute_scoped(client))
    }
    fn execute_scoped(&self, client: &OpenCloudClient) -> Result<Value, String> {
        if matches!(
            self.action.as_str(),
            "sharing_owned_settings" | "sharing_owned_update"
        ) {
            use raiun_opencloud::sharing_inventory::{
                OwnedShareUpdateOutcome, ShareInventoryCategory,
            };
            let category = match self.inventory.as_deref() {
                Some("by-me") => ShareInventoryCategory::SharedByMe,
                Some("public-links") => ShareInventoryCategory::PublicLinks,
                _ => return Err("Choose an owned sharing list".into()),
            };
            let id = self.permission_id.as_deref().unwrap_or_default();
            let resource = self.expected_resource_id.as_deref().unwrap_or_default();
            if self.action == "sharing_owned_settings" {
                let settings = client
                    .get_owned_share_edit_settings(&self.profile_id, category, id, resource)
                    .map_err(|e| error_text(e, false))?;
                return Ok(
                    json!({"profile_id":self.profile_id,"auth_generation":self.expected_auth_generation,
                    "inventory":self.inventory,"read_only":true,"settings":settings}),
                );
            }
            let outcome = client
                .update_owned_share(
                    &self.profile_id,
                    category,
                    id,
                    resource,
                    self.baseline.as_ref().ok_or("Refresh share settings")?,
                    self.update.as_ref().ok_or("Review share settings")?,
                )
                .map_err(|e| error_text(e, true))?;
            if outcome.outcome != OwnedShareUpdateOutcome::Updated {
                return Err("Could not confirm the sharing result. Refresh before trying again; the server may have applied the change".into());
            }
            return Ok(
                json!({"profile_id":self.profile_id,"auth_generation":self.expected_auth_generation,"accepted":true}),
            );
        }
        if self.action == "sharing_owned_revoke" {
            use raiun_opencloud::sharing_inventory::ShareInventoryCategory;
            let category = match self.inventory.as_deref() {
                Some("by-me") => ShareInventoryCategory::SharedByMe,
                Some("public-links") => ShareInventoryCategory::PublicLinks,
                _ => return Err("Choose an owned sharing list".into()),
            };
            client
                .revoke_owned_share(
                    &self.profile_id,
                    category,
                    self.permission_id.as_deref().unwrap_or_default(),
                    self.expected_resource_id.as_deref().unwrap_or_default(),
                )
                .map_err(|e| error_text(e, true))?;
            return Ok(
                json!({"profile_id":self.profile_id,"auth_generation":self.expected_auth_generation,"accepted":true}),
            );
        }
        if self.action == "sharing_inventory" {
            use raiun_opencloud::sharing_inventory::ShareInventoryCategory;
            let inventory = self.inventory.as_deref().ok_or("Choose a sharing list")?;
            let snapshot = match inventory {
                "with-me" => serde_json::to_value(
                    client
                        .list_incoming_shares(&self.profile_id)
                        .map_err(|e| error_text(e, false))?,
                ),
                "by-me" => serde_json::to_value(
                    client
                        .list_owned_shares(&self.profile_id, ShareInventoryCategory::SharedByMe)
                        .map_err(|e| error_text(e, false))?,
                ),
                "public-links" => serde_json::to_value(
                    client
                        .list_owned_shares(&self.profile_id, ShareInventoryCategory::PublicLinks)
                        .map_err(|e| error_text(e, false))?,
                ),
                _ => return Err("Choose a sharing list".into()),
            }
            .map_err(|_| "Sharing list could not be represented")?;
            if serde_json::to_vec(&snapshot)
                .map_err(|_| "Sharing list could not be represented")?
                .len()
                > 900_000
            {
                return Err("This sharing list is too large for the current Desktop view; no partial list was accepted".into());
            }
            return Ok(
                json!({"profile_id":self.profile_id,"auth_generation":self.expected_auth_generation,
                "inventory":inventory,"read_only":true,"snapshot":snapshot}),
            );
        }
        let caps = client
            .sharing_capabilities()
            .map_err(|e| error_text(e, false))?;
        if self.action == "sharing_capabilities" {
            let guests = client
                .guest_sharing_capabilities()
                .map(|c| c.files_sharing_enabled && c.guest_links_enabled)
                .unwrap_or(false);

            return Ok(
                json!({"profile_id":self.profile_id,"auth_generation":self.expected_auth_generation,
                "capabilities":caps,"guest_invitations":guests,"coverage":"item"}),
            );
        }
        if !caps.files_sharing_enabled {
            return Err("File sharing is unavailable on this server".into());
        }
        if self.action == "sharing_recipients" {
            // Directory lookup is added by the protocol adapter; never accept a URL from IPC.
            return self.recipients(client);
        }
        let target = client
            .guest_share_target(
                self.space_id.as_deref().unwrap_or_default(),
                self.path.as_deref().unwrap_or_default(),
            )
            .map_err(|e| error_text(e, false))?;
        if self.mutating() && self.expected_item_id.as_deref() != Some(target.item_id()) {
            return Err("This item changed; refresh its shares before continuing".into());
        }
        match self.action.as_str() {
            "sharing_permissions" => {
                let data = client
                    .ordinary_sharing_permissions(&target)
                    .map_err(|e| error_text(e, false))?;
                return Ok(
                    json!({"profile_id":self.profile_id,"auth_generation":self.expected_auth_generation,
                    "item_id":target.item_id(),"coverage":"item","permissions":data,
                    "link_types":if caps.public_link_creation_supported { client.supported_public_link_types(&target).map_err(|e|error_text(e,false))? } else { Vec::<String>::new() }}),
                );
            }
            "sharing_invite" => {
                client
                    .invite_ordinary(
                        &target,
                        self.recipient_kind.ok_or("Choose a recipient")?,
                        self.recipient_id.as_deref().unwrap_or_default(),
                        self.role_id.as_deref().unwrap_or_default(),
                        self.expiration_date_time.as_deref(),
                    )
                    .map_err(|e| error_text(e, true))?;
            }
            "sharing_update" => {
                client
                    .update_ordinary_role(
                        &target,
                        self.permission_id.as_deref().unwrap_or_default(),
                        self.role_id.as_deref().unwrap_or_default(),
                    )
                    .map_err(|e| error_text(e, true))?;
            }
            "sharing_revoke" => {
                client
                    .revoke_ordinary(&target, self.permission_id.as_deref().unwrap_or_default())
                    .map_err(|e| error_text(e, true))?;
            }
            "sharing_link_create" => {
                client
                    .create_public_link_with_password(
                        &target,
                        self.link_type.as_deref().unwrap_or_default(),
                        self.display_name.as_deref(),
                        self.expiration_date_time.as_deref(),
                        self.password.as_deref(),
                    )
                    .map_err(|e| error_text(e, true))?;
            }
            "sharing_link_revoke" => {
                client
                    .revoke_public_link(&target, self.permission_id.as_deref().unwrap_or_default())
                    .map_err(|e| error_text(e, true))?;
            }
            _ => return Err("Invalid sharing request".into()),
        }
        Ok(
            json!({"profile_id":self.profile_id,"auth_generation":self.expected_auth_generation,"accepted":true}),
        )
    }
    fn recipients(&self, client: &OpenCloudClient) -> Result<Value, String> {
        let query = self.query.as_deref().unwrap_or_default();
        let kind = self
            .recipient_kind
            .ok_or("Choose users or groups to search")?;
        let rows = client
            .search_ordinary_recipients(query, kind)
            .map_err(|e| error_text(e, false))?;
        Ok(
            json!({"profile_id":self.profile_id,"auth_generation":self.expected_auth_generation,"recipients":rows}),
        )
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(password) = &mut self.password {
            password.zeroize();
        }
    }
}
fn valid(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn error_text(e: CloudError, mutating: bool) -> String {
    let status = sharing_http_status(&e.message)
        .map(|status| format!(" (HTTP {status})"))
        .unwrap_or_default();
    match e.kind {
        ErrorKind::Forbidden => "Server denied this sharing operation".into(),
        ErrorKind::Unauthorized => "Reconnect this account before managing sharing".into(),
        ErrorKind::Unsupported => {
            "This sharing operation is unavailable for this server or item".into()
        }
        ErrorKind::NotFound => "This item or share is no longer available".into(),
        _ if mutating => format!(
            "Could not confirm the sharing result. Refresh before trying again; the server may have applied the change{status}"
        ),
        _ => format!("Could not load sharing. Check the connection and refresh{status}"),
    }
}

// Preserve only the status from our HTTP adapter's fixed message format. Never
// expose the upstream body, URL, error code, request identifier or credential.
fn sharing_http_status(message: &str) -> Option<u16> {
    let rest = message
        .strip_prefix("OpenCloud WebDAV request failed with HTTP ")
        .or_else(|| message.strip_prefix("OpenCloud Graph discovery request failed with HTTP "))?;
    let code = rest.split_whitespace().next()?;
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    code.parse()
        .ok()
        .filter(|value| (100..=599).contains(value))
}
#[cfg(test)]
mod tests {
    use super::*;
    use raiun_opencloud::ProxyConfig;
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread,
    };

    #[test]
    fn password_input_is_creation_only_and_bounded_by_utf8_bytes() {
        let mut request = json!({"action":"sharing_link_create","profile_id":"p","expected_auth_generation":2,
            "space_id":"space","path":"/test","expected_item_id":"item","link_type":"view","password":"synthetic-secret"});
        assert!(Request::parse(&request).is_ok());
        request["password"] = json!("é".repeat(36));
        assert!(Request::parse(&request).is_ok());
        for invalid in [json!("é".repeat(37)), json!(""), Value::Null, json!(false)] {
            request["password"] = invalid;
            let error = Request::parse(&request).err().unwrap();
            assert!(!error.contains('é'));
        }
        request["password"] = json!("synthetic-secret");
        request["action"] = json!("sharing_link_revoke");
        request["permission_id"] = json!("grant");
        let error = Request::parse(&request).err().unwrap();
        assert!(!error.contains("synthetic-secret"));
    }

    #[test]
    fn sharing_failure_preserves_only_http_status_and_uncertain_outcome() {
        for mutating in [false, true] {
            let error = error_text(
                CloudError::new(
                    ErrorKind::InvalidResponse,
                    "OpenCloud WebDAV request failed with HTTP 400 (code=private-body request_id=private-id https://private.example/s/private-link)",
                ),
                mutating,
            );
            assert!(error.ends_with("(HTTP 400)"));
            assert!(!error.contains("private"));
            if mutating {
                assert!(error.contains("server may have applied the change"));
            }
        }
        assert_eq!(sharing_http_status("untrusted HTTP 400 secret"), None);
        assert_eq!(
            sharing_http_status("OpenCloud WebDAV request failed with HTTP 400secret"),
            None
        );
        assert_eq!(
            sharing_http_status("OpenCloud WebDAV request failed with HTTP 999"),
            None
        );
    }

    fn read_request(stream: &mut TcpStream) -> (String, String) {
        let mut header = Vec::new();
        let mut byte = [0; 1];
        while !header.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
            assert!(header.len() < 16 * 1024);
        }
        let header = String::from_utf8(header).unwrap();
        let body_len = header
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let mut body = vec![0; body_len];
        stream.read_exact(&mut body).unwrap();
        (header, String::from_utf8(body).unwrap())
    }

    fn respond(stream: &mut TcpStream, status: &str, body: &str) {
        write!(stream,"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        stream.flush().unwrap();
    }

    const OCS_OWNED: &str = r#"{"ocs":{"meta":{"status":"ok","statuscode":100},"data":[{"id":"ocs-user-1","share_type":0,"path":"/Docs/Plan.txt","item_source":"space!resource-1","space_id":"space!root","item_type":"file","permissions":1,"expiration":"","uid_owner":"owner","share_with":"member-1","share_with_displayname":"Ada","name":""}]}}"#;
    const OCS_OWNED_EDITED: &str = r#"{"ocs":{"meta":{"status":"ok","statuscode":100},"data":[{"id":"ocs-user-1","share_type":0,"path":"/Docs/Plan.txt","item_source":"space!resource-1","space_id":"space!root","item_type":"file","permissions":3,"expiration":"","uid_owner":"owner","share_with":"member-1","share_with_displayname":"Ada","name":""}]}}"#;
    const OCS_CAPABILITIES: &str = r#"{"ocs":{"meta":{"status":"ok","statuscode":100},"data":{"capabilities":{"files_sharing":{"api_enabled":true,"group_sharing":true,"public":{"enabled":true,"password":{"enforced":false},"expire_date":{"enabled":true,"enforced":false}}}}}}}"#;
    #[test]
    fn malformed_or_unbound_mutations_are_refused() {
        let base = json!({"action":"sharing_invite","profile_id":"p","expected_auth_generation":3,"space_id":"space","path":"/notes","recipient_id":"u","recipient_kind":"user","role_id":"view"});
        assert!(Request::parse(&base).is_err());
        let mut good = base.clone();
        good["expected_item_id"] = json!("item");
        assert!(Request::parse(&good).unwrap().mutating());
        for (key, v) in [
            ("profile_id", json!("")),
            ("path", json!("/")),
            ("recipient_id", json!("")),
            ("expected_auth_generation", json!(null)),
            ("unknown", json!(true)),
        ] {
            let mut bad = good.clone();
            bad[key] = v;
            assert!(Request::parse(&bad).is_err(), "{key}");
        }
    }
    #[test]
    fn inventory_is_read_only_and_owned_revoke_has_its_own_resource_binding() {
        let read = json!({"action":"sharing_inventory","profile_id":"p","expected_auth_generation":2,"inventory":"with-me"});
        assert!(!Request::parse(&read).unwrap().mutating());
        let mut revoke = json!({"action":"sharing_owned_revoke","profile_id":"p","expected_auth_generation":2,"inventory":"by-me","permission_id":"ocs-id","expected_resource_id":"resource"});
        assert!(Request::parse(&revoke).unwrap().mutating());
        revoke["inventory"] = json!("with-me");
        assert!(Request::parse(&revoke).is_err());
        revoke["inventory"] = json!("by-me");
        revoke["expected_resource_id"] = json!(null);
        assert!(Request::parse(&revoke).is_err());
    }
    #[test]
    fn owned_settings_are_read_only_but_updates_need_typed_changes() {
        let mut r = json!({"action":"sharing_owned_settings","profile_id":"p","expected_auth_generation":2,
            "inventory":"by-me","permission_id":"ocs-id","expected_resource_id":"resource"});
        assert!(!Request::parse(&r).unwrap().mutating());
        r["action"] = json!("sharing_owned_update");
        assert!(Request::parse(&r).is_err());
        r["baseline"] = json!({"ocs_share_id":"ocs-id","resource_id":"resource","kind":{"kind":"user"},
            "recipient_id":"person","permissions":1,"expires_at":null,"label":null,"path":"/notes","file_target":null,"item_type":"file","space_id":null,"owner_id":null});
        r["update"] =
            json!({"kind":"user_or_group","permissions":3,"expiration":{"action":"keep"}});
        assert!(Request::parse(&r).unwrap().mutating());
        r["update"]["expiration"] = json!({"action":"clear"});
        assert!(Request::parse(&r).is_ok());
        r["update"]["password"] = json!("synthetic");
        assert!(Request::parse(&r).is_err());
        r["update"].as_object_mut().unwrap().remove("password");
        r["inventory"] = json!("with-me");
        assert!(Request::parse(&r).is_err());
    }
    #[test]
    fn discovery_is_read_only_and_rejects_credential_fields() {
        let mut r =
            json!({"action":"sharing_capabilities","profile_id":"p","expected_auth_generation":2});
        assert!(!Request::parse(&r).unwrap().mutating());
        r["access_token"] = json!("synthetic");
        assert!(Request::parse(&r).is_err());
    }

    #[test]
    fn owned_settings_update_and_revoke_execute_through_the_wire_with_fresh_ocs_binding() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let serve_get = |expected: &str, body: &str| {
                let (mut stream, _) = listener.accept().unwrap();
                let (headers, _) = read_request(&mut stream);
                assert!(
                    headers.starts_with(expected),
                    "unexpected request: {headers}"
                );
                respond(&mut stream, "200 OK", body);
            };
            let (mut stream, _) = listener.accept().unwrap();
            let (headers, _) = read_request(&mut stream);
            assert!(headers.starts_with(
                "GET /ocs/v2.php/apps/files_sharing/api/v1/shares?format=json HTTP/1.1"
            ));
            respond(&mut stream, "200 OK", OCS_OWNED);
            serve_get(
                "GET /ocs/v1.php/cloud/capabilities?format=json HTTP/1.1",
                OCS_CAPABILITIES,
            );

            let (mut stream, _) = listener.accept().unwrap();
            let (headers, _) = read_request(&mut stream);
            assert!(headers.starts_with(
                "GET /ocs/v2.php/apps/files_sharing/api/v1/shares?format=json HTTP/1.1"
            ));
            respond(&mut stream, "200 OK", OCS_OWNED);
            serve_get(
                "GET /ocs/v1.php/cloud/capabilities?format=json HTTP/1.1",
                OCS_CAPABILITIES,
            );
            let (mut stream, _) = listener.accept().unwrap();
            let (headers, body) = read_request(&mut stream);
            assert!(headers.starts_with(
                "PUT /ocs/v2.php/apps/files_sharing/api/v1/shares/ocs-user-1?format=json HTTP/1.1"
            ));
            assert!(body.contains("permissions=3"));
            assert!(!body.contains("password"));
            respond(
                &mut stream,
                "200 OK",
                r#"{"ocs":{"meta":{"status":"ok","statuscode":100},"data":[]}}"#,
            );
            let (mut stream, _) = listener.accept().unwrap();
            let (headers, _) = read_request(&mut stream);
            assert!(headers.starts_with(
                "GET /ocs/v2.php/apps/files_sharing/api/v1/shares?format=json HTTP/1.1"
            ));
            respond(&mut stream, "200 OK", OCS_OWNED_EDITED);
            serve_get(
                "GET /ocs/v1.php/cloud/capabilities?format=json HTTP/1.1",
                OCS_CAPABILITIES,
            );

            let (mut stream, _) = listener.accept().unwrap();
            let (headers, _) = read_request(&mut stream);
            assert!(headers.starts_with(
                "GET /ocs/v2.php/apps/files_sharing/api/v1/shares?format=json HTTP/1.1"
            ));
            respond(&mut stream, "200 OK", OCS_OWNED_EDITED);
            let (mut stream, _) = listener.accept().unwrap();
            let (headers, _) = read_request(&mut stream);
            assert!(headers.starts_with("DELETE /ocs/v2.php/apps/files_sharing/api/v1/shares/ocs-user-1?format=json HTTP/1.1"));
            respond(&mut stream, "204 No Content", "");
        });

        let client = OpenCloudClient::new_for_guest_sharing(
            &format!("http://{addr}/"),
            "synthetic-token".into(),
            &ProxyConfig::Direct,
        )
        .unwrap();
        let settings_request = Request::parse(&json!({
            "action":"sharing_owned_settings","profile_id":"account-a","expected_auth_generation":7,
            "inventory":"by-me","permission_id":"ocs-user-1","expected_resource_id":"space!resource-1"
        })).unwrap();
        let settings = settings_request.execute(&client).unwrap();
        assert_eq!(
            settings["settings"]["baseline"]["ocs_share_id"],
            "ocs-user-1"
        );
        assert_eq!(settings["settings"]["baseline"]["recipient_id"], "member-1");
        assert_eq!(
            settings["settings"]["share"]["resource_id"],
            "space!resource-1"
        );

        let update_request = Request::parse(&json!({
            "action":"sharing_owned_update","profile_id":"account-a","expected_auth_generation":7,
            "inventory":"by-me","permission_id":"ocs-user-1","expected_resource_id":"space!resource-1",
            "baseline":settings["settings"]["baseline"],
            "update":{"kind":"user_or_group","permissions":3,"expiration":{"action":"keep"}}
        })).unwrap();
        let updated = update_request.execute(&client).unwrap();
        assert_eq!(updated["accepted"], true);

        let revoke_request = Request::parse(&json!({
            "action":"sharing_owned_revoke","profile_id":"account-a","expected_auth_generation":7,
            "inventory":"by-me","permission_id":"ocs-user-1","expected_resource_id":"space!resource-1"
        })).unwrap();
        let revoked = revoke_request.execute(&client).unwrap();
        assert_eq!(revoked["accepted"], true);
        worker.join().unwrap();
    }

    #[test]
    fn owned_update_lost_ack_is_reported_unknown_without_an_automatic_retry() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let observer = listener.try_clone().unwrap();
        let client = OpenCloudClient::new_for_guest_sharing(
            &format!("http://{addr}/"),
            "synthetic-token".into(),
            &ProxyConfig::Direct,
        )
        .unwrap();
        let worker = thread::spawn(move || {
            let accept = || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && std::time::Instant::now() < deadline =>
                        {
                            thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(error) => panic!("fixture failed to accept request: {error}"),
                    }
                }
            };
            let (mut stream, _) = accept();
            let (headers, _) = read_request(&mut stream);
            assert!(headers.starts_with(
                "GET /ocs/v2.php/apps/files_sharing/api/v1/shares?format=json HTTP/1.1"
            ));
            respond(&mut stream, "200 OK", OCS_OWNED);
            let (mut stream, _) = accept();
            let (headers, _) = read_request(&mut stream);
            assert!(headers.starts_with("GET /ocs/v1.php/cloud/capabilities?format=json HTTP/1.1"));
            respond(&mut stream, "200 OK", OCS_CAPABILITIES);
            let mut saw_list = false;
            let mut saw_capabilities = false;
            loop {
                let (mut stream, _) = accept();
                let (headers, body) = read_request(&mut stream);
                if headers.starts_with(
                    "PUT /ocs/v2.php/apps/files_sharing/api/v1/shares/ocs-user-1?format=json HTTP/1.1",
                ) {
                    assert!(saw_list && saw_capabilities);
                    assert!(body.contains("permissions=3"));
                    drop(stream);
                    break;
                } else if headers.starts_with(
                    "GET /ocs/v2.php/apps/files_sharing/api/v1/shares?format=json HTTP/1.1",
                ) {
                    saw_list = true;
                    respond(&mut stream, "200 OK", OCS_OWNED);
                } else if headers
                    .starts_with("GET /ocs/v1.php/cloud/capabilities?format=json HTTP/1.1")
                {
                    saw_capabilities = true;
                    respond(&mut stream, "200 OK", OCS_CAPABILITIES);
                } else {
                    panic!("unexpected sharing request in lost-ack fixture");
                }
            }
        });
        let settings_request = Request::parse(&json!({
            "action":"sharing_owned_settings","profile_id":"account-a","expected_auth_generation":7,
            "inventory":"by-me","permission_id":"ocs-user-1","expected_resource_id":"space!resource-1"
        })).unwrap();
        let settings = settings_request.execute(&client).unwrap();
        let request = Request::parse(&json!({
            "action":"sharing_owned_update","profile_id":"account-a","expected_auth_generation":7,
            "inventory":"by-me","permission_id":"ocs-user-1","expected_resource_id":"space!resource-1",
            "baseline":settings["settings"]["baseline"],
            "update":{"kind":"user_or_group","permissions":3,"expiration":{"action":"keep"}}
        })).unwrap();
        let error = request.execute(&client).unwrap_err();
        assert!(error.contains("Could not confirm the sharing result"));
        assert!(error.contains("server may have applied the change"));
        worker.join().unwrap();
        observer.set_nonblocking(true).unwrap();
        assert!(matches!(
            observer.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }
}

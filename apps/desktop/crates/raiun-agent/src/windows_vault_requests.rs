//! Read-only vault metadata request; no secret-bearing actions or route authority.
use raiun_core::validate_remote_path;
use serde_json::{Map, Value};

/// Own the decoded request across every handler error; no secret copies escape.
pub(super) struct OwnedControlRequest {
    value: Value,
    #[cfg(test)]
    wipe_observed: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}
impl OwnedControlRequest {
    pub(super) fn new(value: Value) -> Self {
        Self {
            value,
            #[cfg(test)]
            wipe_observed: None,
        }
    }
    pub(super) fn value(&self) -> &Value {
        &self.value
    }
}
impl Drop for OwnedControlRequest {
    fn drop(&mut self) {
        if let Some(Value::String(password)) = self.value.get_mut("password") {
            zeroize::Zeroize::zeroize(password);
        }
        #[cfg(test)]
        if let Some(observed) = &self.wipe_observed {
            observed.store(
                self.value.get("password").and_then(Value::as_str) == Some(""),
                std::sync::atomic::Ordering::Release,
            );
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultInspectRequest {
    pub space_id: String,
    pub root_path: String,
    pub root_resource_id: Option<String>,
}
fn invalid() -> String {
    "Invalid vault inspection request".into()
}
fn text(fields: &mut Map<String, Value>, key: &str, max: usize) -> Result<String, String> {
    match fields.remove(key) {
        Some(Value::String(value))
            if !value.trim().is_empty()
                && value.len() <= max
                && !value.chars().any(char::is_control) =>
        {
            Ok(value)
        }
        _ => Err(invalid()),
    }
}
pub fn decode(value: &Value) -> Result<VaultInspectRequest, String> {
    let mut fields = value.as_object().cloned().ok_or_else(invalid)?;
    if text(&mut fields, "action", 64)? != "vault_inspect" {
        return Err(invalid());
    }
    // Shape validation only; the agent compares this envelope with its trusted
    // runtime profile before dispatch. The request never selects credentials.
    if fields.contains_key("profile_id") {
        let profile = text(&mut fields, "profile_id", 128)?;
        if !super::valid_runtime_profile(&profile) {
            return Err(invalid());
        }
    }
    let space_id = text(&mut fields, "space_id", 512)?;
    let root_path = text(&mut fields, "root_path", 4096)?;
    validate_remote_path(&root_path).map_err(|_| invalid())?;
    let root_resource_id = if fields.contains_key("root_resource_id") {
        Some(text(&mut fields, "root_resource_id", 4096)?)
    } else {
        None
    };
    if !fields.is_empty() {
        return Err(invalid());
    }
    Ok(VaultInspectRequest {
        space_id,
        root_path,
        root_resource_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn rejected_request_owner_wipes_password_before_release() {
        let observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let rejected = (|| -> Result<(), String> {
            let mut request = OwnedControlRequest::new(
                json!({"action":"vault_unlock","password":"synthetic-test-password"}),
            );
            request.wipe_observed = Some(observed.clone());
            assert!(
                request
                    .value()
                    .get("password")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
            );
            decode(request.value()).map(|_| ())?;
            Ok(())
        })();
        assert!(rejected.is_err());
        assert!(observed.load(std::sync::atomic::Ordering::Acquire));
    }
    #[test]
    fn accepts_exact_folder_or_whole_space_inspection() {
        for root in ["/", "/Photos.vault"] {
            let value = json!({"action":"vault_inspect","space_id":"space","root_path":root});
            assert_eq!(decode(&value).unwrap().root_path, root);
        }
        let value = json!({"action":"vault_inspect","profile_id":"default","space_id":"space","root_path":"/Photos.vault","root_resource_id":"root-id"});
        assert_eq!(
            decode(&value).unwrap().root_resource_id.as_deref(),
            Some("root-id")
        );
    }
    #[test]
    fn refuses_secrets_unknown_fields_bad_types_paths_and_bounds() {
        let base = json!({"action":"vault_inspect","space_id":"space","root_path":"/Photos.vault"});
        for (key, value) in [
            ("password", Value::Null),
            ("use_saved", json!(true)),
            ("remember", json!(true)),
            ("extra", json!(1)),
            ("profile_id", json!("other")),
            ("profile_id", json!(false)),
            ("root_resource_id", Value::Null),
            ("root_resource_id", json!("")),
            ("root_path", json!("/../escape")),
            ("space_id", json!("s".repeat(513))),
            ("root_path", json!("/".to_owned() + &"a".repeat(4096))),
        ] {
            let mut request = base.clone();
            request[key] = value;
            assert_eq!(
                decode(&request).unwrap_err(),
                "Invalid vault inspection request"
            );
        }
        let mut request = base;
        request["action"] = json!("vault_unlock");
        assert!(decode(&request).is_err());
    }
}

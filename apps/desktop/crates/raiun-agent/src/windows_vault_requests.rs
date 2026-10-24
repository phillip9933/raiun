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
    pub(super) fn decode_session(
        mut self,
    ) -> Result<session_requests::VaultSessionRequest, String> {
        session_requests::decode(std::mem::take(&mut self.value))
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

pub(super) mod session_requests {
    // Unexposed request boundary, not authentication or unlock authority.
    // Consumes the incoming JSON and wipes its top-level password string on Drop.
    // Encoded IPC frames and caller-created copies remain outside this ownership.
    use raiun_core::validate_remote_path;
    use serde_json::{Map, Value};
    use zeroize::{Zeroize, Zeroizing};
    pub struct VaultTarget {
        pub profile_id: Option<String>,
        pub space_id: String,
        pub root_path: String,
        pub root_resource_id: String,
    }
    /// No Debug, Clone, or serialization implementation.
    pub struct VaultPassword(Zeroizing<Vec<u8>>);
    impl VaultPassword {
        pub fn as_mut_bytes(&mut self) -> &mut [u8] {
            self.0.as_mut_slice()
        }
    }
    pub enum VaultSessionRequest {
        Unlock {
            target: VaultTarget,
            password: VaultPassword,
        },
        Lock {
            target: VaultTarget,
        },
    }
    // Private ownership prevents a borrowed decoder from silently leaving its input
    // secret behind. Ordinary return, validation error, and unwinding all run Drop.
    struct OwnedRequest(Value);
    impl Drop for OwnedRequest {
        fn drop(&mut self) {
            if let Some(Value::String(password)) = self.0.get_mut("password") {
                password.zeroize();
            }
        }
    }
    fn invalid() -> String {
        "Invalid vault session request".into()
    }
    fn text<'a>(fields: &'a Map<String, Value>, key: &str, max: usize) -> Result<&'a str, String> {
        fields
            .get(key)
            .and_then(Value::as_str)
            .filter(|v| !v.trim().is_empty() && v.len() <= max && !v.chars().any(char::is_control))
            .ok_or_else(invalid)
    }
    fn false_or_absent(fields: &Map<String, Value>, key: &str) -> bool {
        matches!(fields.get(key), None | Some(Value::Bool(false)))
    }
    pub fn decode(value: Value) -> Result<VaultSessionRequest, String> {
        let owned = OwnedRequest(value);
        decode_owned(&owned)
    }
    fn decode_owned(owned: &OwnedRequest) -> Result<VaultSessionRequest, String> {
        let fields = owned.0.as_object().ok_or_else(invalid)?;
        let unlock = match text(fields, "action", 64)? {
            "vault_unlock" => true,
            "vault_lock" => false,
            _ => return Err(invalid()),
        };
        if fields.keys().any(|key| {
            !matches!(
                key.as_str(),
                "action" | "profile_id" | "space_id" | "root_path" | "root_resource_id"
            ) && !(unlock && matches!(key.as_str(), "password" | "remember" | "use_saved"))
        }) {
            return Err(invalid());
        }
        let profile_id = if fields.contains_key("profile_id") {
            let profile = text(fields, "profile_id", 128)?;
            // Shape only; caller must compare with trusted runtime profile.
            if !super::super::valid_runtime_profile(profile) {
                return Err(invalid());
            }
            Some(profile.to_owned())
        } else {
            None
        };
        let space_id = text(fields, "space_id", 512)?;
        let root_path = text(fields, "root_path", 4096)?;
        validate_remote_path(root_path).map_err(|_| invalid())?;
        let root_resource_id = text(fields, "root_resource_id", 512)?;
        // Match VaultSessionScope identifier grammar without normalizing authority.
        if space_id.trim() != space_id || root_resource_id.trim() != root_resource_id {
            return Err(invalid());
        }
        let password = if unlock {
            if !false_or_absent(fields, "remember") || !false_or_absent(fields, "use_saved") {
                return Err(invalid());
            }
            Some(
                fields
                    .get("password")
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty() && v.len() <= 4096)
                    .ok_or_else(invalid)?,
            )
        } else {
            None
        };
        let target = VaultTarget {
            profile_id,
            space_id: space_id.to_owned(),
            root_path: root_path.to_owned(),
            root_resource_id: root_resource_id.to_owned(),
        };
        Ok(match password {
            Some(p) => VaultSessionRequest::Unlock {
                target,
                password: VaultPassword(Zeroizing::new(p.as_bytes().to_vec())),
            },
            None => VaultSessionRequest::Lock { target },
        })
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::json;
        fn decode(value: Value) -> Result<VaultSessionRequest, String> {
            super::super::OwnedControlRequest::new(value).decode_session()
        }
        fn unlock() -> Value {
            json!({"action":"vault_unlock","profile_id":"default","space_id":"space","root_path":"/Photos.vault","root_resource_id":"root","password":"synthetic secret","remember":false})
        }
        #[test]
        fn existing_ui_password_and_lock_shapes() {
            let mut value = unlock();
            value["use_saved"] = json!(false);
            if let VaultSessionRequest::Unlock {
                target,
                mut password,
            } = decode(value).unwrap()
            {
                assert_eq!(target.profile_id.as_deref(), Some("default"));
                assert_eq!(target.space_id, "space");
                assert_eq!(target.root_path, "/Photos.vault");
                assert_eq!(target.root_resource_id, "root");
                assert_eq!(password.as_mut_bytes(), b"synthetic secret");
            } else {
                panic!("wrong variant");
            }
            assert!(
                matches!(decode(json!({"action":"vault_lock","space_id":"s","root_path":"/","root_resource_id":"r"})).unwrap(),VaultSessionRequest::Lock{target} if target.profile_id.is_none())
            );
        }
        #[test]
        fn foreign_shape_unknown_secrets_and_remembered_modes_fail_opaquely() {
            for (key, bad) in [
                ("profile_id", json!("foreign")),
                ("root_path", json!("/../private")),
                ("root_resource_id", json!("")),
                ("root_resource_id", json!(" root ")),
                ("token", json!("sentinel")),
                ("remember", json!(true)),
                ("use_saved", json!(true)),
                ("remember", Value::Null),
                ("space_id", json!(7)),
                ("action", json!("vault_unlock_offline")),
            ] {
                let mut v = unlock();
                v[key] = bad;
                assert_eq!(decode(v).err().unwrap(), "Invalid vault session request");
            }
            for key in ["password", "remember", "use_saved"] {
                let mut v = json!({"action":"vault_lock","space_id":"s","root_path":"/","root_resource_id":"r"});
                v[key] = json!(false);
                assert!(decode(v).is_err());
            }
        }
        #[test]
        fn utf8_byte_identity_bounds_and_types_are_exact() {
            for p in ["x".into(), "é".repeat(2048)] {
                let mut v = unlock();
                v["password"] = json!(p);
                assert!(decode(v).is_ok());
            }
            for p in [
                json!(""),
                json!("é".repeat(2049)),
                json!(false),
                Value::Null,
            ] {
                let mut v = unlock();
                v["password"] = p;
                assert!(decode(v).is_err());
            }
            let mut v = unlock();
            v["profile_id"] = json!(format!("profile-{}", "a".repeat(32)));
            v["root_resource_id"] = json!("r".repeat(512));
            v["space_id"] = json!("s".repeat(512));
            assert!(decode(v.clone()).is_ok());
            for key in ["root_resource_id", "space_id"] {
                let mut bad = v.clone();
                bad[key] = json!("r".repeat(513));
                assert!(decode(bad).is_err());
            }
        }
    }
}

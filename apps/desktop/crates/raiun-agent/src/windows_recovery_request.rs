//! Pure binding validation for an explicitly confirmed saved-edit retry.
//! Parsing grants no upload, record, native-completion or deletion authority.
use serde_json::Value;

pub(crate) fn validate(
    request: &Value,
    profile: &str,
    generation: u64,
    scope_token: &str,
) -> Result<(), &'static str> {
    validate_action(
        request,
        profile,
        generation,
        scope_token,
        "windows_recovery_retry",
    )
}

pub(crate) fn validate_check(
    request: &Value,
    profile: &str,
    generation: u64,
    scope_token: &str,
) -> Result<(), &'static str> {
    validate_action(
        request,
        profile,
        generation,
        scope_token,
        "windows_recovery_check_cloud",
    )
}

fn validate_action(
    request: &Value,
    profile: &str,
    generation: u64,
    scope_token: &str,
    action: &str,
) -> Result<(), &'static str> {
    const ERROR: &str = "Reopen saved edits for the current account and Windows drive";
    let object = request.as_object().ok_or(ERROR)?;
    const KEYS: [&str; 6] = [
        "action",
        "profile_id",
        "expected_generation",
        "expected_recovery_scope_token",
        "record_id",
        "generation",
    ];
    if object.len() != KEYS.len()
        || !KEYS.iter().all(|key| object.contains_key(*key))
        || request["action"].as_str() != Some(action)
        || request["profile_id"].as_str() != Some(profile)
        || generation == 0
        || request["expected_generation"].as_u64() != Some(generation)
        || !valid_scope(scope_token)
        || request["expected_recovery_scope_token"].as_str() != Some(scope_token)
        || request["generation"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || request["record_id"].as_str().is_none_or(|value| {
            value.is_empty()
                || value.len() > 128
                || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err(ERROR);
    }
    Ok(())
}

fn valid_scope(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request() -> Value {
        json!({"action":"windows_recovery_retry","profile_id":"default",
            "expected_generation":7,"expected_recovery_scope_token":"a".repeat(64),
            "record_id":"aabbccdd","generation":2})
    }

    #[test]
    fn selected_record_generation_is_distinct_from_current_account_generation() {
        validate(&request(), "default", 7, &"a".repeat(64)).unwrap();
        assert!(validate(&request(), "other-profile", 7, &"a".repeat(64)).is_err());
        assert!(validate(&request(), "default", 8, &"a".repeat(64)).is_err());
        assert!(validate(&request(), "default", 7, &"b".repeat(64)).is_err());
    }

    #[test]
    fn missing_extra_or_malformed_binding_never_becomes_retry_authority() {
        let original = request();
        for key in original.as_object().unwrap().keys() {
            let mut request = original.clone();
            request.as_object_mut().unwrap().remove(key);
            assert!(validate(&request, "default", 7, &"a".repeat(64)).is_err());
        }
        for (key, bad) in [
            ("action", json!("windows_recovery_list")),
            ("expected_generation", json!("7")),
            ("expected_generation", json!(0)),
            ("expected_recovery_scope_token", json!("A".repeat(64))),
            ("expected_recovery_scope_token", json!("a".repeat(63))),
            ("record_id", json!("../file")),
            ("record_id", json!("")),
            ("record_id", json!("a".repeat(129))),
            ("generation", json!(0)),
            ("generation", json!(-1)),
        ] {
            let mut request = original.clone();
            request[key] = bad;
            assert!(validate(&request, "default", 7, &"a".repeat(64)).is_err());
        }
        let mut extra = original;
        extra["path"] = json!("never accepted from the caller");
        assert!(validate(&extra, "default", 7, &"a".repeat(64)).is_err());
    }
}

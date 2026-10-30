//! Pure token-response validation before a usable grant can be replaced.
//! Scope is validated but grants no local authority and is not retained here.
use serde_json::{Map, Value};

const INVALID_RESPONSE: &str = "Token endpoint returned an invalid token response";
const DEFAULT_LIFETIME_SECONDS: u64 = 3600;
const MAX_LIFETIME_SECONDS: u64 = 31_536_000;

// Deliberately no Debug, Clone or serialization: these strings contain secrets.
pub(super) struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub lifetime_seconds: u64,
}

pub(super) fn parse(body: &[u8], max_secret: usize) -> Result<TokenResponse, String> {
    let value: Value = serde_json::from_slice(body).map_err(|_| invalid())?;
    let object = value.as_object().ok_or_else(invalid)?;
    let access_token = object
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|token| valid_bearer_token(token, max_secret))
        .ok_or_else(invalid)?;
    let token_type = object
        .get("token_type")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    if !token_type.eq_ignore_ascii_case("Bearer") {
        return Err(invalid());
    }
    let refresh_token = optional_string(object, "refresh_token")?;
    if refresh_token.is_some_and(|token| {
        token.len() > max_secret
            || !token.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
            || !token.bytes().any(|byte| byte != b' ')
    }) {
        return Err(invalid());
    }
    if let Some(scope) = optional_string(object, "scope")?
        && (scope.len() > max_secret
            || scope.split(' ').any(str::is_empty)
            || !scope
                .bytes()
                .all(|byte| (0x20..=0x7e).contains(&byte) && byte != b'"' && byte != b'\\'))
    {
        return Err(invalid());
    }
    let lifetime_seconds = lifetime(object)?;

    // Validate every field before cloning either secret into the result. Do not
    // trim or otherwise transform token bytes, and never retain scope as grants.
    Ok(TokenResponse {
        access_token: access_token.to_owned(),
        refresh_token: refresh_token.map(str::to_owned),
        lifetime_seconds,
    })
}

fn optional_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(invalid()),
    }
}

fn valid_bearer_token(token: &str, max_secret: usize) -> bool {
    if token.is_empty() || token.len() > max_secret {
        return false;
    }
    let mut body_seen = false;
    let mut padding = false;
    for byte in token.bytes() {
        if byte == b'=' {
            if !body_seen {
                return false;
            }
            padding = true;
        } else if padding
            || !(byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/'))
        {
            return false;
        } else {
            body_seen = true;
        }
    }
    body_seen
}

fn lifetime(object: &Map<String, Value>) -> Result<u64, String> {
    let Some(value) = object.get("expires_in") else {
        return Ok(DEFAULT_LIFETIME_SECONDS);
    };
    let seconds = match value {
        Value::Number(number) => number.as_u64().ok_or_else(invalid)?,
        Value::String(text)
            if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            text.parse::<u64>().map_err(|_| invalid())?
        }
        _ => return Err(invalid()),
    };
    // Desktop intentionally retains its stricter positive, at-most-one-year
    // acceptance bound; Android's zero acceptance/upper clamp is not copied.
    if !(1..=MAX_LIFETIME_SECONDS).contains(&seconds) {
        return Err(invalid());
    }
    Ok(seconds)
}

fn invalid() -> String {
    INVALID_RESPONSE.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const MAX_SECRET: usize = 64;

    fn valid() -> Value {
        json!({"access_token":"synthetic-access", "token_type":"Bearer", "expires_in":3600})
    }

    fn parse_value(value: &Value) -> Result<TokenResponse, String> {
        parse(&serde_json::to_vec(value).unwrap(), MAX_SECRET)
    }

    fn refused(value: &Value) {
        // Inspect only the fixed error, never Debug-print a successful grant.
        assert_eq!(parse_value(value).err().as_deref(), Some(INVALID_RESPONSE));
    }

    #[test]
    fn bearer_type_is_case_insensitive_and_jwt_opaque_padding_bytes_are_preserved() {
        for token_type in ["Bearer", "bEaReR", "BEARER"] {
            for access_token in [
                "a",
                "abcXYZ019-._~+/",
                "abc+/==",
                "header.payload.signature",
            ] {
                let mut value = valid();
                value["token_type"] = json!(token_type);
                value["access_token"] = json!(access_token);
                let parsed = parse_value(&value).unwrap();
                assert_eq!(parsed.access_token, access_token);
                assert!(parsed.refresh_token.is_none());
                assert_eq!(parsed.lifetime_seconds, 3600);
            }
        }
    }

    #[test]
    fn optional_nulls_and_exact_printable_refresh_bytes_are_supported() {
        let mut value = valid();
        value["refresh_token"] = Value::Null;
        value["scope"] = Value::Null;
        assert!(parse_value(&value).unwrap().refresh_token.is_none());
        let refresh = "  printable \"refresh\\token +/=  ";
        value["refresh_token"] = json!(refresh);
        value["scope"] = json!("openid files:read files:write");
        assert_eq!(
            parse_value(&value).unwrap().refresh_token.as_deref(),
            Some(refresh)
        );
        value.as_object_mut().unwrap().remove("refresh_token");
        value.as_object_mut().unwrap().remove("scope");
        assert!(parse_value(&value).unwrap().refresh_token.is_none());
    }

    #[test]
    fn absent_expiry_defaults_but_numeric_and_digit_string_bounds_stay_positive() {
        let mut value = valid();
        value.as_object_mut().unwrap().remove("expires_in");
        assert_eq!(parse_value(&value).unwrap().lifetime_seconds, 3600);
        for expiry in [
            json!(1),
            json!(31_536_000),
            json!("1"),
            json!("00001"),
            json!("31536000"),
        ] {
            value["expires_in"] = expiry;
            assert!(
                (1..=MAX_LIFETIME_SECONDS).contains(&parse_value(&value).unwrap().lifetime_seconds)
            );
        }
        // Unlike Android zero/clamping, Desktop rejects zero and excess years.
        for expiry in [
            json!(0),
            json!("0"),
            json!(31_536_001),
            json!("31536001"),
            json!(u64::MAX),
        ] {
            value["expires_in"] = expiry;
            refused(&value);
        }
    }

    #[test]
    fn malformed_json_nonobjects_and_required_field_types_are_refused() {
        for body in [
            b"".as_slice(),
            b"{",
            b"null",
            b"[]",
            b"1",
            b"true",
            b"\"text\"",
            &[0xff],
        ] {
            assert_eq!(
                parse(body, MAX_SECRET).err().as_deref(),
                Some(INVALID_RESPONSE)
            );
        }
        for field in ["access_token", "token_type"] {
            let mut missing = valid();
            missing.as_object_mut().unwrap().remove(field);
            refused(&missing);
            for invalid in [
                Value::Null,
                json!(true),
                json!(1),
                json!([]),
                json!({}),
                json!(""),
            ] {
                let mut value = valid();
                value[field] = invalid;
                refused(&value);
            }
        }
    }

    #[test]
    fn bearer_grammar_rejects_controls_unicode_spaces_and_internal_padding() {
        for token in [
            " ", "=", "==", "=abc", "a=b", "a==b==", " a", "a ", "a\tb", "a\nb", "a\rb", "a\0b",
            "a\u{7f}", "café", "a:b", "a,b", "a\\b", "a\"b",
        ] {
            let mut value = valid();
            value["access_token"] = json!(token);
            refused(&value);
        }
        for token_type in [
            "",
            "Basic",
            " Bearer",
            "Bearer ",
            "Bearer\r\n",
            "Béarér",
            "Bearer\0",
        ] {
            let mut value = valid();
            value["token_type"] = json!(token_type);
            refused(&value);
        }
    }

    #[test]
    fn refresh_optional_types_blank_and_header_controls_are_refused() {
        for refresh in [
            json!(false),
            json!(1),
            json!([]),
            json!({}),
            json!(""),
            json!("   "),
            json!("\t"),
            json!("a\r\nb"),
            json!("a\0b"),
            json!("a\u{7f}"),
            json!("ręfresh"),
        ] {
            let mut value = valid();
            value["refresh_token"] = refresh;
            refused(&value);
        }
    }

    #[test]
    fn scope_accepts_rfc_tokens_but_refuses_bad_types_separators_and_characters() {
        for scope in [
            json!(false),
            json!(1),
            json!([]),
            json!({}),
            json!(""),
            json!(" "),
            json!(" read"),
            json!("read "),
            json!("read  write"),
            json!("read\twrite"),
            json!("read\nwrite"),
            json!("read\rwrite"),
            json!("read\0write"),
            json!("read\"write"),
            json!("read\\write"),
            json!("réad"),
            json!("read\u{7f}"),
        ] {
            let mut value = valid();
            value["scope"] = scope;
            refused(&value);
        }
        let mut value = valid();
        value["scope"] = json!("!#$%&'()*+,-./:;<=>?@[]^_`{|}~ read");
        assert!(parse_value(&value).is_ok());
    }

    #[test]
    fn present_expiry_is_not_silently_defaulted_or_coerced() {
        for expiry in [
            Value::Null,
            json!(false),
            json!(true),
            json!([]),
            json!({}),
            json!(-1),
            json!(1.5),
            json!(1.0),
            json!(""),
            json!("+1"),
            json!("-1"),
            json!("1.0"),
            json!("1e3"),
            json!(" 1"),
            json!("1 "),
            json!("１"),
            json!("18446744073709551616"),
        ] {
            let mut value = valid();
            value["expires_in"] = expiry;
            refused(&value);
        }
        for body in [
            br#"{"access_token":"a","token_type":"Bearer","expires_in":18446744073709551616}"#
                .as_slice(),
            br#"{"access_token":"a","token_type":"Bearer","expires_in":1e3}"#,
        ] {
            assert_eq!(
                parse(body, MAX_SECRET).err().as_deref(),
                Some(INVALID_RESPONSE)
            );
        }
    }

    #[test]
    fn size_limits_are_exact_for_tokens_refresh_and_scope() {
        for field in ["access_token", "refresh_token", "scope"] {
            let mut value = valid();
            value[field] = json!("a".repeat(MAX_SECRET));
            assert!(parse_value(&value).is_ok());
            value[field] = json!("a".repeat(MAX_SECRET + 1));
            refused(&value);
        }
        assert_eq!(
            parse(&serde_json::to_vec(&valid()).unwrap(), 0)
                .err()
                .as_deref(),
            Some(INVALID_RESPONSE)
        );
    }

    #[test]
    fn optional_fields_are_validated_even_when_access_token_would_be_usable() {
        for (field, invalid_value) in [
            ("scope", json!("read  write")),
            ("refresh_token", json!(123)),
            ("expires_in", Value::Null),
        ] {
            let mut value = valid();
            value[field] = invalid_value;
            refused(&value);
        }
    }
}

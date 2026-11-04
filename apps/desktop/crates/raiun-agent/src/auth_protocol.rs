//! Bounded discovery and browser-response checks for the existing code/PKCE flow.
//! Legacy responses without an issuer remain compatible; this does not provide
//! complete mix-up protection for providers without a response issuer proof.
use serde_json::Value;
use url::Url;

const METADATA_ERROR: &str = "OpenID flow metadata was invalid or unsupported";
const CALLBACK_ERROR: &str = "OAuth callback was invalid; sign-in was rejected";
const ISSUER_ERROR: &str = "OAuth callback issuer could not be verified; sign-in was rejected";
const QUERY_LIMIT: usize = 65_536;
const OWNED_QUERY_KEYS: [&str; 7] = [
    "client_id",
    "response_type",
    "scope",
    "redirect_uri",
    "state",
    "code_challenge",
    "code_challenge_method",
];

pub(super) fn validate_flow_metadata(
    metadata: &Value,
    authorization_endpoint: &Url,
) -> Result<bool, String> {
    let object = metadata.as_object().ok_or(METADATA_ERROR)?;
    for (key, required) in [
        ("response_types_supported", "code"),
        ("grant_types_supported", "authorization_code"),
        ("code_challenge_methods_supported", "S256"),
    ] {
        if let Some(value) = object.get(key) {
            let entries = value.as_array().ok_or(METADATA_ERROR)?;
            if entries.len() > 128 {
                return Err(METADATA_ERROR.into());
            }
            let mut supported = false;
            for entry in entries {
                let entry = entry.as_str().ok_or(METADATA_ERROR)?;
                if entry.trim().is_empty()
                    || entry.len() > 512
                    || entry.chars().any(char::is_control)
                {
                    return Err(METADATA_ERROR.into());
                }
                supported |= entry == required;
            }
            if !supported {
                return Err(METADATA_ERROR.into());
            }
        }
    }
    let issuer_required = match object.get("authorization_response_iss_parameter_supported") {
        None => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(METADATA_ERROR.into()),
    };
    for (key, _) in query_pairs(authorization_endpoint).map_err(|_| METADATA_ERROR)? {
        if OWNED_QUERY_KEYS.contains(&key.as_str()) {
            return Err(METADATA_ERROR.into());
        }
    }
    Ok(issuer_required)
}

pub(super) fn callback_code(
    url: &Url,
    expected_state: &str,
    expected_issuer: Option<&str>,
    issuer_required: bool,
) -> Result<String, String> {
    if url.path() != "/" || url.fragment().is_some() {
        return Err(CALLBACK_ERROR.into());
    }
    let (mut state, mut code, mut error, mut issuer) = (None, None, None, None);
    for (key, value) in query_pairs(url).map_err(|_| CALLBACK_ERROR)? {
        let slot = match key.as_str() {
            "state" => &mut state,
            "code" => &mut code,
            "error" => &mut error,
            "iss" => &mut issuer,
            _ => continue,
        };
        if slot.replace(value).is_some() {
            return Err(CALLBACK_ERROR.into());
        }
    }
    let state = state
        .filter(|value| !value.trim().is_empty())
        .ok_or(CALLBACK_ERROR)?;
    if !super::constant_time_equal(state.as_bytes(), expected_state.as_bytes()) {
        return Err("OAuth callback state did not match; sign-in was rejected".into());
    }
    // Check any supplied issuer, including error responses and legacy providers,
    // before permitting the caller to exchange a code. Identifier spelling is
    // compared directly, independently of endpoint URL transport validation.
    match issuer {
        Some(value)
            if !value.trim().is_empty()
                && !value.chars().any(char::is_control)
                && expected_issuer == Some(value.as_str()) => {}
        None if !issuer_required => {}
        _ => return Err(ISSUER_ERROR.into()),
    }
    if let Some(error) = error {
        if code.is_some() || error.trim().is_empty() || error.chars().any(char::is_control) {
            return Err(CALLBACK_ERROR.into());
        }
        return Err(match error.as_str() {
            "access_denied" => "Sign-in was denied by the user or server",
            "login_required" => "The server requires another sign-in method",
            _ => "The authorization server did not complete sign-in",
        }
        .into());
    }
    code.filter(|value| {
        !value.trim().is_empty()
            && value.len() <= 8192
            && !value.bytes().any(|byte| byte.is_ascii_control())
    })
    .ok_or_else(|| CALLBACK_ERROR.into())
}

// URL's query_pairs uses lossy UTF-8 decoding. Security-relevant values instead
// use strict form decoding, with a total allocation bound and no new dependency.
fn query_pairs(url: &Url) -> Result<Vec<(String, String)>, ()> {
    let query = url.query().unwrap_or("");
    if query.len() > QUERY_LIMIT {
        return Err(());
    }
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            Ok((decode_form(key)?, decode_form(value)?))
        })
        .collect()
}

fn decode_form(raw: &str) -> Result<String, ()> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut bytes = raw.bytes();
    while let Some(byte) = bytes.next() {
        decoded.push(match byte {
            b'+' => b' ',
            b'%' => {
                let high = hex(bytes.next().ok_or(())?).ok_or(())?;
                let low = hex(bytes.next().ok_or(())?).ok_or(())?;
                (high << 4) | low
            }
            other => other,
        });
    }
    String::from_utf8(decoded).map_err(|_| ())
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn endpoint(query: &str) -> Url {
        Url::parse(&format!("https://issuer.example/authorize{query}")).unwrap()
    }
    fn callback(query: &str) -> Url {
        Url::parse(&format!("http://127.0.0.1:1234/{query}")).unwrap()
    }
    fn check(query: &str, required: bool) -> Result<String, String> {
        callback_code(
            &callback(query),
            "expected",
            Some("https://issuer.example"),
            required,
        )
    }

    #[test]
    fn metadata_legacy_and_explicit_supported_flow() {
        assert!(!validate_flow_metadata(&json!({}), &endpoint("")).unwrap());
        let metadata = json!({"response_types_supported":["code","id_token"], "grant_types_supported":["authorization_code"], "code_challenge_methods_supported":["S256"], "authorization_response_iss_parameter_supported":true});
        assert!(validate_flow_metadata(&metadata, &endpoint("")).unwrap());
        assert!(
            !validate_flow_metadata(
                &json!({"authorization_response_iss_parameter_supported":false}),
                &endpoint("")
            )
            .unwrap()
        );
    }

    #[test]
    fn metadata_present_capabilities_are_strict_and_bounded() {
        for (key, required) in [
            ("response_types_supported", "code"),
            ("grant_types_supported", "authorization_code"),
            ("code_challenge_methods_supported", "S256"),
        ] {
            for value in [
                Value::Null,
                json!(true),
                json!(required),
                json!([]),
                json!(["other"]),
                json!([required, 7]),
                json!([required, ""]),
                json!([required, "\n"]),
                json!([required, "x".repeat(513)]),
                json!(vec![required; 129]),
            ] {
                let mut metadata = json!({});
                metadata[key] = value;
                assert_eq!(
                    validate_flow_metadata(&metadata, &endpoint("")).unwrap_err(),
                    METADATA_ERROR
                );
            }
        }
        for value in [Value::Null, json!("true"), json!(0), json!([])] {
            assert!(
                validate_flow_metadata(
                    &json!({"authorization_response_iss_parameter_supported":value}),
                    &endpoint("")
                )
                .is_err()
            );
        }
        for metadata in [Value::Null, json!([]), json!(true)] {
            assert!(validate_flow_metadata(&metadata, &endpoint("")).is_err());
        }
        assert!(
            validate_flow_metadata(
                &json!({"code_challenge_methods_supported":["s256"]}),
                &endpoint("")
            )
            .is_err()
        );
    }

    #[test]
    fn endpoint_rejects_owned_decoded_keys_and_retains_unrelated_query() {
        for key in OWNED_QUERY_KEYS {
            for query in [format!("?{key}=old"), format!("?{key}=old&{key}=old")] {
                assert!(validate_flow_metadata(&json!({}), &endpoint(&query)).is_err());
            }
        }
        assert!(validate_flow_metadata(&json!({}), &endpoint("?%73tate=old")).is_err());
        let endpoint = endpoint("?prompt=login&custom=state&custom=two");
        let before = endpoint.as_str().to_owned();
        assert!(!validate_flow_metadata(&json!({}), &endpoint).unwrap());
        assert_eq!(endpoint.as_str(), before);
    }

    #[test]
    fn callbacks_allow_legacy_or_exact_advertised_issuer() {
        assert_eq!(
            check("?state=expected&code=opaque+code", false).unwrap(),
            "opaque code"
        );
        for required in [false, true] {
            assert_eq!(
                check(
                    "?state=expected&code=opaque&iss=https%3A%2F%2Fissuer.example",
                    required
                )
                .unwrap(),
                "opaque"
            );
        }
        assert!(check("?state=expected&code=opaque", true).is_err());
        assert!(
            callback_code(
                &callback("?state=expected&code=x&iss=https%3A%2F%2Fissuer.example"),
                "expected",
                None,
                false
            )
            .is_err()
        );
        assert_eq!(
            check("?state=expected&code=x&other=y&other=z", false).unwrap(),
            "x"
        );
    }

    #[test]
    fn callbacks_reject_every_duplicate_and_bad_state_before_code() {
        for query in [
            "?state=expected&state=expected&code=x",
            "?state=expected&code=x&code=x",
            "?state=expected&code=x&iss=a&iss=a",
            "?state=expected&error=access_denied&error=access_denied",
            "?%73tate=expected&state=expected&code=x",
            "?state=wrong&code=x",
            "?state=&code=x",
            "?code=x",
            "?state=expected&code=",
            "?state=expected&code=+",
            "?state=expected&code=%0A",
            "?state=expected&code=x&error=access_denied",
        ] {
            assert!(check(query, false).is_err(), "query unexpectedly accepted");
        }
        assert!(check(&format!("?state=expected&code={}", "x".repeat(8193)), false).is_err());
    }

    #[test]
    fn callbacks_validate_exact_issuer_including_error_responses() {
        for issuer in [
            "",
            "https://issuer.example/",
            "https://ISSUER.example",
            "https://issuer.example:443",
            "https://other.example",
        ] {
            let mut url = callback("?state=expected&code=x");
            url.query_pairs_mut().append_pair("iss", issuer);
            assert_eq!(
                callback_code(&url, "expected", Some("https://issuer.example"), false).unwrap_err(),
                ISSUER_ERROR
            );
        }
        assert_eq!(
            check("?state=expected&error=access_denied", true).unwrap_err(),
            ISSUER_ERROR
        );
        assert_eq!(
            check("?state=expected&error=access_denied&iss=wrong", false).unwrap_err(),
            ISSUER_ERROR
        );
        assert_eq!(
            check("?state=expected&error=access_denied", false).unwrap_err(),
            "Sign-in was denied by the user or server"
        );
        assert_eq!(
            check("?state=expected&error=login_required", false).unwrap_err(),
            "The server requires another sign-in method"
        );
        assert_eq!(
            check("?state=expected&error=private-provider-text", false).unwrap_err(),
            "The authorization server did not complete sign-in"
        );
        assert!(check("?state=expected&error=", false).is_err());
    }

    #[test]
    fn strict_form_decode_and_callback_location_fail_closed() {
        for value in ["%", "%0", "%GG", "%FF", "%C0%AF", "%E2%82"] {
            assert!(check(&format!("?state=expected&code={value}"), false).is_err());
            assert!(
                validate_flow_metadata(&json!({}), &endpoint(&format!("?custom={value}"))).is_err()
            );
        }
        assert!(
            callback_code(
                &Url::parse("http://127.0.0.1/other?state=expected&code=x").unwrap(),
                "expected",
                None,
                false
            )
            .is_err()
        );
        assert!(check("?state=expected&code=x#fragment", false).is_err());
        assert!(
            check(
                &format!("?state=expected&code=x&extra={}", "x".repeat(QUERY_LIMIT)),
                false
            )
            .is_err()
        );
        assert_eq!(
            decode_form("opaque%2Bcode+%C3%A9").unwrap(),
            "opaque+code é"
        );
    }
}

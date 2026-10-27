//! Pure existing folder RPC decoding. Profile authentication is caller-owned.
use raiun_core::{FolderExclusion, FolderPair, MediaFilter, SyncMode, validate_remote_path};
use serde_json::{Map, Value};

pub enum FolderRequest {
    VaultInspect(super::windows_vault_requests::VaultInspectRequest),
    Media(super::windows_media_requests::MediaRequest),
    Pause {
        paused: bool,
    },
    SpacePause {
        space_id: String,
        paused: bool,
    },
    Pairs,
    Transfers,
    Spaces,
    List {
        space_id: String,
        path: String,
    },
    Add(FolderPair),
    Update {
        id: String,
        expected_pair: FolderPair,
        expected_auth_generation: u64,
        mode: SyncMode,
        content_filter: MediaFilter,
        exclusions: Vec<FolderExclusion>,
        excluded_paths: Vec<String>,
    },
    Exclusions {
        id: String,
        excluded_paths: Vec<String>,
    },
    Remove {
        id: String,
    },
    SpaceDisconnect {
        space_id: String,
    },
    Sync {
        space_id: Option<String>,
    },
}
fn invalid() -> String {
    "Invalid folder request".into()
}
fn text(fields: &mut Map<String, Value>, key: &str, max: usize) -> Result<String, String> {
    match fields.remove(key) {
        Some(Value::String(value)) if bounded(&value, max) => Ok(value),
        _ => Err(invalid()),
    }
}
fn bounded(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn remote(value: &str) -> Result<(), String> {
    if !bounded(value, 4096) || validate_remote_path(value).is_err() {
        return Err(invalid());
    }
    Ok(())
}
pub fn decode(request: &Value) -> Result<FolderRequest, String> {
    let mut fields = request.as_object().cloned().ok_or_else(invalid)?;
    let action = text(&mut fields, "action", 64)?;
    // This is an envelope field, NOT evidence of authenticated profile ownership.
    fields.remove("profile_id");
    let decoded = match action.as_str() {
        "pause" => FolderRequest::Pause {
            paused: fields
                .remove("paused")
                .and_then(|value| value.as_bool())
                .ok_or_else(invalid)?,
        },
        "space_pause" => FolderRequest::SpacePause {
            space_id: text(&mut fields, "space_id", 512)?,
            paused: fields
                .remove("paused")
                .and_then(|value| value.as_bool())
                .ok_or_else(invalid)?,
        },
        "media_jobs" | "media_job_status" | "media_destination" | "media_job_set"
        | "media_job_remove" | "media_job_run" | "media_job_recovery" => {
            return super::windows_media_requests::decode(request).map(FolderRequest::Media);
        }
        "vault_inspect" => {
            return super::windows_vault_requests::decode(request).map(FolderRequest::VaultInspect);
        }
        "pairs" => FolderRequest::Pairs,
        "transfers" => FolderRequest::Transfers,
        "spaces" => FolderRequest::Spaces,
        "list" => {
            let space_id = text(&mut fields, "space_id", 512)?;
            let path = text(&mut fields, "path", 4096)?;
            remote(&path)?;
            FolderRequest::List { space_id, path }
        }
        "pair_add" => {
            let pair: FolderPair =
                serde_json::from_value(Value::Object(fields.clone())).map_err(|_| invalid())?;
            if !bounded(&pair.id, 128)
                || !bounded(&pair.space_id, 512)
                || pair.vault.is_some()
                || pair
                    .local_path
                    .to_str()
                    .is_none_or(|path| !bounded(path, 4096))
                || pair.validate_exclusions().is_err()
            {
                return Err(invalid());
            }
            remote(&pair.remote_path)?;
            fields.clear();
            FolderRequest::Add(pair)
        }
        "pair_update" => {
            let id = text(&mut fields, "id", 128)?;
            let expected_auth_generation = fields
                .remove("expected_auth_generation")
                .and_then(|value| value.as_u64())
                .ok_or_else(invalid)?;
            let expected_pair: FolderPair =
                serde_json::from_value(fields.remove("expected_pair").ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            let mode: SyncMode = serde_json::from_value(fields.remove("mode").ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
            let content_filter: MediaFilter =
                serde_json::from_value(fields.remove("content_filter").ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            let exclusions: Vec<FolderExclusion> =
                serde_json::from_value(fields.remove("exclusions").ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            let excluded_paths: Vec<String> =
                serde_json::from_value(fields.remove("excluded_paths").ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            let candidate = FolderPair {
                mode,
                content_filter,
                exclusions: exclusions.clone(),
                excluded_paths: excluded_paths.clone(),
                ..expected_pair.clone()
            };
            if candidate.id != id || candidate.validate_exclusions().is_err() {
                return Err(invalid());
            }
            FolderRequest::Update {
                id,
                expected_pair,
                expected_auth_generation,
                mode,
                content_filter,
                exclusions,
                excluded_paths,
            }
        }
        "pair_exclusions_set" => {
            let id = text(&mut fields, "id", 128)?;
            let excluded_paths: Vec<String> =
                serde_json::from_value(fields.remove("excluded_paths").ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            // Reuse the exact core exclusion validator without probing paths.
            let pair = FolderPair {
                id: id.clone(),
                local_path: Default::default(),
                space_id: String::new(),
                remote_path: String::new(),
                mode: raiun_core::SyncMode::TwoWay,
                vault: None,
                excluded_paths,
                content_filter: raiun_core::MediaFilter::All,
                exclusions: Vec::new(),
            };
            pair.validate_exclusions().map_err(|_| invalid())?;
            FolderRequest::Exclusions {
                id,
                excluded_paths: pair.excluded_paths,
            }
        }
        "pair_remove" => FolderRequest::Remove {
            id: text(&mut fields, "id", 128)?,
        },
        "space_disconnect" => FolderRequest::SpaceDisconnect {
            space_id: text(&mut fields, "space_id", 512)?,
        },
        "space_sync_now" => FolderRequest::Sync {
            space_id: Some(text(&mut fields, "space_id", 512)?),
        },
        "sync_now" => FolderRequest::Sync { space_id: None },
        _ => return Err(invalid()),
    };
    if !fields.is_empty() {
        return Err(invalid());
    }
    Ok(decoded)
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn transfers_accepts_only_the_existing_empty_request_envelope() {
        assert!(matches!(
            decode(&json!({"action":"transfers","profile_id":"default"})).unwrap(),
            FolderRequest::Transfers
        ));
        for extra in [
            json!({"limit":500}),
            json!({"space_id":"s"}),
            json!({"unexpected":true}),
        ] {
            let mut request = json!({"action":"transfers"});
            request
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert_eq!(decode(&request).err().unwrap(), "Invalid folder request");
        }
    }
    #[test]
    fn pause_contracts_require_boolean_and_exact_fields() {
        assert!(matches!(
            decode(&json!({"action":"pause","paused":true})),
            Ok(FolderRequest::Pause { paused: true })
        ));
        assert!(matches!(
            decode(&json!({"action":"space_pause","space_id":"s","paused":false})),
            Ok(FolderRequest::SpacePause { paused: false, .. })
        ));
        for request in [
            json!({"action":"pause","paused":"true"}),
            json!({"action":"space_pause","paused":true}),
            json!({"action":"pause","paused":false,"extra":1}),
        ] {
            assert!(decode(&request).is_err());
        }
    }
    #[test]
    fn existing_actions_and_envelopes_decode() {
        for (action, fields) in [
            ("pairs", json!({})),
            ("spaces", json!({})),
            ("list", json!({"space_id":"space","path":"/folder"})),
            ("pair_remove", json!({"id":"pair"})),
            (
                "pair_exclusions_set",
                json!({"id":"pair","excluded_paths":["private"]}),
            ),
            ("space_disconnect", json!({"space_id":"space"})),
            ("space_sync_now", json!({"space_id":"space"})),
            ("sync_now", json!({})),
        ] {
            let mut fields = fields.as_object().unwrap().clone();
            fields.insert("action".into(), action.into());
            fields.insert("profile_id".into(), "default".into());
            assert!(decode(&Value::Object(fields)).is_ok());
        }
        let add = json!({"action":"pair_add","profile_id":"default","id":"pair","space_id":"space","local_path":"Z:\\offline","remote_path":"/","mode":"two_way","vault":null});
        match decode(&add).unwrap() {
            FolderRequest::Add(pair) => {
                assert_eq!(pair.content_filter, MediaFilter::All);
                assert!(pair.exclusions.is_empty());
            }
            _ => panic!("pair_add should decode as Add"),
        }
        let expected_pair = json!({"id":"pair","local_path":"Z:\\offline","space_id":"space","vault":null,"remote_path":"/","mode":"two_way","excluded_paths":[],"content_filter":"all","exclusions":[]});
        let update = json!({"action":"pair_update","id":"pair","expected_pair":expected_pair,"expected_auth_generation":7,"mode":"upload_only","content_filter":"photos","exclusions":[{"kind":"path","pattern":"private/"}],"excluded_paths":["legacy"]});
        assert!(matches!(
            decode(&update),
            Ok(FolderRequest::Update {
                expected_auth_generation: 7,
                ..
            })
        ));
        assert!(matches!(
            decode(&json!({"action":"space_sync_now","space_id":"s"})),
            Ok(FolderRequest::Sync { space_id: Some(_) })
        ));
    }
    #[test]
    fn unknown_fields_vault_and_unsupported_actions_refuse_opaquely() {
        for request in [
            json!({"action":"pairs","token":"secret"}),
            json!({"action":"pair_update","id":"p"}),
            json!({"action":"sync_now","id":"p"}),
            json!({"action":"list","space_id":"s","path":"/","cursor":"extra"}),
            json!({"action":"pair_add","id":"p","local_path":"Z:\\local","space_id":"s","remote_path":"/","mode":"two_way","vault":{"root_path":"/","root_resource_id":"v"}}),
        ] {
            assert_eq!(decode(&request).err().unwrap(), "Invalid folder request");
        }
    }
    #[test]
    fn boundaries_and_core_exclusions_are_enforced_without_filesystem() {
        assert!(decode(&json!({"action":"pair_remove","id":"p".repeat(128)})).is_ok());
        for request in [
            json!({"action":"pair_remove","id":"p".repeat(129)}),
            json!({"action":"space_sync_now","space_id":"s".repeat(513)}),
            json!({"action":"list","space_id":"s","path":"/".repeat(4097)}),
            json!({"action":"pair_exclusions_set","id":"p","excluded_paths":["../escape"]}),
            json!({"action":"pair_exclusions_set","id":"p","excluded_paths":["same","same"]}),
            json!({"action":"list","space_id":"s","path":"/../escape"}),
        ] {
            assert!(decode(&request).is_err());
        }
        assert!(decode(&json!({"action":"pair_add","id":"p","space_id":"s","local_path":"Z:\\nonexistent","remote_path":"/","mode":"download_only"})).is_ok());
    }
}

//! Pure subset of existing media RPCs; account/destination/runtime admission is external.
use raiun_core::{MediaImportJob, validate_media_import_jobs, validate_remote_path};
use raiun_engine::{MAX_MEDIA_RECOVERY_PAGE, MediaImportRecoveryCursor};
use serde_json::{Map, Value};
pub enum MediaRequest {
    Jobs,
    Destination {
        space_id: String,
        path: String,
    },
    Set {
        job: MediaImportJob,
        expected_revision: u64,
        expected_account_id: String,
    },
    Status {
        job_id: String,
    },
    Run {
        job_id: String,
        expected_revision: u64,
        expected_account_id: String,
    },
    Recovery {
        job_id: String,
        expected_revision: u64,
        expected_account_id: String,
        limit: usize,
        cursor: Option<MediaImportRecoveryCursor>,
    },
    Remove {
        job_id: String,
        expected_revision: u64,
        expected_account_id: String,
    },
}
fn invalid() -> String {
    "Invalid media request".into()
}
fn text(fields: &mut Map<String, Value>, key: &str, max: usize) -> Result<String, String> {
    match fields.remove(key) {
        Some(Value::String(v))
            if !v.trim().is_empty() && v.len() <= max && !v.chars().any(char::is_control) =>
        {
            Ok(v)
        }
        _ => Err(invalid()),
    }
}
fn revision(fields: &mut Map<String, Value>) -> Result<u64, String> {
    fields
        .remove("expected_revision")
        .and_then(|v| v.as_u64())
        .ok_or_else(invalid)
}
pub fn decode(value: &Value) -> Result<MediaRequest, String> {
    let mut fields = value.as_object().cloned().ok_or_else(invalid)?;
    let action = text(&mut fields, "action", 64)?;
    fields.remove("profile_id");
    let result = match action.as_str() {
        "media_jobs" => MediaRequest::Jobs,
        "media_destination" => {
            let space_id = text(&mut fields, "space_id", 512)?;
            let path = text(&mut fields, "path", 4096)?;
            validate_remote_path(&path).map_err(|_| invalid())?;
            MediaRequest::Destination { space_id, path }
        }
        "media_job_set" => {
            let expected_revision = revision(&mut fields)?;
            let expected_account_id = text(&mut fields, "expected_account_id", 256)?;
            let job: MediaImportJob =
                serde_json::from_value(fields.remove("job").ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            // Unix assigns the persisted revision before validation. Validate shape using a
            // nonzero provisional revision without modifying the caller's returned request.
            let mut shape = job.clone();
            if shape.revision == 0 {
                shape.revision = 1;
            }
            validate_media_import_jobs(&[shape]).map_err(|_| invalid())?;
            MediaRequest::Set {
                job,
                expected_revision,
                expected_account_id,
            }
        }
        "media_job_status" => MediaRequest::Status {
            job_id: text(&mut fields, "job_id", 128)?,
        },
        "media_job_recovery" => {
            let job_id = text(&mut fields, "job_id", 128)?;
            let expected_revision = revision(&mut fields)?;
            let expected_account_id = text(&mut fields, "expected_account_id", 256)?;
            let limit = fields
                .remove("limit")
                .and_then(|value| value.as_u64())
                .and_then(|value| usize::try_from(value).ok())
                .filter(|value| (1..=MAX_MEDIA_RECOVERY_PAGE).contains(value))
                .ok_or_else(invalid)?;
            let cursor = match fields.remove("cursor") {
                None | Some(Value::Null) => None,
                Some(value) => {
                    let cursor: MediaImportRecoveryCursor =
                        serde_json::from_value(value).map_err(|_| invalid())?;
                    for value in [
                        &cursor.origin,
                        &cursor.space_id,
                        &cursor.source_root,
                        &cursor.source_relative_path,
                        &cursor.destination_path,
                    ] {
                        if value.is_empty()
                            || value.len() > 4096
                            || value.chars().any(char::is_control)
                        {
                            return Err(invalid());
                        }
                    }
                    Some(cursor)
                }
            };
            MediaRequest::Recovery {
                job_id,
                expected_revision,
                expected_account_id,
                limit,
                cursor,
            }
        }
        "media_job_run" | "media_job_remove" => {
            let job_id = text(&mut fields, "job_id", 128)?;
            let expected_revision = revision(&mut fields)?;
            let expected_account_id = text(&mut fields, "expected_account_id", 256)?;
            if action == "media_job_run" {
                MediaRequest::Run {
                    job_id,
                    expected_revision,
                    expected_account_id,
                }
            } else {
                MediaRequest::Remove {
                    job_id,
                    expected_revision,
                    expected_account_id,
                }
            }
        }
        _ => return Err(invalid()),
    };
    if !fields.is_empty() {
        return Err(invalid());
    }
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn exact_existing_job_destination_and_action_envelopes() {
        let job = raiun_core::MediaImportJob {
            id: "job".into(),
            revision: 0,
            account_id: "account".into(),
            source_root: std::env::temp_dir().join("raiun-synthetic-offline-media"),
            space_id: "space".into(),
            destination_root: "/Photos".into(),
            destination_root_resource_id: "destination-id".into(),
            filter: raiun_core::MediaFilter::Photos,
            exclusions: Vec::new(),
            organization: raiun_core::MediaOrganization::PreserveRelativePath,
            filesystem_mtime_utc: false,
            interval_seconds: 3600,
            enabled: true,
        };
        let request = json!({"action":"media_job_set","job":job,"expected_revision":0,"expected_account_id":"account"});
        match decode(&request).unwrap() {
            MediaRequest::Set {
                job,
                expected_revision,
                ..
            } => {
                assert_eq!(job.revision, 0);
                assert_eq!(expected_revision, 0);
            }
            _ => panic!("wrong request"),
        }
        assert!(matches!(
            decode(&json!({"action":"media_jobs","profile_id":"default"})),
            Ok(MediaRequest::Jobs)
        ));
        assert!(matches!(
            decode(&json!({"action":"media_destination","space_id":"space","path":"/Photos"})),
            Ok(MediaRequest::Destination { .. })
        ));
        for action in ["media_job_run", "media_job_remove"] {
            assert!(decode(&json!({"action":action,"job_id":"job","expected_revision":1,"expected_account_id":"account"})).is_ok());
        }
        assert!(decode(&json!({"action":"media_job_status","job_id":"job"})).is_ok());
    }
    #[test]
    fn malformed_or_unimplemented_requests_fail_without_values_in_error() {
        for value in [
            json!({"action":"media_jobs","token":"secret"}),
            json!({"action":"media_destination","space_id":"s","path":"/../escape"}),
            json!({"action":"media_job_run","job_id":"j","expected_revision":true,"expected_account_id":"a"}),
            json!({"action":"media_job_set","job":{"id":"j","unexpected":1},"expected_revision":0,"expected_account_id":"a"}),
            json!({"action":"media_job_remove","job_id":"j".repeat(129),"expected_revision":1,"expected_account_id":"a"}),
            json!({"action":"media_job_verify_upload","job_id":"j"}),
        ] {
            assert_eq!(decode(&value).err().unwrap(), "Invalid media request");
        }
    }
    fn recovery_request() -> Value {
        json!({"action":"media_job_recovery","job_id":"backup-one","expected_revision":7,
            "expected_account_id":"account-hash","limit":100,"cursor":null})
    }
    #[test]
    fn recovery_matches_unix_envelope_and_exact_engine_cursor() {
        let mut request = recovery_request();
        match decode(&request).unwrap() {
            MediaRequest::Recovery {
                job_id,
                expected_revision,
                expected_account_id,
                limit,
                cursor,
            } => {
                assert_eq!(job_id, "backup-one");
                assert_eq!(expected_revision, 7);
                assert_eq!(expected_account_id, "account-hash");
                assert_eq!(limit, MAX_MEDIA_RECOVERY_PAGE);
                assert!(cursor.is_none());
            }
            _ => panic!("wrong request"),
        }
        request.as_object_mut().unwrap().remove("cursor");
        assert!(matches!(
            decode(&request),
            Ok(MediaRequest::Recovery { cursor: None, .. })
        ));
        let cursor = MediaImportRecoveryCursor {
            origin: "https://synthetic.invalid".into(),
            space_id: "space".into(),
            source_root: "C:\\synthetic".into(),
            source_relative_path: "photo.jpg".into(),
            destination_path: "/Photos/photo.jpg".into(),
        };
        request["cursor"] = serde_json::to_value(&cursor).unwrap();
        request["limit"] = json!(1);
        match decode(&request).unwrap() {
            MediaRequest::Recovery {
                cursor: Some(actual),
                limit,
                ..
            } => {
                assert_eq!(actual, cursor);
                assert_eq!(limit, 1);
            }
            _ => panic!("cursor lost"),
        }
    }
    #[test]
    fn recovery_rejects_wrong_limits_scope_types_and_unknown_fields() {
        for limit in [
            json!(0),
            json!(101),
            json!(true),
            json!(-1),
            json!(1.5),
            json!("1"),
            Value::Null,
        ] {
            let mut request = recovery_request();
            request["limit"] = limit;
            assert_eq!(decode(&request).err().unwrap(), "Invalid media request");
        }
        for (key, value) in [
            ("expected_revision", json!(true)),
            ("expected_account_id", json!("")),
            ("job_id", json!("j".repeat(129))),
            ("extra", json!("not-exported")),
        ] {
            let mut request = recovery_request();
            request[key] = value;
            assert_eq!(decode(&request).err().unwrap(), "Invalid media request");
        }
        let mut request = recovery_request();
        request.as_object_mut().unwrap().remove("limit");
        assert!(decode(&request).is_err());
    }
    #[test]
    fn recovery_cursor_is_bounded_and_denies_unknown_or_malformed_fields() {
        let cursor = json!({"origin":"origin","space_id":"space","source_root":"root",
            "source_relative_path":"photo.jpg","destination_path":"/Photos/photo.jpg"});
        for key in [
            "origin",
            "space_id",
            "source_root",
            "source_relative_path",
            "destination_path",
        ] {
            for value in [
                json!(""),
                json!("a".repeat(4097)),
                json!("line\nvalue"),
                json!(false),
            ] {
                let mut request = recovery_request();
                request["cursor"] = cursor.clone();
                request["cursor"][key] = value;
                assert_eq!(decode(&request).err().unwrap(), "Invalid media request");
            }
        }
        for value in [
            json!([]),
            json!("cursor"),
            json!({"origin":"only-one-field"}),
        ] {
            let mut request = recovery_request();
            request["cursor"] = value;
            assert!(decode(&request).is_err());
        }
        let mut request = recovery_request();
        request["cursor"] = cursor;
        request["cursor"]["extra"] = json!(1);
        assert!(decode(&request).is_err());
    }
}

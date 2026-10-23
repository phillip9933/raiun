//! Pure subset of existing media RPCs; account/destination/runtime admission is external.
use raiun_core::{MediaImportJob, validate_media_import_jobs, validate_remote_path};
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
            source_root: "/missing-offline-media".into(),
            space_id: "space".into(),
            destination_root: "/Photos".into(),
            destination_root_resource_id: "destination-id".into(),
            filter: raiun_core::MediaFilter::Photos,
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
}

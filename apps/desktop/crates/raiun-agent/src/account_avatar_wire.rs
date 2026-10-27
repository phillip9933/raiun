//! Bounded image-only bridge. URLs, credentials and provider claims never reach the UI.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use raiun_opencloud::avatar::AvatarImage;
use serde_json::{Value, json};

pub(crate) fn response(
    profile: &str,
    generation: u64,
    image: Option<AvatarImage>,
) -> Result<Value, String> {
    let data_url = image
        .map(|image| {
            if !matches!(image.mime_type, "image/png" | "image/jpeg")
                || image.bytes.is_empty()
                || image.bytes.len() > 512 * 1024
            {
                return Err("The account photo is unavailable".to_owned());
            }
            Ok(format!(
                "data:{};base64,{}",
                image.mime_type,
                STANDARD.encode(image.bytes)
            ))
        })
        .transpose()?;
    Ok(json!({"profile_id": profile, "auth_generation": generation, "data_url": data_url}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn image_response_is_profile_bound_and_never_an_external_url() {
        let image = AvatarImage {
            mime_type: "image/png",
            bytes: vec![1, 2, 3],
        };
        let result = response("profile-a", 7, Some(image)).unwrap();
        assert_eq!(result["profile_id"], "profile-a");
        assert_eq!(result["auth_generation"], 7);
        assert_eq!(result["data_url"], "data:image/png;base64,AQID");
        assert!(response("profile-b", 8, None).unwrap()["data_url"].is_null());
    }
    #[test]
    fn bridge_rejects_active_content_and_control_message_overflow() {
        assert!(
            response(
                "a",
                1,
                Some(AvatarImage {
                    mime_type: "image/svg+xml",
                    bytes: vec![1]
                })
            )
            .is_err()
        );
        assert!(
            response(
                "a",
                1,
                Some(AvatarImage {
                    mime_type: "image/png",
                    bytes: vec![0; 512 * 1024 + 1]
                })
            )
            .is_err()
        );
    }
}

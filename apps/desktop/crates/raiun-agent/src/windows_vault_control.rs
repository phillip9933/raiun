// Child module of windows_folder_sync. Metadata inspection never uses its
// ordinary-Space filter or creates an unlocked session/decrypted native route.
use super::super::windows_vault_requests::VaultInspectRequest;
use super::*;
use raiun_opencloud::vault::{VaultMetadataClient, VaultRootListing};

impl Runtime {
    pub fn inspect_vault_metadata(
        &self,
        request: VaultInspectRequest,
        authorized: &AtomicU64,
    ) -> Result<Value, String> {
        self.check(authorized)?;
        if self.account_id.is_empty() || self.engine.revocation_handle().is_revoked() {
            return Err("The vault account is unavailable".into());
        }
        let account = self.account_id.clone();
        // This API resolves fresh Graph Space/DAV metadata from this exact
        // authenticated client and supports whole encrypted Spaces itself.
        // Do not weaken Runtime::space's ordinary/encrypted exclusion.
        let listing = VaultMetadataClient::new(self.client.as_ref())
            .inspect_vault(&request.space_id, &request.root_path)
            .map_err(|_| "Could not inspect vault metadata")?;
        self.check(authorized)?;
        if self.account_id != account || self.engine.revocation_handle().is_revoked() {
            return Err("The vault account changed during inspection".into());
        }
        inspection_value(&request, &listing)
    }
}

fn inspection_value(
    request: &VaultInspectRequest,
    listing: &VaultRootListing,
) -> Result<Value, String> {
    if listing.space_id != request.space_id
        || listing.root_path.trim_end_matches('/') != request.root_path.trim_end_matches('/')
        || !listing.root.directory
        || listing.root.id.is_empty()
    {
        return Err("Vault metadata does not match the selected root".into());
    }
    if request
        .root_resource_id
        .as_ref()
        .is_some_and(|expected| expected != &listing.root.id)
    {
        return Err("Vault root changed; select it again before unlocking".into());
    }
    Ok(json!({
        "root_path":listing.root_path,
        "root_resource_id":listing.root.id,
        // Server metadata only; no password/token authentication was attempted.
        "root_etag":listing.root.strong_etag,
        "initialized":listing.integrity_token.is_some(),
        "writable":listing.root.writable,
        "unlocked":false,
        "vault_mount_ready":false,
        "vault_mount_writable":false,
        "vault_mount_write_unavailable_reason":"route_not_installed",
        "remembered_status":"unavailable",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use raiun_opencloud::vault::VaultDavEntry;
    fn listing() -> VaultRootListing {
        VaultRootListing {
            space_id: "space".into(),
            space_dav_root: "https://synthetic.invalid/dav/space/".into(),
            root_path: "/Photos.vault/".into(),
            root: VaultDavEntry {
                id: "root-id".into(),
                path: "/Photos.vault/".into(),
                raw_name: "Photos.vault".into(),
                directory: true,
                modified_unix: 1,
                writable: true,
                size: 0,
                strong_etag: Some("\"server-hint\"".into()),
                vault_evidence: vec![],
                href: "https://synthetic.invalid/dav/space/Photos.vault/".into(),
            },
            children: vec![],
            integrity_token: Some("untrusted-server-token".into()),
            evidence: vec![],
        }
    }
    #[test]
    fn metadata_presence_never_grants_unlock_or_route_or_saved_password() {
        let request = VaultInspectRequest {
            space_id: "space".into(),
            root_path: "/Photos.vault".into(),
            root_resource_id: Some("root-id".into()),
        };
        let mut listing = listing();
        let value = inspection_value(&request, &listing).unwrap();
        assert_eq!(value["initialized"], true);
        assert_eq!(value["root_etag"], "\"server-hint\"");
        for key in ["unlocked", "vault_mount_ready", "vault_mount_writable"] {
            assert_eq!(value[key], false);
        }
        assert_eq!(
            value["vault_mount_write_unavailable_reason"],
            "route_not_installed"
        );
        assert_eq!(value["remembered_status"], "unavailable");
        assert!(value.get("integrity_token").is_none());
        assert!(value.get("children").is_none());
        listing.integrity_token = None;
        assert_eq!(
            inspection_value(&request, &listing).unwrap()["initialized"],
            false
        );
    }
    #[test]
    fn substituted_root_or_space_is_refused_without_server_values_in_error() {
        let request = VaultInspectRequest {
            space_id: "space".into(),
            root_path: "/Photos.vault".into(),
            root_resource_id: Some("other-root".into()),
        };
        assert_eq!(
            inspection_value(&request, &listing()).unwrap_err(),
            "Vault root changed; select it again before unlocking"
        );
        let mut request = request;
        request.root_resource_id = None;
        let mut listing = listing();
        listing.space_id = "other-space".into();
        assert!(inspection_value(&request, &listing).is_err());
        listing.space_id = "space".into();
        listing.root.directory = false;
        assert!(inspection_value(&request, &listing).is_err());
    }
}

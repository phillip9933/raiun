//! Explicit new-folder vault creation; never initializes an existing collection.
use crate::vault::{VaultMetadataClient, VaultRootListing};
use crate::{OpenCloudClient, append_logical_path, checked, invalid, network, read_bounded};
use raiun_core::backend::{CloudBackend, CloudError, ErrorKind};
use reqwest::{
    Method, StatusCode,
    header::{CONTENT_TYPE, IF_MATCH, IF_NONE_MATCH},
};
use url::Url;

/// An opaque capability for a collection created by this client call. Failure
/// leaves the empty marked folder for inspection; nothing is deleted on error.
pub struct NewRemoteVault {
    client: OpenCloudClient,
    listing: VaultRootListing,
}
impl NewRemoteVault {
    pub fn root(&self) -> &VaultRootListing {
        &self.listing
    }

    /// Set an initial proof only while the newly-created root is still empty,
    /// has the same resource identity and has no existing integrity property.
    /// The returned readback must still be checked by the local draft codec.
    pub fn initialize(self, integrity_token: &str) -> Result<VaultRootListing, CloudError> {
        if integrity_token.is_empty()
            || integrity_token.len() > 4096
            || !integrity_token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
        {
            return Err(invalid("invalid vault integrity token encoding"));
        }
        let current = VaultMetadataClient::new(&self.client)
            .inspect_folder_vault(&self.listing.space_id, &self.listing.root_path)?;
        if current.root.id != self.listing.root.id
            || !current.children.is_empty()
            || current.integrity_token.is_some()
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "new vault changed before initialization; no property was written",
            ));
        }
        let etag = current
            .root
            .strong_etag
            .as_deref()
            .ok_or_else(|| invalid("new vault requires a strong root ETag"))?;
        let url =
            Url::parse(&current.root.href).map_err(|_| invalid("invalid verified vault href"))?;
        let (request, auth) = self.client.request(
            Method::from_bytes(b"PROPPATCH").expect("static method"),
            &url,
        )?;
        let body = format!(
            "<d:propertyupdate xmlns:d=\"DAV:\" xmlns:ocrclone=\"ocrclone\"><d:set><d:prop><ocrclone:integrity-id>{integrity_token}</ocrclone:integrity-id></d:prop></d:set></d:propertyupdate>"
        );
        let response = request
            .header(IF_MATCH, etag)
            .header(CONTENT_TYPE, "application/xml; charset=utf-8")
            .body(body)
            .send()
            .map_err(network)?;
        let mut response = checked(response, &[StatusCode::MULTI_STATUS], &auth)?;
        // A 207 alone is not success; exact bounded readback below establishes
        // the property, root identity and emptiness before a key is published.
        read_bounded(&mut response, 64 * 1024)?;
        let verified = VaultMetadataClient::new(&self.client)
            .inspect_folder_vault(&self.listing.space_id, &self.listing.root_path)?;
        if verified.root.id != self.listing.root.id
            || !verified.children.is_empty()
            || verified.integrity_token.as_deref() != Some(integrity_token)
        {
            return Err(CloudError::new(
                ErrorKind::Conflict,
                "vault initialization was not confirmed; the folder was retained and remains locked",
            ));
        }
        Ok(verified)
    }
}

/// Create a new `.vault` folder below a verified ordinary writable parent.
/// MKCOL plus initial metadata are separate WebDAV operations, not a transaction.
pub fn create_folder_vault(
    client: &OpenCloudClient,
    space: &str,
    parent: &str,
    name: &str,
) -> Result<NewRemoteVault, CloudError> {
    crate::validate_logical_path(parent)?;
    if name.len() > 255
        || name.trim() != name
        || name.len() <= 6
        || !name.to_ascii_lowercase().ends_with(".vault")
        || name.contains(['/', '\\'])
        || name.chars().any(char::is_control)
    {
        return Err(invalid(
            "a vault name must be one nonempty component ending in .vault",
        ));
    }
    let (selected, parent_url) = client.resolve_dav(space, parent)?;
    client.ensure_writable_target(&selected, &parent_url, parent)?;
    let parent_entry = client.stat(space, parent)?;
    if !parent_entry.directory || !parent_entry.writable || parent_entry.encrypted {
        return Err(CloudError::new(
            ErrorKind::Forbidden,
            "vault parent must be an ordinary writable folder",
        ));
    }
    let path = format!("{}/{name}", parent.trim_end_matches('/'));
    let root = Url::parse(&selected.dav_url).map_err(|_| invalid("invalid Space root"))?;
    let url = append_logical_path(&root, &path)?;
    let (request, auth) =
        client.request(Method::from_bytes(b"MKCOL").expect("static method"), &url)?;
    let response = request.header(IF_NONE_MATCH, "*").send().map_err(network)?;
    checked(response, &[StatusCode::CREATED], &auth)?;
    let listing = VaultMetadataClient::new(client).inspect_folder_vault(space, &path)?;
    if !listing.children.is_empty() || listing.integrity_token.is_some() {
        return Err(CloudError::new(
            ErrorKind::Conflict,
            "new vault is not empty; folder retained without initialization",
        ));
    }
    Ok(NewRemoteVault {
        client: client.clone(),
        listing,
    })
}

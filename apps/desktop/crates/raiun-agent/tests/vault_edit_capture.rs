// Portable semantic tests of inert Windows-owned models; no native I/O.
#[allow(dead_code)]
#[path = "../src/vault_custody.rs"]
mod vault_custody;
#[allow(dead_code)]
#[path = "../src/vault_edit_capture.rs"]
mod vault_edit_capture;

#[allow(dead_code)]
#[path = "../src/vault_edit_retention.rs"]
mod vault_edit_retention;

#[allow(dead_code)]
#[path = "../src/vault_edit_upload.rs"]
mod vault_edit_upload;

#[allow(dead_code)]
#[path = "../src/root_manifest.rs"]
mod root_manifest;

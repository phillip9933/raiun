// Portable protected-CAS semantics only; synthetic native proofs are cfg(test).
#[allow(dead_code)]
#[path = "../src/root_manifest.rs"]
mod root_manifest;
#[allow(dead_code)]
#[path = "../src/vault_custody.rs"]
mod vault_custody;
#[allow(dead_code)]
#[path = "../src/vault_edit_capture.rs"]
mod vault_edit_capture;
#[allow(dead_code)]
#[path = "../src/vault_edit_disposition.rs"]
mod vault_edit_disposition;
#[allow(dead_code)]
#[path = "../src/vault_edit_upload.rs"]
mod vault_edit_upload;

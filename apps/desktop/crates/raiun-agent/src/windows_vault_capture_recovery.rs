//! Explicit, read-only access to one authenticated retained Windows vault edit.
//! A Save Copy is an intentional plaintext export, never an upload or retry.

use super::windows_vault_custody::{RecoveryCaptureMetadata, WindowsVaultCustody};
use raiun_cloudfiles_windows::{
    ConfiguredRootIdentity, ConfiguredRootLease, ProviderScope, pin_registered_configured_root,
};
use raiun_control_windows::{PinnedDirectory, PinnedFileIdentity};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, Prefix},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const MAX_PAGE: usize = 100;
const MAX_ITEMS: usize = 4096;
const MAX_CURSORS: usize = 64;
const TOKEN_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_TOKEN_BYTES: usize = 48;
const MAX_DESTINATION_COMPONENT: usize = 255;
const MAX_PUBLIC_NAME_BYTES: usize = 96;
pub(super) const MAX_RESPONSE_BYTES: usize = 64 * 1024;

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Eq, PartialEq)]
pub(super) struct RecoveryScope {
    pub(super) space_id: String,
    pub(super) root_resource_id: String,
    pub(super) remote_root: String,
}

#[derive(Clone)]
struct TokenBinding {
    generation: u64,
    context: String,
    scope: RecoveryScope,
    capture_id: String,
    expires: Instant,
}

#[derive(Clone)]
struct CursorBinding {
    generation: u64,
    context: String,
    scope: RecoveryScope,
    after_capture_id: String,
    expires: Instant,
}

#[derive(Default)]
pub(super) struct Tokens {
    items: HashMap<String, TokenBinding>,
    cursors: HashMap<String, CursorBinding>,
}

#[derive(Serialize)]
struct PublicItem {
    item_token: String,
    file_name: String,
    body_length: usize,
}

#[derive(Serialize)]
pub(super) struct RecoveryPage {
    schema_version: u8,
    profile_id: String,
    auth_generation: u64,
    items: Vec<PublicItem>,
    next_cursor: Option<String>,
    read_only: bool,
}

#[derive(Serialize)]
pub(super) struct CopyReceipt {
    schema_version: u8,
    body_length: usize,
    read_only: bool,
}

pub(super) struct SaveCopyDestination<'a> {
    pub(super) root_path: &'a Path,
    pub(super) root_identity: ConfiguredRootIdentity,
    pub(super) destination: &'a Path,
}

/// Hold the exact registered root, including its legitimate Cloud Files state.
/// Destination directories continue to require the strict plain-directory pin.
struct RegisteredRecoveryRoot<'a> {
    path: &'a Path,
    expected: ConfiguredRootIdentity,
    _lease: ConfiguredRootLease,
}
impl<'a> RegisteredRecoveryRoot<'a> {
    fn open(path: &'a Path, expected: ConfiguredRootIdentity) -> Result<Self> {
        let lease = pin_registered_configured_root(path, expected)
            .map_err(|_| "The registered Windows drive root could not be pinned")?;
        if lease.identity() != expected {
            return Err("The registered Windows drive root changed".into());
        }
        Ok(Self {
            path,
            expected,
            _lease: lease,
        })
    }
    fn identity(&self) -> PinnedFileIdentity {
        PinnedFileIdentity {
            volume_serial: self.expected.volume_serial,
            file_index: self.expected.file_index,
        }
    }
    fn verify_path(&self) -> Result<()> {
        // Re-pin both the path identity and OS registration at every former
        // generic root revalidation boundary; the original lease stays held.
        let current = pin_registered_configured_root(self.path, self.expected)
            .map_err(|_| "The registered Windows drive root changed")?;
        if current.identity() != self.expected {
            return Err("The registered Windows drive root changed".into());
        }
        Ok(())
    }
}

impl Tokens {
    pub(super) fn after(
        &mut self,
        token: Option<&str>,
        generation: u64,
        context: &str,
        scope: &RecoveryScope,
    ) -> Result<Option<String>> {
        self.prune();
        let Some(token) = token else {
            return Ok(None);
        };
        validate_token(token)?;
        let binding = self
            .cursors
            .get(token)
            .ok_or("Saved vault edits page expired; reopen the list")?;
        if binding.generation != generation
            || binding.context != context
            || &binding.scope != scope
            || binding.expires <= Instant::now()
        {
            return Err("Saved vault edits page no longer matches this account and vault".into());
        }
        Ok(Some(binding.after_capture_id.clone()))
    }

    pub(super) fn item(
        &mut self,
        token: &str,
        generation: u64,
        context: &str,
        scope: &RecoveryScope,
    ) -> Result<String> {
        self.prune();
        validate_token(token)?;
        let binding = self
            .items
            .get(token)
            .ok_or("Saved vault edit selection expired; reopen the list")?;
        if binding.generation != generation
            || binding.context != context
            || &binding.scope != scope
            || binding.expires <= Instant::now()
        {
            return Err(
                "Saved vault edit selection no longer matches this account and vault".into(),
            );
        }
        Ok(binding.capture_id.clone())
    }

    pub(super) fn page(
        &mut self,
        profile_id: &str,
        generation: u64,
        context: &str,
        scope: RecoveryScope,
        rows: Vec<RecoveryCaptureMetadata>,
        after: Option<String>,
    ) -> Result<RecoveryPage> {
        self.prune();
        if generation == 0 || rows.len() > MAX_PAGE || rows.len() > MAX_ITEMS {
            return Err("Saved vault edit page is unavailable".into());
        }
        if self.items.len().saturating_add(rows.len()) > MAX_ITEMS {
            // The service is bounded. Old selectors become stale and callers
            // must refresh their visible page before using them again.
            self.items.clear();
            self.cursors.clear();
        } else if after.is_some() && self.cursors.len() >= MAX_CURSORS {
            self.cursors.clear();
        }
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let token = random_token()?;
            self.items.insert(
                token.clone(),
                TokenBinding {
                    generation,
                    context: context.to_owned(),
                    scope: scope.clone(),
                    capture_id: row.capture_id,
                    expires: Instant::now() + TOKEN_TTL,
                },
            );
            items.push(PublicItem {
                item_token: token,
                file_name: safe_basename(&row.remote_path),
                body_length: row.body_len,
            });
        }
        let next_cursor = match after {
            Some(after_capture_id) => {
                let token = random_token()?;
                self.cursors.insert(
                    token.clone(),
                    CursorBinding {
                        generation,
                        context: context.to_owned(),
                        scope,
                        after_capture_id,
                        expires: Instant::now() + TOKEN_TTL,
                    },
                );
                Some(token)
            }
            None => None,
        };
        Ok(RecoveryPage {
            schema_version: 1,
            profile_id: profile_id.to_owned(),
            auth_generation: generation,
            items,
            next_cursor,
            read_only: true,
        })
    }

    fn prune(&mut self) {
        let now = Instant::now();
        self.items.retain(|_, token| token.expires > now);
        self.cursors.retain(|_, token| token.expires > now);
    }
}

pub(super) fn page_from_custody(
    custody: &WindowsVaultCustody,
    owner: &ProviderScope,
    scope: &RecoveryScope,
    after_capture_id: Option<&str>,
    limit: usize,
) -> Result<(Vec<RecoveryCaptureMetadata>, Option<String>)> {
    if limit == 0 || limit > MAX_PAGE {
        return Err("Saved vault edit page size must be between 1 and 100".into());
    }
    custody
        .recovery_capture_page(
            owner,
            &scope.space_id,
            &scope.root_resource_id,
            &scope.remote_root,
            after_capture_id,
            limit,
        )
        .map_err(|_| "Protected saved vault edits could not be verified".to_owned())
}

pub(super) fn save_copy(
    custody: &WindowsVaultCustody,
    owner: &ProviderScope,
    scope: &RecoveryScope,
    capture_id: &str,
    destination: SaveCopyDestination<'_>,
    still_current: impl Fn() -> bool,
) -> Result<CopyReceipt> {
    if !still_current() {
        return Err("The account or Windows drive changed".into());
    }
    let root = RegisteredRecoveryRoot::open(destination.root_path, destination.root_identity)?;
    let (parent_path, component) = validate_destination(destination.destination)?;
    let parent = PinnedDirectory::open(parent_path)
        .map_err(|_| "The Save Copy destination folder is unavailable or redirected")?;
    parent
        .verify_path()
        .map_err(|_| "The Save Copy destination folder changed")?;
    validate_parent_outside_root(parent_path, &parent, root.identity())?;
    let retained = custody
        .recovery_capture_body(
            owner,
            &scope.space_id,
            &scope.root_resource_id,
            &scope.remote_root,
            capture_id,
        )
        .map_err(|_| "The selected saved vault edit could not be authenticated")?;
    if !still_current() {
        return Err("The account or Windows drive changed".into());
    }
    let body = retained.bytes_for_recovery();
    if body.len() > raiun_cloudfiles_windows::MAX_VAULT_EDIT_CAPTURE_BYTES {
        return Err("The selected saved vault edit has an unsupported size".into());
    }
    let body_sha256: [u8; 32] = Sha256::digest(body).into();
    let (stage_name, mut stage, stage_identity) = create_stage(&parent)?;
    let staged = (|| {
        stage
            .write_all(body)
            .map_err(|_| "Could not write the Save Copy staging file")?;
        stage
            .sync_all()
            .map_err(|_| "Could not flush the Save Copy staging file")?;
        stage
            .seek(SeekFrom::Start(0))
            .map_err(|_| "Could not verify the Save Copy staging file")?;
        let actual = read_bounded(&mut stage, body.len())?;
        verify_bytes(&actual, body.len(), &body_sha256)?;
        parent
            .verify_path()
            .map_err(|_| "The Save Copy destination folder changed")?;
        root.verify_path()
            .map_err(|_| "The registered Windows drive root changed")?;
        if !still_current() {
            return Err("The account or Windows drive changed".into());
        }
        Ok::<(), String>(())
    })();
    drop(stage);
    if let Err(error) = staged {
        if !remove_exact_stage(&parent, &stage_name, stage_identity) {
            return Err(format!(
                "{error}; a partial staging file may remain in the chosen destination folder"
            ));
        }
        return Err(error);
    }
    if !still_current() {
        if !remove_exact_stage(&parent, &stage_name, stage_identity) {
            return Err(
                "The account changed; a staging file may remain in the chosen destination folder"
                    .into(),
            );
        }
        return Err("The account or Windows drive changed".into());
    }
    if root.verify_path().is_err() {
        if !remove_exact_stage(&parent, &stage_name, stage_identity) {
            return Err("The registered drive changed; a staging file may remain in the chosen destination folder".into());
        }
        return Err("The registered Windows drive root changed".into());
    }
    let published_identity = match parent.publish_staged_file(
        &stage_name,
        component,
        stage_identity,
    ) {
        Ok(identity) => identity,
        Err(_) => {
            // A rename result may be ambiguous. Only the exact staging name
            // and identity may be removed; never inspect/delete the destination.
            let cleaned = remove_exact_stage(&parent, &stage_name, stage_identity);
            return Err(if cleaned {
                "Save Copy could not confirm no-clobber publication; inspect the chosen destination"
                    .into()
            } else {
                "Save Copy publication is uncertain; a staging or final file may remain, so inspect the chosen destination".into()
            });
        }
    };
    if !still_current() {
        return Err(
            "Save Copy was published, but account state changed; inspect the destination".into(),
        );
    }
    let (mut published, final_identity) = parent
        .open_immutable_regular_file(component)
        .map_err(|_| "Save Copy was published but final readback could not be confirmed")?;
    if final_identity != published_identity {
        return Err("Save Copy was published but final file identity changed".into());
    }
    let actual = read_bounded(&mut published, body.len())
        .map_err(|_| "Save Copy was published but final contents could not be verified")?;
    verify_bytes(&actual, body.len(), &body_sha256)
        .map_err(|_| "Save Copy was published but final contents did not match")?;
    parent
        .verify_path()
        .map_err(|_| "Save Copy was published but the destination folder changed")?;
    root.verify_path()
        .map_err(|_| "Save Copy was published but the registered drive changed")?;
    if !still_current() {
        return Err(
            "Save Copy was published, but account state changed; inspect the destination".into(),
        );
    }
    Ok(CopyReceipt {
        schema_version: 1,
        body_length: body.len(),
        read_only: true,
    })
}

fn validate_destination(destination: &Path) -> Result<(&Path, &OsStr)> {
    if !destination.is_absolute()
        || destination
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        || !matches!(destination.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)))
    {
        return Err("Choose a fresh destination on a local Windows drive".into());
    }
    let file_name = destination
        .file_name()
        .ok_or("Choose a file name for Save Copy")?;
    validate_file_name(file_name)?;
    let parent_path = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or("Choose a destination folder for Save Copy")?;
    Ok((parent_path, file_name))
}

fn validate_parent_outside_root(
    parent_path: &Path,
    pinned_parent: &PinnedDirectory,
    root_identity: PinnedFileIdentity,
) -> Result<()> {
    // Walk by opening each actual directory without following reparses. The
    // held parent pins its complete ancestor chain for this walk. Bind the
    // caller's already-validated destination path to that pinned identity,
    // then traverse that exact lexical path for the root boundary check.
    pinned_parent
        .verify_path()
        .map_err(|_| "The Save Copy destination folder changed")?;
    let checked_parent = PinnedDirectory::open(parent_path)
        .map_err(|_| "A Save Copy destination ancestor is unavailable or redirected")?;
    if checked_parent.identity() != pinned_parent.identity() {
        return Err("The Save Copy destination folder changed".into());
    }
    let mut ancestor = parent_path.to_path_buf();
    for _ in 0..256 {
        let pinned = PinnedDirectory::open(&ancestor)
            .map_err(|_| "A Save Copy destination ancestor is unavailable or redirected")?;
        if pinned.identity() == root_identity {
            return Err("Save Copy must be outside the registered Windows drive folder".into());
        }
        let Some(parent) = ancestor.parent() else {
            return Ok(());
        };
        if parent == ancestor {
            return Ok(());
        }
        ancestor = parent.to_path_buf();
    }
    Err("Save Copy destination ancestry exceeds the validation limit".into())
}

fn validate_file_name(name: &OsStr) -> Result<()> {
    let value = name
        .to_str()
        .ok_or("Choose a valid Windows file name for Save Copy")?;
    let utf16_len = value.encode_utf16().count();
    let base = value
        .split('.')
        .next()
        .unwrap_or(value)
        .trim_end_matches([' ', '.']);
    let upper = base.to_ascii_uppercase();
    if value.is_empty()
        || utf16_len > MAX_DESTINATION_COMPONENT
        || value.len() > MAX_DESTINATION_COMPONENT * 4
        || value.ends_with([' ', '.'])
        || value.chars().any(char::is_control)
        || value.contains(['/', '\\', ':', '\0'])
        || matches!(
            upper.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        )
        || (upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && matches!(upper.as_bytes()[3], b'1'..=b'9'))
    {
        return Err("Choose a valid fresh file name for Save Copy".into());
    }
    Ok(())
}

fn create_stage(
    parent: &PinnedDirectory,
) -> Result<(std::ffi::OsString, File, PinnedFileIdentity)> {
    for _ in 0..4 {
        let name = std::ffi::OsString::from(format!(".raiun-copy-{}.tmp", random_token()?));
        match parent.create_new_file(&name) {
            Ok((file, identity)) => return Ok((name, file, identity)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err("Could not create a unique Save Copy staging file".into()),
        }
    }
    Err("Could not create a unique Save Copy staging file".into())
}

fn remove_exact_stage(
    parent: &PinnedDirectory,
    name: &OsStr,
    expected: PinnedFileIdentity,
) -> bool {
    matches!(parent.remove_file_if_identity(name, expected), Ok(true))
}

fn read_bounded(file: &mut File, expected: usize) -> Result<Zeroizing<Vec<u8>>> {
    let limit = expected.checked_add(1).ok_or("Save Copy size is invalid")?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        expected.min(raiun_cloudfiles_windows::MAX_VAULT_EDIT_CAPTURE_BYTES),
    ));
    file.take(limit as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "Could not read back the Save Copy file")?;
    Ok(bytes)
}

fn verify_bytes(actual: &[u8], expected_len: usize, expected_sha256: &[u8; 32]) -> Result<()> {
    let actual_sha256: [u8; 32] = Sha256::digest(actual).into();
    if actual.len() != expected_len || &actual_sha256 != expected_sha256 {
        return Err("Save Copy readback did not match the authenticated body".into());
    }
    Ok(())
}

fn safe_basename(remote_path: &str) -> String {
    let basename = remote_path.rsplit('/').next().unwrap_or_default();
    let mut safe = String::new();
    for character in basename.chars().filter(|character| {
        !character.is_control() && !matches!(character, '/' | '\\' | ':' | '\0')
    }) {
        if safe.len() + character.len_utf8() > MAX_PUBLIC_NAME_BYTES {
            break;
        }
        safe.push(character);
    }
    while safe.ends_with([' ', '.']) {
        safe.pop();
    }
    if safe.is_empty() || validate_file_name(OsStr::new(&safe)).is_err() {
        "recovered-file".into()
    } else {
        safe
    }
}

fn random_token() -> Result<String> {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).map_err(|_| "Could not create a protected recovery token")?;
    Ok(hex(&bytes))
}

fn validate_token(token: &str) -> Result<()> {
    if token.len() != MAX_TOKEN_BYTES || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Saved vault edit token is invalid".into());
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> RecoveryScope {
        RecoveryScope {
            space_id: "space".into(),
            root_resource_id: "root".into(),
            remote_root: "/Vault".into(),
        }
    }

    #[test]
    fn tokens_are_scope_and_generation_bound_and_pages_are_capped() {
        let mut tokens = Tokens::default();
        let rows = vec![RecoveryCaptureMetadata {
            capture_id: "capture_1".into(),
            remote_path: "/name.txt".into(),
            body_len: 4,
        }];
        let page = tokens
            .page(
                "profile",
                4,
                "root-context",
                scope(),
                rows,
                Some("capture_1".into()),
            )
            .unwrap();
        assert_eq!(page.schema_version, 1);
        assert_eq!(page.items[0].file_name, "name.txt");
        assert_eq!(page.items[0].body_length, 4);
        let encoded = serde_json::to_string(&page).unwrap();
        assert!(!encoded.contains("capture_1"));
        assert!(!encoded.contains("/name.txt"));
        let item = page.items[0].item_token.clone();
        assert_eq!(
            tokens.item(&item, 4, "root-context", &scope()).unwrap(),
            "capture_1"
        );
        assert!(tokens.item(&item, 5, "root-context", &scope()).is_err());
        let cursor = page.next_cursor.as_deref().unwrap();
        assert!(
            tokens
                .after(Some(cursor), 4, "root-context", &scope())
                .unwrap()
                .is_some()
        );
        assert!(
            tokens
                .after(Some(cursor), 5, "root-context", &scope())
                .is_err()
        );
        let mut foreign_scope = scope();
        foreign_scope.space_id = "other-space".into();
        assert!(
            tokens
                .after(Some(cursor), 4, "root-context", &foreign_scope)
                .is_err()
        );
        assert!(
            tokens
                .page("profile", 0, "root-context", scope(), Vec::new(), None)
                .is_err()
        );
        assert!(
            tokens
                .page(
                    "profile",
                    4,
                    "root-context",
                    scope(),
                    Vec::new(),
                    Some("last".into())
                )
                .is_err()
        );
    }

    #[test]
    fn basename_disclosure_is_flat_and_bounded() {
        assert_eq!(safe_basename("/folder/name.txt"), "name.txt");
        assert_eq!(safe_basename("/folder/../NUL.txt"), "recovered-file");
        assert_eq!(safe_basename("/folder/"), "recovered-file");
    }

    #[test]
    fn selected_names_reject_windows_path_aliases() {
        assert!(validate_file_name(OsStr::new("name.txt")).is_ok());
        for name in [
            "",
            ".",
            "..",
            "name:stream",
            "CON.txt",
            "LPT9.log",
            "trail.",
        ] {
            assert!(validate_file_name(OsStr::new(name)).is_err(), "{name}");
        }
    }

    #[test]
    fn recovery_root_requires_exact_os_registration_not_a_plain_directory() {
        let scratch =
            std::env::temp_dir().join(format!("raiun-recovery-root-{}", random_token().unwrap()));
        std::fs::create_dir(&scratch).unwrap();
        let plain = PinnedDirectory::open(&scratch).unwrap();
        let identity = plain.identity();
        let expected = ConfiguredRootIdentity {
            volume_serial: identity.volume_serial,
            file_index: identity.file_index,
        };
        assert!(RegisteredRecoveryRoot::open(&scratch, expected).is_err());
        assert!(
            RegisteredRecoveryRoot::open(
                &scratch,
                ConfiguredRootIdentity {
                    file_index: expected.file_index + 1,
                    ..expected
                },
            )
            .is_err()
        );
        drop(plain);
        std::fs::remove_dir(scratch).unwrap();
    }

    #[test]
    fn destination_must_be_outside_the_pinned_root() {
        let scratch =
            std::env::temp_dir().join(format!("raiun-recovery-{}", random_token().unwrap()));
        let root_path = scratch.join("registered-root");
        let outside_path = scratch.join("outside");
        std::fs::create_dir_all(&root_path).unwrap();
        std::fs::create_dir_all(&outside_path).unwrap();
        let root = PinnedDirectory::open(&root_path).unwrap();
        let inside = PinnedDirectory::open(&root_path).unwrap();
        let outside = PinnedDirectory::open(&outside_path).unwrap();
        let nested_path = root_path.join("nested");
        std::fs::create_dir(&nested_path).unwrap();
        let nested = PinnedDirectory::open(&nested_path).unwrap();
        assert!(validate_parent_outside_root(&root_path, &inside, root.identity()).is_err());
        assert!(validate_parent_outside_root(&outside_path, &outside, root.identity()).is_ok());
        assert!(validate_parent_outside_root(&nested_path, &nested, root.identity()).is_err());
        drop(nested);
        drop(inside);
        drop(outside);
        drop(root);
        std::fs::remove_dir_all(scratch).unwrap();
    }
}

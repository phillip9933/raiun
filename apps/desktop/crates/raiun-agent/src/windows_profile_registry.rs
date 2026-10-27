//! Storage-free Windows v1 registry with additive root exclusion reservations.
//! Legacy empty reservations require protected-storage inventory before admission.
//! Selection changes only the selected ID; it does not stop or revoke runtimes.
//! The caller owns random ID allocation, protected persistence and runtime admission.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
const DEFAULT_ID: &str = "default";
const REGISTRY_VERSION: u32 = 1;
const MAX_REGISTRY_BYTES: usize = 1_048_576;
const MAX_PROFILES: usize = 16;
const MAX_LABEL_BYTES: usize = 256;
const MAX_SOURCE_RESERVATIONS: usize = 128;
const MAX_VAULT_RESERVATIONS: usize = 128;

fn is_false(value: &bool) -> bool {
    !value
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRecord {
    label: String,
    #[serde(default, skip_serializing_if = "is_false")]
    removed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    root_reservations: Vec<RootReservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    source_reservations: Vec<SourceReservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    vault_reservations: Vec<VaultReservation>,
}
impl ProfileRecord {
    pub fn root_reservations(&self) -> &[RootReservation] {
        &self.root_reservations
    }
    pub fn source_reservations(&self) -> &[SourceReservation] {
        &self.source_reservations
    }
    pub fn vault_reservations(&self) -> &[VaultReservation] {
        &self.vault_reservations
    }
    pub fn label(&self) -> &str {
        &self.label
    }
    pub fn removed(&self) -> bool {
        self.removed
    }
}

/// A durable exclusion reservation only; never account or registration authority.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootReservation {
    path: String,
    volume_serial: u32,
    file_index: u64,
    may_be_registered: bool,
}
impl std::fmt::Debug for RootReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootReservation")
            .field("path", &"<redacted>")
            .field("may_be_registered", &self.may_be_registered)
            .finish_non_exhaustive()
    }
}
impl RootReservation {
    pub fn new(
        path: String,
        volume_serial: u32,
        file_index: u64,
        may_be_registered: bool,
    ) -> Result<Self, String> {
        let value = Self {
            path,
            volume_serial,
            file_index,
            may_be_registered,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn volume_serial(&self) -> u32 {
        self.volume_serial
    }
    pub fn file_index(&self) -> u64 {
        self.file_index
    }
    pub fn may_be_registered(&self) -> bool {
        self.may_be_registered
    }
    fn validate(&self) -> Result<(), String> {
        let bytes = self.path.as_bytes();
        // Lexical analogue of the native plain-drive admission, not a pin or
        // canonicalization: no UNC/device paths, drive root, dot/parent or ADS.
        let valid_prefix = bytes.len() > 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/');
        if !valid_prefix
            || bytes.len() > 32_000
            || self.file_index == 0
            || self.path.chars().any(char::is_control)
        {
            return Err("Invalid root reservation".into());
        }
        let mut components = self.path[3..]
            .split(['\\', '/'])
            .filter(|part| !part.is_empty())
            .peekable();
        if components.peek().is_none()
            || components.any(|part| part == "." || part == ".." || part.contains(':'))
        {
            return Err("Invalid root reservation".into());
        }
        Ok(())
    }
}

/// Saved-source exclusion only; never an authenticated account or execution permit.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    FolderPair,
    MediaJob,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceReservation {
    scope_digest: String,
    kind: SourceKind,
    id: String,
    root: RootReservation,
}
impl std::fmt::Debug for SourceReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceReservation").finish_non_exhaustive()
    }
}
impl SourceReservation {
    pub fn new(
        scope_digest: String,
        kind: SourceKind,
        id: String,
        root: RootReservation,
    ) -> Result<Self, String> {
        let value = Self {
            scope_digest,
            kind,
            id,
            root,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }
    pub fn kind(&self) -> SourceKind {
        self.kind
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn root(&self) -> &RootReservation {
        &self.root
    }
    fn key(&self) -> (&str, SourceKind, &str, &str) {
        (&self.scope_digest, self.kind, &self.id, self.root.path())
    }
    fn validate(&self) -> Result<(), String> {
        self.root.validate()?;
        if self.root.may_be_registered()
            || self.scope_digest.len() != 64
            || !self
                .scope_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.id.trim().is_empty()
            || self.id.len() > 128
            || self.id.chars().any(char::is_control)
        {
            return Err("Invalid source reservation".into());
        }
        Ok(())
    }
}

/// Durable encrypted-location exclusion only. Never an unlock, credential,
/// authenticated identity, or native registration authority. The broker must
/// persist it before projecting a verified vault and restore matching exclusions
/// before ordinary catalogue/cache access. Reservations survive lock/logout.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultReservation {
    scope_digest: String,
    space_id: String,
    root_resource_id: String,
    root_path: String,
}
impl std::fmt::Debug for VaultReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultReservation").finish_non_exhaustive()
    }
}
impl VaultReservation {
    pub fn new(
        scope_digest: String,
        space_id: String,
        root_resource_id: String,
        root_path: String,
    ) -> Result<Self, String> {
        let row = Self {
            scope_digest,
            space_id,
            root_resource_id,
            root_path,
        };
        row.validate()?;
        Ok(row)
    }
    pub fn space_id(&self) -> &str {
        &self.space_id
    }
    pub fn root_path(&self) -> &str {
        &self.root_path
    }
    fn key(&self) -> (&str, &str, &str, &str) {
        (
            &self.scope_digest,
            &self.space_id,
            &self.root_resource_id,
            &self.root_path,
        )
    }
    fn validate(&self) -> Result<(), String> {
        let identifier = |value: &str| {
            !value.trim().is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control)
        };
        let canonical_path = self.root_path == "/"
            || (self.root_path.starts_with('/')
                && !self.root_path.ends_with('/')
                && self.root_path[1..]
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != ".."));
        if self.scope_digest.len() != 64
            || !self
                .scope_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !identifier(&self.space_id)
            || !identifier(&self.root_resource_id)
            || self.root_path.len() > 32_000
            || self.root_path.contains('\\')
            || self.root_path.chars().any(char::is_control)
            || !canonical_path
        {
            return Err("Invalid vault reservation".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    version: u32,
    selected: Option<String>,
    #[serde(deserialize_with = "unique_profiles")]
    profiles: BTreeMap<String, ProfileRecord>,
}

// Unlike serde's default map decoding, reject duplicate profile IDs instead of
// silently replacing an earlier label. Root reservations are a Windows-only
// additive v1 field; this model does not claim identical Linux wire semantics.
fn unique_profiles<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<BTreeMap<String, ProfileRecord>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, ProfileRecord>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("unique profile IDs")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut result = BTreeMap::new();
            while let Some((id, record)) = map.next_entry::<String, ProfileRecord>()? {
                if result.len() >= MAX_PROFILES || result.insert(id, record).is_some() {
                    return Err(serde::de::Error::custom("invalid profile map"));
                }
            }
            Ok(result)
        }
    }
    d.deserialize_map(Visitor)
}
impl Registry {
    /// None means the caller established that the registry is absent, not unreadable.
    /// The caller must durably publish this default before starting runtimes.
    pub fn decode_or_default(bytes: Option<&[u8]>) -> Result<Self, String> {
        let Some(bytes) = bytes else {
            return Ok(Self {
                version: REGISTRY_VERSION,
                selected: Some(DEFAULT_ID.into()),
                profiles: BTreeMap::from([(
                    DEFAULT_ID.into(),
                    ProfileRecord {
                        label: "Default".into(),
                        removed: false,
                        root_reservations: Vec::new(),
                        source_reservations: Vec::new(),
                        vault_reservations: Vec::new(),
                    },
                )]),
            });
        };
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err("Profiles registry exceeds size limit".into());
        }
        let registry: Self =
            serde_json::from_slice(bytes).map_err(|_| "Profiles registry is invalid")?;
        validate_registry(&registry)?;
        Ok(registry)
    }
    pub fn selected(&self) -> Option<&str> {
        self.selected.as_deref()
    }
    pub fn profiles(&self) -> &BTreeMap<String, ProfileRecord> {
        &self.profiles
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        validate_registry(self)?;
        let bytes = serde_json::to_vec_pretty(self).map_err(|_| "Profiles registry is invalid")?;
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err("Profiles registry exceeds size limit".into());
        }
        Ok(bytes)
    }
    /// Return an unpublished candidate; never overwrite an existing/default ID.
    pub fn with_added(&self, id: &str, label: &str) -> Result<Self, String> {
        validate_registry(self)?;
        if self.profiles.len() >= MAX_PROFILES {
            return Err("Profile limit reached".into());
        }
        if !valid_profile_id(id) || self.profiles.contains_key(id) {
            return Err("Invalid new profile id".into());
        }
        validate_label(label)?;
        let mut next = self.clone();
        next.profiles.insert(
            id.into(),
            ProfileRecord {
                label: label.trim().into(),
                removed: false,
                root_reservations: Vec::new(),
                source_reservations: Vec::new(),
                vault_reservations: Vec::new(),
            },
        );
        if next.selected.is_none() {
            next.selected = Some(id.into());
        }
        validate_registry(&next)?;
        Ok(next)
    }
    /// Return an unpublished candidate with only the active profile label
    /// changed. The caller supplies the exact current label to reject stale UI
    /// edits; IDs and every reservation remain byte-for-byte intact.
    pub fn with_renamed(
        &self,
        id: &str,
        expected_label: &str,
        label: &str,
    ) -> Result<Self, String> {
        validate_registry(self)?;
        validate_label(label)?;
        let mut next = self.clone();
        if next.selected.as_deref() != Some(id) {
            return Err("Only the selected account can be renamed".into());
        }
        let record = next
            .profiles
            .get_mut(id)
            .filter(|record| !record.removed)
            .ok_or("Unknown active profile_id")?;
        if record.label != expected_label {
            return Err("The account label changed; refresh and try again".into());
        }
        record.label = label.trim().into();
        validate_registry(&next)?;
        Ok(next)
    }
    /// Produce an unpublished candidate; existing reservations cannot be removed
    /// or downgraded here. The caller must persist before configure/registration.
    pub fn with_reserved_root(
        &self,
        id: &str,
        reservation: RootReservation,
    ) -> Result<Self, String> {
        validate_registry(self)?;
        reservation.validate()?;
        let mut next = self.clone();
        let record = next.profiles.get_mut(id).ok_or("Unknown profile_id")?;
        if let Some(existing) = record.root_reservations.iter_mut().find(|existing| {
            existing.path == reservation.path
                && existing.volume_serial == reservation.volume_serial
                && existing.file_index == reservation.file_index
        }) {
            existing.may_be_registered |= reservation.may_be_registered;
        } else {
            if record.root_reservations.len() >= 16 {
                return Err("Root reservation limit reached".into());
            }
            record.root_reservations.push(reservation);
        }
        next.encode()?; // Enforce the aggregate document byte bound before returning.
        Ok(next)
    }
    /// Append an unpublished exclusion candidate. Old paths are never retired;
    /// an exact saved source key cannot silently acquire a replacement identity.
    pub fn with_reserved_source(
        &self,
        profile: &str,
        row: SourceReservation,
    ) -> Result<Self, String> {
        validate_registry(self)?;
        row.validate()?;
        let mut next = self.clone();
        let record = next.profiles.get_mut(profile).ok_or("Unknown profile_id")?;
        if let Some(old) = record
            .source_reservations
            .iter()
            .find(|old| old.key() == row.key())
        {
            if old.root.volume_serial() != row.root.volume_serial()
                || old.root.file_index() != row.root.file_index()
            {
                return Err("A saved source changed identity".into());
            }
        } else {
            if record.source_reservations.len() >= MAX_SOURCE_RESERVATIONS {
                return Err("Source reservation limit reached".into());
            }
            record.source_reservations.push(row);
        }
        next.encode()?;
        Ok(next)
    }
    /// Return an unpublished additive candidate. A moved/replaced vault retains
    /// all old exclusions; removing historical reservations is not implicit.
    pub fn with_reserved_vault(
        &self,
        profile: &str,
        row: VaultReservation,
    ) -> Result<Self, String> {
        validate_registry(self)?;
        row.validate()?;
        let mut next = self.clone();
        let record = next.profiles.get_mut(profile).ok_or("Unknown profile_id")?;
        if !record.vault_reservations.contains(&row) {
            if record.vault_reservations.len() >= MAX_VAULT_RESERVATIONS {
                return Err("Vault reservation limit reached".into());
            }
            record.vault_reservations.push(row);
        }
        next.encode()?;
        Ok(next)
    }
    pub fn with_selected(&self, id: &str) -> Result<Self, String> {
        validate_registry(self)?;
        if self.profiles.get(id).is_none_or(ProfileRecord::removed) {
            return Err("Unknown profile_id".into());
        }
        let mut next = self.clone();
        next.selected = Some(id.into());
        Ok(next)
    }
    pub fn with_retired(&self, id: &str, fallback: Option<&str>) -> Result<Self, String> {
        validate_registry(self)?;
        let record = self.profiles.get(id).ok_or("Unknown profile_id")?;
        if record.removed {
            return Err("Account is already removed".into());
        }
        if self.selected.as_deref() != Some(id) {
            return Err("Only the selected account can be removed".into());
        }
        if fallback == Some(id) {
            return Err("Removed account cannot remain selected".into());
        }
        if let Some(fallback) = fallback {
            if fallback == id
                || self
                    .profiles
                    .get(fallback)
                    .is_none_or(ProfileRecord::removed)
            {
                return Err("Invalid fallback account".into());
            }
        } else if self
            .profiles
            .iter()
            .any(|(other, row)| other != id && !row.removed)
        {
            return Err("An active account must be selected".into());
        }
        let mut next = self.clone();
        next.profiles
            .get_mut(id)
            .expect("validated profile")
            .removed = true;
        if next.selected.as_deref() == Some(id) {
            next.selected = fallback.map(str::to_owned);
        }
        next.encode()?;
        Ok(next)
    }
    pub fn with_restored(&self, id: &str) -> Result<Self, String> {
        validate_registry(self)?;
        let mut next = self.clone();
        let record = next.profiles.get_mut(id).ok_or("Unknown profile_id")?;
        if !record.removed {
            return Err("Account is not removed".into());
        }
        record.removed = false;
        if next.selected.is_none() {
            next.selected = Some(id.into());
        }
        next.encode()?;
        Ok(next)
    }
}
fn validate_registry(registry: &Registry) -> Result<(), String> {
    if registry.version != REGISTRY_VERSION {
        return Err("Unsupported profiles registry version".into());
    }
    if registry.profiles.is_empty() || registry.profiles.len() > MAX_PROFILES {
        return Err("Profiles registry has an invalid profile count".into());
    }
    if !registry.profiles.contains_key(DEFAULT_ID) {
        return Err("Profiles registry is missing the default profile".into());
    }
    let active_count = registry
        .profiles
        .values()
        .filter(|record| !record.removed)
        .count();
    match registry.selected.as_deref() {
        Some(selected)
            if registry
                .profiles
                .get(selected)
                .is_some_and(|record| !record.removed) => {}
        None if active_count == 0 => {}
        _ => return Err("Selected profile is missing or removed".into()),
    }
    for (id, record) in &registry.profiles {
        if id != DEFAULT_ID && !valid_profile_id(id) {
            return Err("Profiles registry contains an invalid profile id".into());
        }
        validate_label(&record.label)?;
        if record.root_reservations.len() > 16 {
            return Err("Root reservation limit reached".into());
        }
        for reservation in &record.root_reservations {
            reservation.validate()?;
        }
        if record.vault_reservations.len() > MAX_VAULT_RESERVATIONS {
            return Err("Vault reservation limit reached".into());
        }
        let mut vault_keys = BTreeSet::new();
        for vault in &record.vault_reservations {
            vault.validate()?;
            if !vault_keys.insert(vault.key()) {
                return Err("Duplicate vault reservation".into());
            }
        }
        if record.source_reservations.len() > MAX_SOURCE_RESERVATIONS {
            return Err("Source reservation limit reached".into());
        }
        let mut keys = BTreeSet::new();
        for source in &record.source_reservations {
            source.validate()?;
            if !keys.insert(source.key()) {
                return Err("Duplicate source reservation".into());
            }
        }
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), String> {
    let trimmed = label.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_LABEL_BYTES
        || trimmed.chars().any(char::is_control)
    {
        return Err("Profile label must contain 1 to 256 non-control bytes".into());
    }
    Ok(())
}

fn valid_profile_id(id: &str) -> bool {
    id.strip_prefix("profile-").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "profile-0123456789abcdef0123456789abcdef";
    #[test]
    fn missing_registry_and_add_select_roundtrip_preserve_other_profiles() {
        let original = Registry::decode_or_default(None).unwrap();
        assert_eq!(original.selected(), Some("default"));
        assert_eq!(original.profiles()["default"].label(), "Default");
        let added = original.with_added(ID, "  Work  ").unwrap();
        assert_eq!(added.selected(), Some("default"));
        assert_eq!(added.profiles()[ID].label(), "Work");
        let selected = added.with_selected(ID).unwrap();
        let restored = Registry::decode_or_default(Some(&selected.encode().unwrap())).unwrap();
        assert_eq!(restored.selected(), Some(ID));
        assert_eq!(restored.profiles().len(), 2);
        assert_eq!(restored.profiles()["default"].label(), "Default");
        assert_eq!(original.profiles().len(), 1);
        assert!(selected.with_added(ID, "Overwrite").is_err());
        assert!(selected.with_selected("missing").is_err());
    }
    #[test]
    fn strict_schema_and_duplicate_ids_refuse_without_migration() {
        for input in [
            r#"{"version":2,"selected":"default","profiles":{"default":{"label":"Default"}}}"#,
            r#"{"version":1,"selected":"missing","profiles":{"default":{"label":"Default"}}}"#,
            r#"{"version":1,"selected":"default","profiles":{}}"#,
            r#"{"version":1,"selected":"default","profiles":{"default":{"label":"Default","token":"x"}}}"#,
            r#"{"version":1,"selected":"default","profiles":{"default":{"label":"A"},"default":{"label":"B"}}}"#,
            r#"{"version":1,"selected":"default","profiles":{"default":{"label":"Default"}}} {}"#,
            "",
        ] {
            assert!(Registry::decode_or_default(Some(input.as_bytes())).is_err());
        }
        assert!(Registry::decode_or_default(Some(&vec![b' '; MAX_REGISTRY_BYTES + 1])).is_err());
    }
    #[test]
    fn linux_id_label_and_count_boundaries_are_preserved() {
        let mut registry = Registry::decode_or_default(None).unwrap();
        assert!(registry.with_added("../escape", "Work").is_err());
        assert!(
            registry
                .with_added("profile-0123456789ABCDEF0123456789abcdef", "Work")
                .is_err()
        );
        assert!(registry.with_added(ID, "\n").is_err());
        assert!(registry.with_added(ID, "bad\0label").is_err());
        assert!(registry.with_added(ID, &"é".repeat(129)).is_err());
        assert!(registry.with_added(ID, &"é".repeat(128)).is_ok());
        // Linux validates the trimmed label, and trims labels only when adding.
        assert!(
            registry
                .with_added(ID, &format!(" {} ", "x".repeat(256)))
                .is_ok()
        );
        for i in 0..15 {
            registry = registry
                .with_added(&format!("profile-{i:032x}"), "Work")
                .unwrap();
        }
        assert_eq!(registry.profiles().len(), MAX_PROFILES);
        assert!(registry.with_added(ID, "Extra").is_err());
    }
    #[test]
    fn rename_requires_exact_current_label_and_preserves_profile_identity_and_reservations() {
        let registry = Registry::decode_or_default(None)
            .unwrap()
            .with_added(ID, "Work")
            .unwrap()
            .with_reserved_root(
                ID,
                RootReservation::new(r"C:\WorkCloud".into(), 31, 47, true).unwrap(),
            )
            .unwrap()
            .with_reserved_source(
                ID,
                SourceReservation::new(
                    "a".repeat(64),
                    SourceKind::FolderPair,
                    "pair-1".into(),
                    RootReservation::new(r"C:\WorkSource".into(), 31, 48, false).unwrap(),
                )
                .unwrap(),
            )
            .unwrap()
            .with_reserved_vault(
                ID,
                VaultReservation::new(
                    "b".repeat(64),
                    "space-id".into(),
                    "root-id".into(),
                    "/Spaces/space-id".into(),
                )
                .unwrap(),
            )
            .unwrap()
            .with_selected(ID)
            .unwrap();

        assert!(registry.with_renamed(ID, "Stale", "New name").is_err());
        assert!(
            registry
                .with_renamed("default", "Default", "New name")
                .is_err()
        );
        assert!(registry.with_renamed(ID, "Work", "\n").is_err());
        assert!(registry.with_renamed(ID, "Work", &"é".repeat(129)).is_err());

        let renamed = registry
            .with_renamed(ID, "Work", "  Work laptop  ")
            .unwrap();
        let record = &renamed.profiles()[ID];
        assert_eq!(renamed.selected(), Some(ID));
        assert_eq!(renamed.profiles().len(), registry.profiles().len());
        assert_eq!(record.label(), "Work laptop");
        assert_eq!(
            serde_json::to_value(record.root_reservations()).unwrap(),
            serde_json::to_value(registry.profiles()[ID].root_reservations()).unwrap()
        );
        assert_eq!(
            serde_json::to_value(record.source_reservations()).unwrap(),
            serde_json::to_value(registry.profiles()[ID].source_reservations()).unwrap()
        );
        assert_eq!(
            record.vault_reservations(),
            registry.profiles()[ID].vault_reservations()
        );
        assert_eq!(registry.profiles()[ID].label(), "Work");
    }
    #[test]
    fn actual_linux_wire_shape_is_compatible_and_has_no_runtime_fields() {
        let bytes = br#"{"version":1,"selected":"default","profiles":{"default":{"label":" Default "},"profile-0123456789abcdef0123456789abcdef":{"label":"Work"}}}"#;
        let model = Registry::decode_or_default(Some(bytes)).unwrap();
        assert_eq!(model.profiles()["default"].label(), " Default ");
        let value: serde_json::Value = serde_json::from_slice(&model.encode().unwrap()).unwrap();
        assert_eq!(
            value,
            serde_json::from_slice::<serde_json::Value>(bytes).unwrap()
        );
    }
    #[test]
    fn reservations_default_deduplicate_upgrade_roundtrip_preserve_and_bound() {
        let legacy =
            br#"{"version":1,"selected":"default","profiles":{"default":{"label":"Default"}}}"#;
        let original = Registry::decode_or_default(Some(legacy)).unwrap();
        assert!(
            original.profiles()["default"]
                .root_reservations()
                .is_empty()
        );
        let root = |path: &str, index, registered| {
            RootReservation::new(path.into(), 7, index, registered).unwrap()
        };
        let first = original
            .with_reserved_root("default", root(r"C:\Cloud", 10, false))
            .unwrap();
        let upgraded = first
            .with_reserved_root("default", root(r"C:\Cloud", 10, true))
            .unwrap()
            .with_reserved_root("default", root(r"C:\Cloud", 10, false))
            .unwrap();
        let reservations = upgraded.profiles()["default"].root_reservations();
        assert_eq!(reservations.len(), 1);
        assert!(reservations[0].may_be_registered());
        assert_eq!(reservations[0].path(), r"C:\Cloud");
        assert_eq!(reservations[0].volume_serial(), 7);
        assert_eq!(reservations[0].file_index(), 10);
        assert!(!first.profiles()["default"].root_reservations()[0].may_be_registered());
        let next = upgraded
            .with_reserved_root("default", root(r"D:\Other", 11, false))
            .unwrap();
        let restored = Registry::decode_or_default(Some(&next.encode().unwrap())).unwrap();
        assert_eq!(restored.profiles()["default"].root_reservations().len(), 2);
        assert!(restored.profiles()["default"].root_reservations()[0].may_be_registered());
        assert!(
            next.with_reserved_root("missing", root(r"C:\Safe", 12, false))
                .is_err()
        );
        assert!(RootReservation::new(r"C:\..\bad".into(), 7, 1, false).is_err());
        assert!(RootReservation::new(r"\\?\C:\bad".into(), 7, 1, false).is_err());
        assert!(RootReservation::new(r"C:\Safe".into(), 7, 0, false).is_err());
        let mut full = restored;
        for index in 12..26 {
            full = full
                .with_reserved_root("default", root(&format!(r"D:\Root{index}"), index, false))
                .unwrap();
        }
        assert_eq!(full.profiles()["default"].root_reservations().len(), 16);
        assert!(
            full.with_reserved_root("default", root(r"D:\Overflow", 26, false))
                .is_err()
        );
        let mut value: serde_json::Value = serde_json::from_slice(&full.encode().unwrap()).unwrap();
        value["profiles"]["default"]["root_reservations"][0]["unexpected"] = true.into();
        assert!(Registry::decode_or_default(Some(&serde_json::to_vec(&value).unwrap())).is_err());
    }
    #[test]
    fn retirement_preserves_identity_and_reservations_until_explicit_restore() {
        let mut registry = Registry::decode_or_default(None)
            .unwrap()
            .with_added(ID, "Work")
            .unwrap()
            .with_reserved_root(
                ID,
                RootReservation::new(r"C:\WorkCloud".into(), 31, 47, true).unwrap(),
            )
            .unwrap()
            .with_reserved_source(
                ID,
                SourceReservation::new(
                    "a".repeat(64),
                    SourceKind::FolderPair,
                    "pair-1".into(),
                    RootReservation::new(r"C:\WorkSource".into(), 31, 48, false).unwrap(),
                )
                .unwrap(),
            )
            .unwrap()
            .with_reserved_vault(
                ID,
                VaultReservation::new(
                    "b".repeat(64),
                    "space-id".into(),
                    "root-id".into(),
                    "/Spaces/space-id".into(),
                )
                .unwrap(),
            )
            .unwrap()
            .with_selected(ID)
            .unwrap();

        registry = registry.with_retired(ID, Some("default")).unwrap();
        assert_eq!(registry.selected(), Some("default"));
        assert!(registry.profiles()[ID].removed());
        assert_eq!(registry.profiles()[ID].label(), "Work");
        assert_eq!(registry.profiles()[ID].root_reservations().len(), 1);
        assert_eq!(registry.profiles()[ID].source_reservations().len(), 1);
        assert_eq!(registry.profiles()[ID].vault_reservations().len(), 1);
        assert!(registry.with_selected(ID).is_err());

        registry = registry.with_retired("default", None).unwrap();
        assert_eq!(registry.selected(), None);
        assert!(registry.profiles()["default"].removed());
        let decoded = Registry::decode_or_default(Some(&registry.encode().unwrap())).unwrap();
        assert_eq!(decoded.selected(), None);
        assert!(decoded.profiles()[ID].removed());
        assert_eq!(decoded.profiles()[ID].root_reservations().len(), 1);
        assert_eq!(decoded.profiles()[ID].source_reservations().len(), 1);
        assert_eq!(decoded.profiles()[ID].vault_reservations().len(), 1);

        let restored = decoded.with_restored(ID).unwrap();
        assert_eq!(restored.selected(), Some(ID));
        assert!(!restored.profiles()[ID].removed());
        assert_eq!(restored.profiles()[ID].root_reservations().len(), 1);
        assert_eq!(restored.profiles()[ID].source_reservations().len(), 1);
        assert_eq!(restored.profiles()[ID].vault_reservations().len(), 1);
        assert!(restored.profiles()["default"].removed());
        assert!(restored.with_retired(ID, Some(ID)).is_err());
    }
    fn source(path: &str, index: u64, kind: SourceKind) -> SourceReservation {
        SourceReservation::new(
            "a".repeat(64),
            kind,
            "saved-id".into(),
            RootReservation::new(path.into(), 7, index, false).unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn source_reservations_are_legacy_default_additive_and_identity_bound() {
        let original = Registry::decode_or_default(Some(
            br#"{"version":1,"selected":"default","profiles":{"default":{"label":"Default"}}}"#,
        ))
        .unwrap();
        assert!(
            original.profiles()["default"]
                .source_reservations()
                .is_empty()
        );
        let first = original
            .with_reserved_source("default", source(r"C:\Photos", 10, SourceKind::MediaJob))
            .unwrap();
        let same = first
            .with_reserved_source("default", source(r"C:\Photos", 10, SourceKind::MediaJob))
            .unwrap();
        assert_eq!(same.encode().unwrap(), first.encode().unwrap());
        assert!(
            first
                .with_reserved_source("default", source(r"C:\Photos", 11, SourceKind::MediaJob))
                .is_err()
        );
        let next = first
            .with_reserved_source("default", source(r"D:\Photos", 11, SourceKind::MediaJob))
            .unwrap()
            .with_reserved_source("default", source(r"C:\Photos", 10, SourceKind::FolderPair))
            .unwrap();
        let restored = Registry::decode_or_default(Some(&next.encode().unwrap())).unwrap();
        let rows = restored.profiles()["default"].source_reservations();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].root().path(), r"C:\Photos");
        assert_eq!(rows[0].root().file_index(), 10);
        assert_eq!(rows[0].scope_digest(), "a".repeat(64));
        assert_eq!(rows[0].id(), "saved-id");
        assert!(rows[0].kind() == SourceKind::MediaJob);
        assert!(
            restored.profiles()["default"]
                .root_reservations()
                .is_empty()
        );
        assert!(
            original.profiles()["default"]
                .source_reservations()
                .is_empty()
        );
        assert!(
            next.with_reserved_source("missing", source(r"C:\Safe", 12, SourceKind::MediaJob))
                .is_err()
        );
    }
    #[test]
    fn source_reservation_bounds_and_restored_schema_fail_closed() {
        let mut full = Registry::decode_or_default(None).unwrap();
        for i in 0..128 {
            full = full
                .with_reserved_source(
                    "default",
                    source(&format!(r"C:\Source{i}"), i + 1, SourceKind::FolderPair),
                )
                .unwrap();
        }
        assert!(
            full.with_reserved_source(
                "default",
                source(r"C:\Overflow", 130, SourceKind::FolderPair)
            )
            .is_err()
        );
        let mut raw = serde_json::to_value(&full).unwrap();
        let duplicate = raw["profiles"]["default"]["source_reservations"][0].clone();
        raw["profiles"]["default"]["source_reservations"][1] = duplicate.clone();
        assert!(Registry::decode_or_default(Some(&serde_json::to_vec(&raw).unwrap())).is_err());
        for (field, value) in [
            ("scope_digest", serde_json::json!("A".repeat(64))),
            ("id", serde_json::json!("x".repeat(129))),
            ("kind", serde_json::json!("unknown")),
        ] {
            let mut invalid = serde_json::to_value(&full).unwrap();
            invalid["profiles"]["default"]["source_reservations"][0][field] = value;
            assert!(
                Registry::decode_or_default(Some(&serde_json::to_vec(&invalid).unwrap())).is_err()
            );
        }
        let mut registered = serde_json::to_value(&full).unwrap();
        registered["profiles"]["default"]["source_reservations"][0]["root"]["may_be_registered"] =
            true.into();
        assert!(
            Registry::decode_or_default(Some(&serde_json::to_vec(&registered).unwrap())).is_err()
        );
        let mut volume = source(r"C:\Safe", 1, SourceKind::MediaJob);
        volume.root.may_be_registered = true;
        assert!(volume.validate().is_err());
    }
    #[test]
    fn vault_exclusions_survive_legacy_roundtrip_move_and_replacement() {
        let legacy =
            br#"{"version":1,"selected":"default","profiles":{"default":{"label":"Default"}}}"#;
        let original = Registry::decode_or_default(Some(legacy))
            .unwrap()
            .with_added(ID, "Work")
            .unwrap();
        assert!(
            original.profiles()["default"]
                .vault_reservations()
                .is_empty()
        );
        let row = |scope: &str, resource: &str, path: &str| {
            VaultReservation::new(
                scope.repeat(64),
                "space".into(),
                resource.into(),
                path.into(),
            )
            .unwrap()
        };
        let first = row("a", "root", "/Vault");
        let saved = original
            .with_reserved_vault("default", first.clone())
            .unwrap();
        let repeated = saved.with_reserved_vault("default", first.clone()).unwrap();
        assert_eq!(saved.encode().unwrap(), repeated.encode().unwrap());
        let next = repeated
            .with_reserved_vault(ID, first)
            .unwrap()
            .with_reserved_vault("default", row("b", "root", "/Vault"))
            .unwrap()
            .with_reserved_vault("default", row("a", "root", "/Moved"))
            .unwrap()
            .with_reserved_vault("default", row("a", "replacement", "/Vault"))
            .unwrap();
        let bytes = next.encode().unwrap();
        let restored = Registry::decode_or_default(Some(&bytes)).unwrap();
        assert_eq!(restored.profiles()["default"].vault_reservations().len(), 4);
        assert_eq!(restored.profiles()[ID].vault_reservations().len(), 1);
        assert_eq!(
            restored.profiles()["default"].vault_reservations()[0].root_path(),
            "/Vault"
        );
        assert!(
            restored
                .with_reserved_vault("unknown", row("a", "root", "/Vault"))
                .is_err()
        );
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for (field, invalid) in [
            ("root_path", serde_json::json!("/Vault/../escape")),
            ("extra", serde_json::json!(true)),
        ] {
            let mut altered = value.clone();
            altered["profiles"]["default"]["vault_reservations"][0][field] = invalid;
            assert!(
                Registry::decode_or_default(Some(&serde_json::to_vec(&altered).unwrap())).is_err()
            );
        }
        let mut duplicate = value;
        duplicate["profiles"]["default"]["vault_reservations"][1] =
            duplicate["profiles"]["default"]["vault_reservations"][0].clone();
        assert!(
            Registry::decode_or_default(Some(&serde_json::to_vec(&duplicate).unwrap())).is_err()
        );
        assert_eq!(restored.encode().unwrap(), bytes);
    }
}

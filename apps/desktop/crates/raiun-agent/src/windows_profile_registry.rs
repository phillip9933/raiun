//! Storage-free Windows v1 registry with additive root exclusion reservations.
//! Legacy empty reservations require protected-storage inventory before admission.
//! Selection changes only the selected ID; it does not stop or revoke runtimes.
//! The caller owns random ID allocation, protected persistence and runtime admission.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
const DEFAULT_ID: &str = "default";
const REGISTRY_VERSION: u32 = 1;
const MAX_REGISTRY_BYTES: usize = 1_048_576;
const MAX_PROFILES: usize = 16;
const MAX_LABEL_BYTES: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRecord {
    label: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    root_reservations: Vec<RootReservation>,
}
impl ProfileRecord {
    pub fn root_reservations(&self) -> &[RootReservation] {
        &self.root_reservations
    }
    pub fn label(&self) -> &str {
        &self.label
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    version: u32,
    selected: String,
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
                selected: DEFAULT_ID.into(),
                profiles: BTreeMap::from([(
                    DEFAULT_ID.into(),
                    ProfileRecord {
                        label: "Default".into(),
                        root_reservations: Vec::new(),
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
    pub fn selected(&self) -> &str {
        &self.selected
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
                root_reservations: Vec::new(),
            },
        );
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
    pub fn with_selected(&self, id: &str) -> Result<Self, String> {
        validate_registry(self)?;
        if !self.profiles.contains_key(id) {
            return Err("Unknown profile_id".into());
        }
        let mut next = self.clone();
        next.selected = id.into();
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
    if !registry.profiles.contains_key(&registry.selected) {
        return Err("Selected profile is missing from the registry".into());
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
        assert_eq!(original.selected(), "default");
        assert_eq!(original.profiles()["default"].label(), "Default");
        let added = original.with_added(ID, "  Work  ").unwrap();
        assert_eq!(added.selected(), "default");
        assert_eq!(added.profiles()[ID].label(), "Work");
        let selected = added.with_selected(ID).unwrap();
        let restored = Registry::decode_or_default(Some(&selected.encode().unwrap())).unwrap();
        assert_eq!(restored.selected(), ID);
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
}

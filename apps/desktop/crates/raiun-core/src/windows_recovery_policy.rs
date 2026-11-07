//! Nonsecret Windows ordinary-file recovery limits. Parsing settings grants no
//! storage, upload, native publication or provider-activation authority.
use serde::{Deserialize, Serialize};

const GIB: u64 = 1024 * 1024 * 1024;
const TIB: u64 = 1024 * GIB;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WindowsRecoveryPolicy {
    pub max_file_bytes: u64,
    pub max_state_bytes: u64,
    pub max_state_entries: usize,
    pub max_scan_metadata_bytes: u64,
    pub total_timeout_seconds: u64,
}

impl Default for WindowsRecoveryPolicy {
    fn default() -> Self {
        Self {
            // The aggregate protected-storage allowance is the default bound;
            // do not impose an additional smaller per-file product limit.
            max_file_bytes: 8 * GIB,
            max_state_bytes: 8 * GIB,
            max_state_entries: 20_000,
            max_scan_metadata_bytes: 64 * 1024 * 1024,
            total_timeout_seconds: 6 * 60 * 60,
        }
    }
}

impl<'de> Deserialize<'de> for WindowsRecoveryPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Default, Deserialize)]
        #[serde(default, deny_unknown_fields)]
        struct Fields {
            #[serde(deserialize_with = "present")]
            max_file_bytes: Option<u64>,
            #[serde(deserialize_with = "present")]
            max_state_bytes: Option<u64>,
            #[serde(deserialize_with = "present")]
            max_state_entries: Option<usize>,
            #[serde(deserialize_with = "present")]
            max_scan_metadata_bytes: Option<u64>,
            #[serde(deserialize_with = "present")]
            total_timeout_seconds: Option<u64>,
        }
        fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
        where
            D: serde::Deserializer<'de>,
            T: Deserialize<'de>,
        {
            T::deserialize(deserializer).map(Some)
        }
        let fields = Fields::deserialize(deserializer)?;
        let defaults = Self::default();
        let max_state_bytes = fields.max_state_bytes.unwrap_or(defaults.max_state_bytes);
        Ok(Self {
            // Explicit owner limits survive unchanged. An omitted file limit
            // follows even an older, smaller configured quota rather than
            // invalidating that configuration when defaults change.
            max_file_bytes: fields.max_file_bytes.unwrap_or(max_state_bytes.min(TIB)),
            max_state_bytes,
            max_state_entries: fields
                .max_state_entries
                .unwrap_or(defaults.max_state_entries),
            max_scan_metadata_bytes: fields
                .max_scan_metadata_bytes
                .unwrap_or(defaults.max_scan_metadata_bytes),
            total_timeout_seconds: fields
                .total_timeout_seconds
                .unwrap_or(defaults.total_timeout_seconds),
        })
    }
}

impl WindowsRecoveryPolicy {
    /// These are logical admission limits. Existing retained evidence and
    /// conservative ciphertext reservations can still make a write exceed the
    /// aggregate budget; validation neither reserves disk nor evicts records.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(1..=TIB).contains(&self.max_file_bytes) {
            return Err("windows_recovery.max_file_bytes must be between 1 and 1099511627776");
        }
        if !(16 * 1024 * 1024..=16 * TIB).contains(&self.max_state_bytes)
            || self.max_state_bytes < self.max_file_bytes
        {
            return Err(
                "windows_recovery.max_state_bytes must be between 16777216 and 17592186044416 and at least max_file_bytes",
            );
        }
        if !(64..=20_000).contains(&self.max_state_entries) {
            return Err("windows_recovery.max_state_entries must be between 64 and 20000");
        }
        if !(512 * 1024..=64 * 1024 * 1024).contains(&self.max_scan_metadata_bytes) {
            return Err(
                "windows_recovery.max_scan_metadata_bytes must be between 524288 and 67108864",
            );
        }
        if !(60..=86_400).contains(&self.total_timeout_seconds) {
            return Err("windows_recovery.total_timeout_seconds must be between 60 and 86400");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_partial_configuration_preserve_all_limits() {
        let defaults = WindowsRecoveryPolicy::default();
        defaults.validate().unwrap();
        let partial: WindowsRecoveryPolicy =
            serde_json::from_str(r#"{"total_timeout_seconds":86400}"#).unwrap();
        assert_eq!(
            partial,
            WindowsRecoveryPolicy {
                total_timeout_seconds: 86_400,
                ..defaults
            }
        );
        partial.validate().unwrap();
        let encoded = serde_json::to_string(&partial).unwrap();
        assert_eq!(
            serde_json::from_str::<WindowsRecoveryPolicy>(&encoded).unwrap(),
            partial
        );
        assert!(
            serde_json::from_str::<WindowsRecoveryPolicy>(r#"{"timeout_seconds":90}"#).is_err()
        );
    }

    #[test]
    fn unsupported_limits_and_overflowing_inputs_are_refused() {
        for invalid in [
            serde_json::json!({"max_file_bytes":0}),
            serde_json::json!({"max_file_bytes":TIB+1}),
            serde_json::json!({"max_state_bytes":16*1024*1024-1}),
            serde_json::json!({"max_state_bytes":16*TIB+1}),
            serde_json::json!({"max_state_entries":20_001}),
            serde_json::json!({"max_scan_metadata_bytes":64*1024*1024+1}),
            serde_json::json!({"total_timeout_seconds":59}),
            serde_json::json!({"total_timeout_seconds":86_401}),
        ] {
            let policy: WindowsRecoveryPolicy = serde_json::from_value(invalid).unwrap();
            assert!(policy.validate().is_err());
        }
        assert!(
            serde_json::from_str::<WindowsRecoveryPolicy>(
                r#"{"max_file_bytes":18446744073709551616}"#
            )
            .is_err()
        );
        let policy = WindowsRecoveryPolicy {
            max_file_bytes: 2 * GIB,
            max_state_bytes: GIB,
            ..Default::default()
        };
        assert!(policy.validate().is_err());
    }
}

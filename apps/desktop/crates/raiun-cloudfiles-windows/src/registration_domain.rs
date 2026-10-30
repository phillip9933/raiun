//! Pure configured-root registration domains. The native boundary obtains the
//! trusted headless state scope; this module never reads paths or environment.

use crate::{ConfiguredRootIdentity, Error};
use std::fmt::Write;

pub(super) struct ConfiguredRegistrationDomain {
    pub sync_root_identity: Vec<u8>,
    pub provider_name: String,
    pub provider_version: &'static str,
}

impl ConfiguredRegistrationDomain {
    pub fn new(root: ConfiguredRootIdentity, headless_scope: Option<&str>) -> Result<Self, Error> {
        // Keep the Desktop domain byte-for-byte compatible with published roots.
        let mut sync_root_identity = vec![0_u8; 24];
        sync_root_identity[..8].copy_from_slice(b"RaiunCF1");
        sync_root_identity[8..12].copy_from_slice(&root.volume_serial.to_le_bytes());
        sync_root_identity[12..20].copy_from_slice(&root.file_index.to_le_bytes());
        let provider_name = match headless_scope {
            None => String::from("Raiun Internal Cloud Files Root"),
            Some(scope) => {
                // Require the complete canonical state digest. Never truncate it
                // or allow invalid headless context to fall back to Desktop.
                if scope.len() != 64
                    || !scope
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(Error::InvalidConfiguredRoot);
                }
                sync_root_identity[..8].copy_from_slice(b"RaiunHC1");
                for pair in scope.as_bytes().chunks_exact(2) {
                    let nibble = |byte: u8| match byte {
                        b'0'..=b'9' => byte - b'0',
                        _ => byte - b'a' + 10,
                    };
                    sync_root_identity.push((nibble(pair[0]) << 4) | nibble(pair[1]));
                }
                format!(
                    "Raiun Headless Cloud Files {scope} {:08x}-{:016x}",
                    root.volume_serial, root.file_index
                )
            }
        };
        Ok(Self {
            sync_root_identity,
            provider_name,
            provider_version: "0.0.0-internal",
        })
    }

    pub fn vault_binding(&self, composite: &[u8]) -> String {
        let mut binding = format!(
            "raiun-vault-registration-v1:{}:{}:",
            self.provider_name, self.provider_version
        );
        for byte in self.sync_root_identity.iter().chain(composite) {
            write!(&mut binding, "{byte:02x}").expect("format registration binding");
        }
        binding
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> ConfiguredRootIdentity {
        ConfiguredRootIdentity {
            volume_serial: 0x1234_5678,
            file_index: 0x1234_5678_90ab_cdef,
        }
    }

    #[test]
    fn desktop_registration_and_vault_binding_remain_byte_identical() {
        let domain = ConfiguredRegistrationDomain::new(root(), None).unwrap();
        assert_eq!(domain.provider_name, "Raiun Internal Cloud Files Root");
        assert_eq!(domain.provider_version, "0.0.0-internal");
        assert_eq!(
            domain.sync_root_identity,
            b"RaiunCF1\x78\x56\x34\x12\xef\xcd\xab\x90\x78\x56\x34\x12\0\0\0\0"
        );
        assert_eq!(
            domain.vault_binding(&[0x12, 0x34]),
            "raiun-vault-registration-v1:Raiun Internal Cloud Files Root:0.0.0-internal:526169756e43463178563412efcdab9078563412000000001234"
        );
    }

    #[test]
    fn headless_domains_bind_full_state_scope_and_physical_root() {
        let scope_a = "12".repeat(32);
        let mut scope_b = scope_a.clone();
        scope_b.replace_range(62..64, "13");
        let desktop = ConfiguredRegistrationDomain::new(root(), None).unwrap();
        let first = ConfiguredRegistrationDomain::new(root(), Some(&scope_a)).unwrap();
        let restarted = ConfiguredRegistrationDomain::new(root(), Some(&scope_a)).unwrap();
        let other_state = ConfiguredRegistrationDomain::new(root(), Some(&scope_b)).unwrap();
        assert_eq!(first.sync_root_identity, restarted.sync_root_identity);
        assert_eq!(first.provider_name, restarted.provider_name);
        assert_eq!(first.sync_root_identity.len(), 56);
        assert_eq!(&first.sync_root_identity[..8], b"RaiunHC1");
        assert_eq!(&first.sync_root_identity[24..], &[0x12; 32]);
        for other in [desktop, other_state] {
            assert_ne!(first.sync_root_identity, other.sync_root_identity);
            assert_ne!(first.provider_name, other.provider_name);
            assert_ne!(first.vault_binding(&[1; 16]), other.vault_binding(&[1; 16]));
        }
        for changed in [
            ConfiguredRootIdentity {
                volume_serial: root().volume_serial + 1,
                ..root()
            },
            ConfiguredRootIdentity {
                file_index: root().file_index + 1,
                ..root()
            },
        ] {
            let other = ConfiguredRegistrationDomain::new(changed, Some(&scope_a)).unwrap();
            assert_ne!(first.sync_root_identity, other.sync_root_identity);
            assert_ne!(first.provider_name, other.provider_name);
            assert_ne!(first.vault_binding(&[1; 16]), other.vault_binding(&[1; 16]));
        }
        assert!(first.provider_name.encode_utf16().count() < 256);
        assert!(first.sync_root_identity.len() <= 256);
    }

    #[test]
    fn invalid_headless_scope_cannot_select_desktop_domain() {
        for invalid in [
            String::new(),
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
        ] {
            assert!(ConfiguredRegistrationDomain::new(root(), Some(&invalid)).is_err());
        }
    }
}

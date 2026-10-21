//! Bounded, all-or-nothing decoding for one encrypted directory listing.
//!
//! The caller-facing entry point is [`crate::session::VaultSessionCoordinator::decode_directory_names`];
//! this module only contains the private batch implementation and collision
//! key construction.

use std::collections::HashSet;

use caseless::Caseless;
use unicode_normalization::UnicodeNormalization;

use crate::{VaultError, VerifiedVaultSession, invalid};

const MAX_DIRECTORY_ENTRIES: usize = 10_000;
const MAX_CIPHERTEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_COLLISION_KEY_BYTES: usize = 4 * 1024;
const MAX_COLLISION_KEYS_BYTES: usize = 4 * 1024 * 1024;

/// Decode and validate an entire directory before returning any plaintext.
///
/// All inputs are preflighted before decryption, then each decoded component is
/// checked against a compatibility-caseless collision key. The returned names
/// retain their original decoded spelling. There are no callbacks or partial
/// results.
pub(crate) fn decode_directory_names(
    session: &VerifiedVaultSession,
    encrypted_names: &[&str],
) -> Result<Vec<String>, VaultError> {
    preflight(encrypted_names)?;

    let mut ciphertexts = HashSet::with_capacity(encrypted_names.len());
    for encrypted in encrypted_names {
        if !ciphertexts.insert(*encrypted) {
            return Err(invalid("directory contains duplicate encrypted names"));
        }
    }

    let decoded_names = encrypted_names
        .iter()
        .map(|encrypted| session.decrypt_name(encrypted))
        .collect::<Result<Vec<_>, _>>()?;
    validate_decoded_names(decoded_names)
}

/// Encode a complete proposed directory-name batch only if it is portable
/// and collision-free both internally and against the complete current remote
/// sibling listing. The returned ciphertext batch is all-or-nothing.
pub(crate) fn encode_directory_names(
    session: &VerifiedVaultSession,
    plain_names: &[&str],
    existing_encrypted_names: &[&str],
) -> Result<Vec<String>, VaultError> {
    if plain_names
        .len()
        .saturating_add(existing_encrypted_names.len())
        > MAX_DIRECTORY_ENTRIES
    {
        return Err(invalid("directory contains too many entries"));
    }
    let mut total_input_bytes = 0usize;
    for encrypted in existing_encrypted_names {
        if encrypted.is_empty()
            || encrypted.len() > crate::MAX_ENCRYPTED_NAME
            || encrypted.contains('/')
            || encrypted.contains('\\')
        {
            return Err(invalid("directory entry is not one bounded encrypted name"));
        }
        total_input_bytes = total_input_bytes
            .checked_add(encrypted.len())
            .filter(|total| *total <= MAX_CIPHERTEXT_BYTES)
            .ok_or_else(|| invalid("directory ciphertext exceeds its size limit"))?;
    }
    for name in plain_names {
        if name.is_empty() || name.len() > crate::MAX_NAME_UTF8 {
            return Err(invalid("directory name is empty or too large"));
        }
        total_input_bytes = total_input_bytes
            .checked_add(name.len())
            .filter(|total| *total <= MAX_CIPHERTEXT_BYTES)
            .ok_or_else(|| invalid("directory name input exceeds its size limit"))?;
    }

    // Decode and validate all existing siblings before validating the combined
    // namespace. The caller must provide the complete current listing.
    let existing_names = decode_directory_names(session, existing_encrypted_names)?;
    let mut combined = Vec::with_capacity(existing_names.len() + plain_names.len());
    combined.extend(existing_names);
    combined.extend(plain_names.iter().map(|name| (*name).to_owned()));
    validate_decoded_names(combined)?;

    plain_names
        .iter()
        .map(|name| session.encrypt_name(name))
        .collect()
}

fn validate_decoded_names(decoded_names: Vec<String>) -> Result<Vec<String>, VaultError> {
    let mut accepted_names = Vec::with_capacity(decoded_names.len());
    let mut collision_keys = HashSet::with_capacity(decoded_names.len());
    let mut collision_key_bytes = 0usize;
    for decoded in decoded_names {
        crate::validate_portable_name(&decoded)?;
        let key = compatibility_collision_key(&decoded)?;
        collision_key_bytes = collision_key_bytes
            .checked_add(key.len())
            .filter(|total| *total <= MAX_COLLISION_KEYS_BYTES)
            .ok_or_else(|| invalid("directory name collision data exceeds its size limit"))?;
        if !collision_keys.insert(key) {
            return Err(invalid("directory contains ambiguous decoded names"));
        }
        accepted_names.push(decoded);
    }

    Ok(accepted_names)
}

fn preflight(encrypted_names: &[&str]) -> Result<(), VaultError> {
    if encrypted_names.len() > MAX_DIRECTORY_ENTRIES {
        return Err(invalid("directory contains too many entries"));
    }
    let mut total_bytes = 0usize;
    for encrypted in encrypted_names {
        if encrypted.is_empty()
            || encrypted.len() > crate::MAX_ENCRYPTED_NAME
            || encrypted.contains('/')
            || encrypted.contains('\\')
        {
            return Err(invalid("directory entry is not one bounded encrypted name"));
        }
        total_bytes = total_bytes
            .checked_add(encrypted.len())
            .filter(|total| *total <= MAX_CIPHERTEXT_BYTES)
            .ok_or_else(|| invalid("directory ciphertext exceeds its size limit"))?;
    }
    Ok(())
}

/// Construct the Unicode compatibility-caseless key described by Unicode's
/// compatibility caseless matching algorithm:
/// NFD → full default case fold → NFKD → full default case fold → NFKD.
///
/// This is an intentionally conservative name-collision policy. It is not an
/// assertion that every target filesystem applies the same equivalence rules.
fn compatibility_collision_key(value: &str) -> Result<String, VaultError> {
    let mut key = String::new();
    for character in value
        .chars()
        .nfd()
        .default_case_fold()
        .nfkd()
        .default_case_fold()
        .nfkd()
    {
        if key.len() + character.len_utf8() > MAX_COLLISION_KEY_BYTES {
            return Err(invalid("directory name collision key is too large"));
        }
        key.push(character);
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(value: &str) -> String {
        compatibility_collision_key(value).unwrap()
    }

    fn validate(values: &[&str]) -> Result<Vec<String>, VaultError> {
        validate_decoded_names(values.iter().map(|value| (*value).to_owned()).collect())
    }

    fn verified_session() -> VerifiedVaultSession {
        let mut password = b"potato".to_vec();
        let cipher = crate::VaultCipher::from_password(&mut password).unwrap();
        cipher
            .verify_and_unlock(include_str!("../tests/fixtures/web-integrity-token.b64").trim())
            .unwrap()
    }

    #[test]
    fn compatibility_key_catches_casefold_and_normalization_collisions() {
        assert_eq!(caseless::UNICODE_VERSION, (16, 0, 0));
        assert_eq!(unicode_normalization::UNICODE_VERSION, (16, 0, 0));
        for (left, right) in [
            ("Readme", "README"),
            ("Straße", "STRASSE"),
            ("Σ", "ς"),
            ("σ", "ς"),
            ("é", "e\u{301}"),
            ("ﬀ", "ff"),
        ] {
            assert_eq!(key(left), key(right), "{left:?} and {right:?}");
        }
    }

    #[test]
    fn decoded_batch_rejects_late_unsafe_or_ambiguous_names_as_a_unit() {
        assert!(validate(&["first-safe", "unsafe:name"]).is_err());
        assert!(validate(&["first-safe", "Straße", "STRASSE"]).is_err());
        assert!(validate(&["first-safe", "Σ", "ς"]).is_err());
        assert_eq!(validate(&["first-safe", "é"]).unwrap(), ["first-safe", "é"]);
    }

    #[test]
    fn encoded_batch_rejects_local_and_existing_sibling_collisions_atomically() {
        let session = verified_session();
        let existing = [session.encrypt_name("Readme").unwrap()];
        assert!(
            encode_directory_names(&session, &["new-safe", "README"], &[&existing[0]]).is_err()
        );
        assert!(encode_directory_names(&session, &["Straße", "STRASSE"], &[]).is_err());
        assert!(encode_directory_names(&session, &["safe", "bad:name"], &[]).is_err());

        let encoded =
            encode_directory_names(&session, &["new-safe", "école"], &[&existing[0]]).unwrap();
        assert_eq!(encoded.len(), 2);
        assert_eq!(session.decrypt_name(&encoded[0]).unwrap(), "new-safe");
        assert_eq!(session.decrypt_name(&encoded[1]).unwrap(), "école");
    }

    #[test]
    fn encode_batch_preflights_combined_count_and_size() {
        let session = verified_session();
        let too_many = vec!["x"; MAX_DIRECTORY_ENTRIES + 1];
        assert!(encode_directory_names(&session, &too_many, &[]).is_err());
        let large_names =
            vec!["x".repeat(crate::MAX_NAME_UTF8); MAX_CIPHERTEXT_BYTES / crate::MAX_NAME_UTF8 + 1];
        let refs = large_names.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(encode_directory_names(&session, &refs, &[]).is_err());
    }

    #[test]
    fn preflight_rejects_count_size_and_component_violations() {
        let excessive_count = vec!["x"; MAX_DIRECTORY_ENTRIES + 1];
        assert!(preflight(&excessive_count).is_err());

        let chunk = "a".repeat(crate::MAX_ENCRYPTED_NAME);
        let excessive_size = vec![chunk.as_str(); MAX_CIPHERTEXT_BYTES / chunk.len() + 1];
        assert!(preflight(&excessive_size).is_err());
        assert!(preflight(&["a/b"]).is_err());
        assert!(preflight(&["a\\b"]).is_err());
        assert!(preflight(&[""]).is_err());
        let oversized = "a".repeat(crate::MAX_ENCRYPTED_NAME + 1);
        assert!(preflight(&[oversized.as_str()]).is_err());
    }
}

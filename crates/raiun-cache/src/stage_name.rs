//! Strict accounting names for protected, interrupted download stages.

use super::{CacheError, MAX_CONTENT_BYTES};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StageName {
    Ordinary,
    Legacy,
    Reserved(u64),
}

pub(super) fn classify(name: &str) -> Result<StageName, CacheError> {
    let Some(suffix) = name.strip_prefix(".stage-") else {
        return Ok(StageName::Ordinary);
    };
    let hex = |text: &str, length: usize| {
        text.len() == length
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if hex(suffix, 32) {
        return Ok(StageName::Legacy);
    }
    let Some(suffix) = suffix.strip_prefix("v1-") else {
        return Err(CacheError::InvalidEntry);
    };
    let Some((nonce, length)) = suffix.split_once('-') else {
        return Err(CacheError::InvalidEntry);
    };
    if !hex(nonce, 32) || !hex(length, 16) {
        return Err(CacheError::InvalidEntry);
    }
    let promised = u64::from_str_radix(length, 16).map_err(|_| CacheError::InvalidEntry)?;
    if promised > MAX_CONTENT_BYTES {
        return Err(CacheError::LimitExceeded);
    }
    Ok(StageName::Reserved(promised))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_legacy_and_reserved_names_have_distinct_accounting() {
        assert_eq!(classify("a.blob"), Ok(StageName::Ordinary));
        assert_eq!(
            classify(".stage-0123456789abcdef0123456789abcdef"),
            Ok(StageName::Legacy)
        );
        for promised in [0, 1, 65536, MAX_CONTENT_BYTES] {
            let name = format!(".stage-v1-0123456789abcdef0123456789abcdef-{promised:016x}");
            assert_eq!(classify(&name), Ok(StageName::Reserved(promised)));
        }
    }

    #[test]
    fn malformed_or_oversized_reservations_never_become_small_ordinary_files() {
        for name in [
            ".stage-",
            ".stage-v2-0123456789abcdef0123456789abcdef-0000000000000001",
            ".stage-v1-0123456789ABCDEF0123456789abcdef-0000000000000001",
            ".stage-v1-0123456789abcdef0123456789abcdef-1",
            ".stage-v1-0123456789abcdef0123456789abcdef-0000000000000001-extra",
            ".stage-v1-../0123456789abcdef0123456789abcdef-0000000000000001",
        ] {
            assert_eq!(classify(name), Err(CacheError::InvalidEntry), "{name}");
        }
        let name = format!(
            ".stage-v1-0123456789abcdef0123456789abcdef-{:016x}",
            MAX_CONTENT_BYTES + 1
        );
        assert_eq!(classify(&name), Err(CacheError::LimitExceeded));
    }
}

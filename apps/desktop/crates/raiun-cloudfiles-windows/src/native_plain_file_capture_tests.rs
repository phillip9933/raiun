use super::*;
#[test]
fn plain_capture_usn_decoder_matches_v2_identity_and_positive_record_bounds() {
    let mut bytes = vec![0u8; 60];
    bytes[0..4].copy_from_slice(&60u32.to_le_bytes());
    bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
    bytes[8..16].copy_from_slice(&17u64.to_le_bytes());
    bytes[24..32].copy_from_slice(&23i64.to_le_bytes());
    assert_eq!(decode_file_usn_record(&bytes, 17), Some(23));
    assert_eq!(decode_file_usn_record(&bytes, 18), None);
    for len in [0, 4, 32, 59] {
        assert_eq!(decode_file_usn_record(&bytes[..len], 17), None);
    }
    for major in [0u16, 1, 3] {
        let mut altered = bytes.clone();
        altered[4..6].copy_from_slice(&major.to_le_bytes());
        assert_eq!(decode_file_usn_record(&altered, 17), None);
    }
    for length in [0u32, 59, 61, u32::MAX] {
        let mut altered = bytes.clone();
        altered[0..4].copy_from_slice(&length.to_le_bytes());
        assert_eq!(decode_file_usn_record(&altered, 17), None);
    }
    for usn in [0i64, -1, i64::MIN] {
        let mut altered = bytes.clone();
        altered[24..32].copy_from_slice(&usn.to_le_bytes());
        assert_eq!(decode_file_usn_record(&altered, 17), None);
    }
    assert_eq!(decode_file_usn_record(&vec![0; 65537], 17), None);
}

#[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
#[path = "native_plain_file_capture_fixture.rs"]
mod fixture;

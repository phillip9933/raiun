//! Bounded FILE_ID_EXTD_DIR_INFO decoding. Values are hints, never authority.
pub(super) const BUFFER_BYTES: usize = 4096;
pub(super) const PAGE_ENTRIES: usize = 64;
const HEADER: usize = 88;

pub(super) fn parse(bytes: &[u8]) -> Result<Vec<String>, ()> {
    if bytes.len() > BUFFER_BYTES {
        return Err(());
    }
    let mut names = Vec::new();
    let mut offset = 0usize;
    loop {
        let record = bytes.get(offset..).ok_or(())?;
        if record.len() < HEADER {
            return Err(());
        }
        let next = u32::from_le_bytes(record[0..4].try_into().map_err(|_| ())?) as usize;
        let length = u32::from_le_bytes(record[60..64].try_into().map_err(|_| ())?) as usize;
        if length == 0 || length > 510 || length % 2 != 0 {
            return Err(());
        }
        let end = HEADER.checked_add(length).ok_or(())?;
        let raw = record.get(HEADER..end).ok_or(())?;
        let units = raw
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect::<Vec<_>>();
        let name = String::from_utf16(&units).map_err(|_| ())?;
        if name.contains(['\0', '/', '\\', ':']) || name.is_empty() {
            return Err(());
        }
        names.push(name);
        if names.len() > PAGE_ENTRIES {
            return Err(());
        }
        if next == 0 {
            return Ok(names);
        }
        if next % 8 != 0 || next < end || next > record.len() {
            return Err(());
        }
        offset = offset.checked_add(next).ok_or(())?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(name: &[u16], next: u32) -> Vec<u8> {
        let mut b = vec![0; HEADER + name.len() * 2];
        b[..4].copy_from_slice(&next.to_le_bytes());
        b[60..64].copy_from_slice(&(name.len() as u32 * 2).to_le_bytes());
        for (out, unit) in b[HEADER..].chunks_exact_mut(2).zip(name) {
            out.copy_from_slice(&unit.to_le_bytes());
        }
        b
    }
    #[test]
    fn bounded_names_and_chain() {
        let mut b = record(&[65], 96);
        b.resize(96, 0);
        b.extend(record(&[66], 0));
        assert_eq!(parse(&b).unwrap(), ["A", "B"]);
        assert_eq!(parse(&record(&[46, 46], 0)).unwrap(), [".."]);
    }
    #[test]
    fn malformed_offsets_lengths_and_utf16_refuse() {
        for b in [
            vec![],
            vec![0; 87],
            record(&[], 0),
            record(&[0xd800], 0),
            record(&[47], 0),
            record(&[65], 89),
            record(&[65], 8),
            record(&[65], 4096),
        ] {
            assert!(parse(&b).is_err());
        }
        let mut b = record(&[65], 0);
        b[60..64].copy_from_slice(&1u32.to_le_bytes());
        assert!(parse(&b).is_err());
        assert!(parse(&vec![0; BUFFER_BYTES + 1]).is_err());
    }
}

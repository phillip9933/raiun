//! Platform-neutral, bounded JSON-line framing for the local agent control API.
//!
//! This crate deliberately does not open sockets, pipes, or files. Unix sockets
//! and a future Windows named-pipe adapter can share the same framing rules
//! without inheriting each other's operating-system assumptions.

use serde::{Serialize, de::DeserializeOwned};
use std::io::{Read, Write};
use zeroize::Zeroizing;

/// Maximum encoded request or response, including the trailing newline.
pub const MAX_CONTROL_MESSAGE_BYTES: usize = 1_048_576;
const READ_CHUNK_BYTES: usize = 4096;

/// Read one bounded JSON-line frame. The owned bytes are zeroized on drop,
/// which matters for requests that carry a password through local IPC.
pub fn read_json_line<R: Read>(input: &mut R) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut line = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0_u8; READ_CHUNK_BYTES]);
    loop {
        let count = input
            .read(&mut *chunk)
            .map_err(|_| "Could not read control message".to_string())?;
        if count == 0 {
            return Err("Incomplete control message".into());
        }
        let end = chunk[..count].iter().position(|byte| *byte == b'\n');
        let consumed = end.map_or(count, |index| index + 1);
        if line.len().saturating_add(consumed) > MAX_CONTROL_MESSAGE_BYTES {
            return Err("Control message exceeds the 1 MiB limit".into());
        }
        line.extend_from_slice(&chunk[..consumed]);
        if end.is_some() {
            return Ok(line);
        }
    }
}

/// Encode one JSON value as a bounded, zeroizing line frame.
pub fn encode_json_line<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut encoded = Zeroizing::new(
        serde_json::to_vec(value).map_err(|_| "Could not encode control message".to_string())?,
    );
    if encoded.len().saturating_add(1) > MAX_CONTROL_MESSAGE_BYTES {
        return Err("Control message exceeds the 1 MiB limit".into());
    }
    encoded.push(b'\n');
    Ok(encoded)
}

/// Write one bounded JSON value as a line frame.
pub fn write_json_line<W: Write, T: Serialize>(output: &mut W, value: &T) -> Result<(), String> {
    let encoded = encode_json_line(value)?;
    output
        .write_all(&encoded)
        .map_err(|_| "Could not write control message".to_string())
}

/// Read and decode one bounded JSON-line frame.
pub fn read_json_value<R: Read, T: DeserializeOwned>(input: &mut R) -> Result<T, String> {
    let line = read_json_line(input)?;
    let json = line
        .strip_suffix(b"\n")
        .ok_or_else(|| "Incomplete control message".to_string())?;
    serde_json::from_slice(json).map_err(|_| "Control message is not valid JSON".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;

    #[test]
    fn line_reader_returns_one_frame_and_ignores_trailing_frame_bytes() {
        let mut input = Cursor::new(b"{\"action\":\"status\"}\n{\"action\":\"logout\"}\n");
        let frame = read_json_line(&mut input).expect("first frame");
        assert_eq!(&*frame, b"{\"action\":\"status\"}\n");
    }

    #[test]
    fn line_reader_rejects_eof_before_newline() {
        let mut input = Cursor::new(b"{\"action\":\"status\"}");
        assert_eq!(
            read_json_line(&mut input).expect_err("incomplete frame"),
            "Incomplete control message"
        );
    }

    #[test]
    fn line_reader_rejects_oversized_frame() {
        let input = vec![b'x'; MAX_CONTROL_MESSAGE_BYTES + 1];
        let mut input = Cursor::new(input);
        assert_eq!(
            read_json_line(&mut input).expect_err("oversized frame"),
            "Control message exceeds the 1 MiB limit"
        );
    }

    #[test]
    fn encoder_bounds_frames_and_adds_exactly_one_terminator() {
        let encoded = encode_json_line(&json!({ "action": "status" })).expect("encoded");
        assert_eq!(&*encoded, b"{\"action\":\"status\"}\n");
        let oversized = "x".repeat(MAX_CONTROL_MESSAGE_BYTES);
        assert_eq!(
            encode_json_line(&oversized).expect_err("oversized frame"),
            "Control message exceeds the 1 MiB limit"
        );
    }

    #[test]
    fn read_json_value_decodes_only_a_valid_single_frame() {
        let mut input = Cursor::new(b"{\"action\":\"status\"}\n");
        let value: serde_json::Value = read_json_value(&mut input).expect("valid JSON");
        assert_eq!(value["action"], "status");

        let mut invalid = Cursor::new(b"not-json\n");
        assert_eq!(
            read_json_value::<_, serde_json::Value>(&mut invalid).expect_err("invalid JSON"),
            "Control message is not valid JSON"
        );
    }

    #[test]
    fn writer_uses_the_same_frame_limit() {
        let mut output = Vec::new();
        write_json_line(&mut output, &json!({ "ok": true })).expect("write frame");
        assert_eq!(output, b"{\"ok\":true}\n");
    }
}

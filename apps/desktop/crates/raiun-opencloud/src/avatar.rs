//! Bounded account avatar retrieval from OpenCloud Graph.
//!
//! The endpoint is fixed beneath the authenticated client's configured server;
//! no provider-supplied URL is accepted or followed. The caller can turn the
//! validated raster bytes into a data URL for its own UI.

use std::time::{Duration, Instant};

use raiun_core::backend::CloudError;
use reqwest::{Method, StatusCode, header::CONTENT_TYPE};

use crate::{OpenCloudClient, RangeReadContext, invalid, network, read_bounded};

const AVATAR_PATH: &str = "graph/v1.0/me/photo/$value";
const AVATAR_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_AVATAR_BYTES: usize = 512 * 1024;
const MAX_AVATAR_DIMENSION: u32 = 1024;
const MAX_PNG_CHUNKS: usize = 8192;

/// An authenticated OpenCloud avatar after strict media and dimension checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvatarImage {
    /// Either `image/png` or `image/jpeg`.
    pub mime_type: &'static str,
    /// Bounded raster bytes. This can be encoded as a data URL by the trusted
    /// desktop bridge; the provider never controls a fetchable URL.
    pub bytes: Vec<u8>,
}

impl OpenCloudClient {
    /// Fetch the current authenticated user's Graph photo from the fixed
    /// same-origin endpoint. A missing photo is normal and returns `Ok(None)`.
    /// The request has a five-second bound and returns no image if the bearer
    /// generation changes before the response is accepted.
    pub fn account_avatar(&self) -> Result<Option<AvatarImage>, CloudError> {
        let generation = self.token_generation();
        let deadline = Instant::now()
            .checked_add(AVATAR_TIMEOUT)
            .ok_or_else(|| invalid("avatar request deadline is invalid"))?;
        let context = RangeReadContext {
            deadline,
            token_generation: generation,
        };
        let url = self
            .server
            .join(AVATAR_PATH)
            .map_err(|_| invalid("Graph avatar endpoint is invalid"))?;
        let (request, token) = self.request_with_context(Method::GET, &url, Some(context))?;
        let mut response = request.send().map_err(network)?;

        if response.status() == StatusCode::NOT_FOUND {
            return self.with_token_generation(generation, || None);
        }
        if response.status() != StatusCode::OK {
            // `checked` keeps the existing sanitized status/diagnostic policy,
            // including explicit refusal of redirects (the client also has
            // redirect following disabled).
            return match crate::checked(response, &[StatusCode::OK], &token) {
                Err(error) => Err(error),
                Ok(_) => Err(invalid("Graph avatar response status is invalid")),
            };
        }

        if response
            .content_length()
            .is_some_and(|length| length > MAX_AVATAR_BYTES as u64)
        {
            return Err(invalid("avatar response exceeds its size limit"));
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            .ok_or_else(|| invalid("avatar response has no supported image type"))?;
        let mime_type = if content_type.eq_ignore_ascii_case("image/png") {
            "image/png"
        } else if content_type.eq_ignore_ascii_case("image/jpeg") {
            "image/jpeg"
        } else {
            return Err(invalid("avatar response has no supported image type"));
        };
        let bytes = read_bounded(&mut response, MAX_AVATAR_BYTES)?;
        validate_image(mime_type, &bytes)?;
        self.with_token_generation(generation, || Some(AvatarImage { mime_type, bytes }))
    }
}

fn validate_image(mime_type: &'static str, bytes: &[u8]) -> Result<(), CloudError> {
    let (width, height) = match mime_type {
        "image/png" => png_dimensions(bytes)?,
        "image/jpeg" => jpeg_dimensions(bytes)?,
        _ => return Err(invalid("avatar image type is unsupported")),
    };
    if width == 0 || height == 0 || width > MAX_AVATAR_DIMENSION || height > MAX_AVATAR_DIMENSION {
        return Err(invalid("avatar dimensions exceed the supported limit"));
    }
    Ok(())
}

fn png_dimensions(bytes: &[u8]) -> Result<(u32, u32), CloudError> {
    const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if bytes.len() < 8 || &bytes[..8] != SIGNATURE {
        return Err(invalid("avatar image bytes do not match PNG"));
    }
    let mut cursor = 8usize;
    let mut chunks = 0usize;
    let mut dimensions = None;
    let mut saw_data = false;
    loop {
        chunks += 1;
        if chunks > MAX_PNG_CHUNKS || cursor.checked_add(12).is_none_or(|end| end > bytes.len()) {
            return Err(invalid("avatar PNG structure is invalid"));
        }
        let length = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        let kind = &bytes[cursor + 4..cursor + 8];
        let data_start = cursor + 8;
        let data_end = data_start
            .checked_add(length)
            .ok_or_else(|| invalid("avatar PNG structure is invalid"))?;
        let chunk_end = data_end
            .checked_add(4)
            .ok_or_else(|| invalid("avatar PNG structure is invalid"))?;
        if chunk_end > bytes.len() {
            return Err(invalid("avatar PNG structure is invalid"));
        }
        let expected_crc = u32::from_be_bytes(bytes[data_end..chunk_end].try_into().unwrap());
        if png_crc32(&bytes[cursor + 4..data_end]) != expected_crc {
            return Err(invalid("avatar PNG checksum is invalid"));
        }
        if chunks == 1 {
            if kind != b"IHDR" || length != 13 {
                return Err(invalid("avatar PNG header is invalid"));
            }
            let width = u32::from_be_bytes(bytes[data_start..data_start + 4].try_into().unwrap());
            let height =
                u32::from_be_bytes(bytes[data_start + 4..data_start + 8].try_into().unwrap());
            dimensions = Some((width, height));
        } else if kind == b"IHDR" {
            return Err(invalid("avatar PNG header is duplicated"));
        }
        if kind == b"IDAT" {
            saw_data = true;
        }
        cursor = chunk_end;
        if kind == b"IEND" {
            if length != 0 || !saw_data || cursor != bytes.len() {
                return Err(invalid("avatar PNG ending is invalid"));
            }
            return dimensions.ok_or_else(|| invalid("avatar PNG header is missing"));
        }
    }
}

fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

fn jpeg_dimensions(bytes: &[u8]) -> Result<(u32, u32), CloudError> {
    if bytes.len() < 4 || bytes[..2] != [0xff, 0xd8] || bytes[bytes.len() - 2..] != [0xff, 0xd9] {
        return Err(invalid("avatar image bytes do not match JPEG"));
    }
    let mut cursor = 2usize;
    while cursor < bytes.len() - 2 {
        if bytes[cursor] != 0xff {
            return Err(invalid("avatar JPEG marker is invalid"));
        }
        while cursor < bytes.len() && bytes[cursor] == 0xff {
            cursor += 1;
        }
        let marker = *bytes
            .get(cursor)
            .ok_or_else(|| invalid("avatar JPEG marker is truncated"))?;
        cursor += 1;
        if marker == 0xda || marker == 0xd9 || marker == 0x00 {
            return Err(invalid("avatar JPEG has no frame header"));
        }
        if matches!(marker, 0xd8 | 0x01 | 0xd0..=0xd7) {
            continue;
        }
        let length_bytes = bytes
            .get(cursor..cursor + 2)
            .ok_or_else(|| invalid("avatar JPEG segment is truncated"))?;
        let length = u16::from_be_bytes(length_bytes.try_into().unwrap()) as usize;
        if length < 2 {
            return Err(invalid("avatar JPEG segment length is invalid"));
        }
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| invalid("avatar JPEG segment is invalid"))?;
        if end > bytes.len() {
            return Err(invalid("avatar JPEG segment is truncated"));
        }
        if is_jpeg_start_of_frame(marker) {
            if length < 8 {
                return Err(invalid("avatar JPEG frame header is invalid"));
            }
            let components = usize::from(bytes[cursor + 7]);
            if components == 0 || length < 8 + components.saturating_mul(3) {
                return Err(invalid("avatar JPEG frame header is invalid"));
            }
            let height = u16::from_be_bytes(bytes[cursor + 3..cursor + 5].try_into().unwrap());
            let width = u16::from_be_bytes(bytes[cursor + 5..cursor + 7].try_into().unwrap());
            if !bytes[end..bytes.len() - 2]
                .windows(2)
                .any(|marker| marker == [0xff, 0xda])
            {
                return Err(invalid("avatar JPEG scan is missing"));
            }
            return Ok((u32::from(width), u32::from(height)));
        }
        cursor = end;
    }
    Err(invalid("avatar JPEG frame header is missing"))
}

fn is_jpeg_start_of_frame(marker: u8) -> bool {
    matches!(marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use raiun_core::backend::ErrorKind;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
    };

    fn png(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
        append_png_chunk(
            &mut bytes,
            b"IHDR",
            &[
                width.to_be_bytes().as_slice(),
                height.to_be_bytes().as_slice(),
                &[8, 2, 0, 0, 0],
            ]
            .concat(),
        );
        append_png_chunk(&mut bytes, b"IDAT", b"synthetic");
        append_png_chunk(&mut bytes, b"IEND", b"");
        bytes
    }

    fn append_png_chunk(bytes: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
        bytes.extend_from_slice(kind);
        bytes.extend_from_slice(data);
        let crc_start = bytes.len() - data.len() - 4;
        bytes.extend_from_slice(&png_crc32(&bytes[crc_start..]).to_be_bytes());
    }

    fn jpeg(width: u16, height: u16) -> Vec<u8> {
        vec![
            0xff,
            0xd8, // SOI
            0xff,
            0xc0,
            0x00,
            0x0b,
            8,
            (height >> 8) as u8,
            height as u8,
            (width >> 8) as u8,
            width as u8,
            1,
            1,
            0x11,
            0,
            0xff,
            0xda,
            0x00,
            0x08,
            1,
            1,
            0,
            0,
            0x3f,
            0,
            0x12,
            0x34,
            0xff,
            0xd9,
        ]
    }

    fn run_server(
        status: u16,
        content_type: &'static str,
        body: Vec<u8>,
        extra: &'static str,
    ) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (seen_tx, seen_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 16 * 1024);
            }
            seen_tx
                .send(String::from_utf8_lossy(&request).into_owned())
                .unwrap();
            write!(stream, "HTTP/1.1 {status} test\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\n{extra}Connection: close\r\n\r\n", body.len()).unwrap();
            stream.write_all(&body).unwrap();
        });
        (format!("http://{address}"), seen_rx, worker)
    }

    #[test]
    fn downloads_fixed_authenticated_png_and_jpeg() {
        for (mime, body) in [("image/png", png(64, 32)), ("image/jpeg", jpeg(32, 64))] {
            let (server, seen, worker) = run_server(200, mime, body.clone(), "");
            let client = OpenCloudClient::new(&server, "synthetic-avatar-token".into()).unwrap();
            let avatar = client.account_avatar().unwrap().unwrap();
            assert_eq!(avatar.mime_type, mime);
            assert_eq!(avatar.bytes, body);
            let request = seen.recv().unwrap();
            assert!(request.starts_with("GET /graph/v1.0/me/photo/$value HTTP/1.1"));
            assert!(request.contains("authorization: Bearer synthetic-avatar-token"));
            worker.join().unwrap();
        }
    }

    #[test]
    fn missing_photo_is_none_and_redirect_is_not_followed() {
        let (server, seen, worker) = run_server(404, "text/plain", b"missing".to_vec(), "");
        let client = OpenCloudClient::new(&server, "synthetic-token".into()).unwrap();
        assert!(client.account_avatar().unwrap().is_none());
        seen.recv().unwrap();
        worker.join().unwrap();

        let (server, seen, worker) = run_server(
            302,
            "text/plain",
            vec![],
            "Location: http://127.0.0.1:9/steal\r\n",
        );
        let client = OpenCloudClient::new(&server, "synthetic-token".into()).unwrap();
        assert_eq!(
            client.account_avatar().unwrap_err().kind,
            ErrorKind::InvalidResponse
        );
        seen.recv().unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn rejects_wrong_mime_magic_truncation_and_excessive_dimensions() {
        for (mime, body) in [
            ("text/html", png(2, 2)),
            ("image/png", b"not png".to_vec()),
            ("image/png", png(1025, 2)),
            ("image/jpeg", jpeg(2, 2)[..20].to_vec()),
        ] {
            let (server, seen, worker) = run_server(200, mime, body, "");
            let client = OpenCloudClient::new(&server, "synthetic-token".into()).unwrap();
            assert_eq!(
                client.account_avatar().unwrap_err().kind,
                ErrorKind::InvalidResponse
            );
            seen.recv().unwrap();
            worker.join().unwrap();
        }
    }

    #[test]
    fn rejects_oversized_body_before_accepting_image() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request).unwrap();
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: image/png\r\nConnection: close\r\n\r\n", MAX_AVATAR_BYTES + 1).as_bytes()).unwrap();
        });
        let client =
            OpenCloudClient::new(&format!("http://{address}"), "synthetic-token".into()).unwrap();
        assert_eq!(
            client.account_avatar().unwrap_err().kind,
            ErrorKind::InvalidResponse
        );
        worker.join().unwrap();
    }

    #[test]
    fn token_rotation_during_response_discards_avatar() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            accepted_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            let body = png(2, 2);
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: image/png\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            stream.write_all(&body).unwrap();
        });
        let client =
            OpenCloudClient::new(&format!("http://{address}"), "synthetic-token".into()).unwrap();
        let requester = client.clone();
        let request_thread = thread::spawn(move || requester.account_avatar());
        accepted_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        client.set_bearer_token("rotated-token".into()).unwrap();
        release_tx.send(()).unwrap();
        assert_eq!(
            request_thread.join().unwrap().unwrap_err().kind,
            ErrorKind::Unauthorized
        );
        worker.join().unwrap();
    }
}

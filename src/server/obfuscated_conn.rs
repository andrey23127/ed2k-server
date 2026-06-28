//! Obfuscation detection and handshake (SPEC.md §4).
//!
//! Detection strategy: read exactly ONE byte.
//! - If it's a known eD2k protocol marker (0xE3, 0xC5, 0xD4) → plain stream.
//! - Otherwise → obfuscated; read the rest of the DH packet and handshake.
//!
//! This avoids the deadlock where we'd try to buffer 98+ bytes while the
//! client is waiting for a server response (plain LOGINREQUEST is only 83b).

use crate::proto::crypt_stream::CryptStream;
use crate::proto::obfuscation::TcpObfuscation;
use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

/// eD2k protocol first-byte markers — any of these means a plain connection.
const PLAIN_MARKERS: [u8; 3] = [0xE3, 0xC5, 0xD4];

/// Minimum payload for a DH handshake after the first byte:
///   96 bytes DH pubkey A + 1 byte padding_len = 97
const DH_REST_MIN: usize = 97;

/// Detect obfuscation and perform handshake if needed.
/// Returns a `CryptStream` ready for `Framed<CryptStream, Ed2kCodec>`.
pub async fn make_stream(mut stream: TcpStream, support_crypt: bool) -> Result<CryptStream> {
    if !support_crypt {
        return Ok(CryptStream::plain(stream));
    }

    // Step 1: read exactly 1 byte to decide
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await?;
    let marker = first[0];

    if PLAIN_MARKERS.contains(&marker) {
        // Plain connection — prefix the already-read byte back
        debug!(marker = format!("0x{marker:02x}"), "plain connection");
        return Ok(CryptStream::plain_with_prefix(stream, vec![marker]));
    }

    // Step 2: obfuscated — read the rest of the DH packet
    info!(marker = format!("0x{marker:02x}"), "obfuscated connection — DH handshake");

    // Full negotiate buffer: marker(1) + A(96) + pad_len(1) + padding(0-15)
    // We need at least DH_REST_MIN more bytes after the marker.
    let mut rest = vec![0u8; DH_REST_MIN + 16]; // extra for padding
    let mut n = 0;
    // Read at least the required minimum
    while n < DH_REST_MIN {
        let read = stream.read(&mut rest[n..]).await?;
        if read == 0 {
            return Err(anyhow!("connection closed during DH read"));
        }
        n += read;
    }
    // Try to read padding bytes too (optional, client may not send them)
    // Use try_read (non-blocking) to avoid waiting
    if n < DH_REST_MIN + 16 {
        // One more non-blocking attempt to get trailing padding if available
        match stream.try_read(&mut rest[n..]) {
            Ok(extra) => n += extra,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
    }
    rest.truncate(n);

    // Build full negotiate buffer: [marker] + rest
    let mut full_buf = Vec::with_capacity(1 + n);
    full_buf.push(marker);
    full_buf.extend_from_slice(&rest);

    let mut obf = TcpObfuscation::new(true);

    // Phase 1: parse client DH pubkey, produce server response
    let server_resp = obf.negotiate(&full_buf)
        .map_err(|e| anyhow!("obfuscation negotiate: {e}"))?;
    stream.write_all(&server_resp).await?;

    // Phase 2: read and decrypt client handshake ack
    let mut ack = vec![0u8; 256];
    let m = stream.read(&mut ack).await?;
    if m == 0 {
        return Err(anyhow!("connection closed during handshake ack"));
    }
    ack.truncate(m);

    let leftover = obf.handshake(&mut ack)
        .map_err(|e| anyhow!("obfuscation handshake: {e}"))?
        .to_vec();

    let (recv_key, send_key) = obf.take_keys()
        .ok_or_else(|| anyhow!("keys missing after handshake"))?;

    info!("DH handshake complete — RC4 stream active");

    if leftover.is_empty() {
        Ok(CryptStream::encrypted(stream, recv_key, send_key))
    } else {
        debug!(leftover = leftover.len(), "client pipelined frame after ack");
        Ok(CryptStream::encrypted_with_prefix(stream, recv_key, send_key, leftover))
    }
}

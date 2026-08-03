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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::obfuscation::test_client::*;
    use crate::proto::obfuscation::DH_PRIME_SIZE;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Drive `make_stream` over a REAL TcpStream, as an eMule client would.
    ///
    /// Every other obfuscation test works on in-memory buffers, which cannot see
    /// the class of bug that actually matters here: `make_stream` decides how
    /// much to read from a socket, and TCP is a stream, not a message queue. A
    /// client's hello can arrive as one segment, or split across several, or
    /// with the padding trailing behind — and a reader whose loop bound is off
    /// by a byte, or which assumes one read returns the whole hello, passes
    /// every buffer test and hangs on a real connection.
    ///
    /// This came out of an interop report claiming the handshake was unreachable
    /// because the reader demanded one byte more than clients send. Packet
    /// captures showed real clients sending 99-107 bytes and the handshake
    /// completing, so the report was wrong — but nothing in the suite would have
    /// caught it if it had been right. Hence this test.
    ///
    /// `pad_len` is the parameter that matters: 0 reproduces the minimal hello
    /// from the report, and a non-zero value reproduces what real clients send.
    async fn run_handshake(pad_len: u8, split_writes: bool) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        // ── server side, exactly as connection.rs calls it ──
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.expect("accept");
            let mut stream = make_stream(sock, true).await.expect("make_stream");
            let mut buf = vec![0u8; 64];
            let n = stream.read(&mut buf).await.expect("read payload");
            buf.truncate(n);
            buf
        });

        // ── client side: a real eMule obfuscated hello ──
        let mut sock = TcpStream::connect(addr).await.expect("connect");
        let client_priv = vec![7u8; DH_PRIVATE_SIZE];
        let client_pub = dh_pow_mod(&client_priv);

        let mut hello = Vec::new();
        hello.push(0x7Au8); // marker: not a protocol byte
        hello.extend_from_slice(&client_pub);
        hello.push(pad_len);
        hello.extend(std::iter::repeat(0xEEu8).take(pad_len as usize));

        if split_writes {
            // Worst case for a length-driven reader: the marker alone, then the
            // key in two pieces, with the socket flushed between each.
            sock.write_all(&hello[..1]).await.unwrap();
            sock.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            sock.write_all(&hello[1..50]).await.unwrap();
            sock.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            sock.write_all(&hello[50..]).await.unwrap();
        } else {
            sock.write_all(&hello).await.unwrap();
        }
        sock.flush().await.unwrap();

        // ── server's DH response ──
        let mut resp = vec![0u8; 512];
        let n = sock.read(&mut resp).await.expect("server response");
        assert!(n >= DH_PRIME_SIZE, "server must answer with at least G^B");
        resp.truncate(n);

        let shared = dh_shared(&resp[..DH_PRIME_SIZE], &client_priv);
        let mut client_send = derive_rc4(&shared, MAGIC_VALUE_REQUESTER);
        let mut client_recv = derive_rc4(&shared, MAGIC_VALUE_SERVER);

        let mut dec = resp[DH_PRIME_SIZE..].to_vec();
        client_recv.apply(&mut dec);
        let sync = u32::from_le_bytes([dec[0], dec[1], dec[2], dec[3]]);
        assert_eq!(sync, MAGIC_SYNC, "client must see the server's MagicSync");

        // ── client ack, with a real eD2k frame riding behind it ──
        let mut ack = Vec::new();
        ack.extend_from_slice(&MAGIC_SYNC.to_le_bytes());
        ack.push(EM_OBFUSCATE);
        ack.push(0u8); // pad_len
        ack.extend_from_slice(b"\xE3\x05\x00\x00\x00\x38hi");
        let ack = client_send.encrypt(&ack);
        sock.write_all(&ack).await.unwrap();
        sock.flush().await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("handshake must not hang — a 5s timeout is the reported symptom")
            .expect("server task")
    }

    #[tokio::test]
    async fn end_to_end_handshake_minimal_hello() {
        // pad_len = 0: the 97-byte hello the interop report describes.
        let payload = run_handshake(0, false).await;
        assert_eq!(&payload[..3], &[0xE3, 0x05, 0x00], "eD2k frame must survive");
    }

    #[tokio::test]
    async fn end_to_end_handshake_with_padding() {
        // What real clients send — captures show 99-107 byte hellos.
        for pad in [1u8, 8, 15] {
            let payload = run_handshake(pad, false).await;
            assert_eq!(&payload[..3], &[0xE3, 0x05, 0x00], "pad_len {pad}");
        }
    }

    #[tokio::test]
    async fn end_to_end_handshake_survives_a_split_hello() {
        // The reason this test exists over a socket rather than a buffer: TCP may
        // deliver the hello in pieces, and a reader that assumes one read gets
        // the whole thing works in every unit test and hangs in production.
        let payload = run_handshake(4, true).await;
        assert_eq!(&payload[..3], &[0xE3, 0x05, 0x00]);
    }

    #[tokio::test]
    async fn plain_marker_is_passed_through_untouched() {
        // A plain client must not be dragged into a DH handshake, and the marker
        // byte make_stream consumed to make that decision has to come back.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut stream = make_stream(sock, true).await.expect("plain make_stream");
            let mut buf = vec![0u8; 16];
            let n = stream.read(&mut buf).await.unwrap();
            buf.truncate(n);
            buf
        });
        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"\xE3\x05\x00\x00\x00\x38hi").await.unwrap();
        sock.flush().await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("must not hang")
            .unwrap();
        assert_eq!(&got[..3], &[0xE3, 0x05, 0x00], "the consumed marker must be restored");
    }
}

//! OBF ping — server-to-server obfuscation handshake (TCP+12 channel).
//!
//! Algorithm fully reverse-engineered from Lugdunum 17.15 cverbose=7 log
//! and decompiled receive code (eserver.c line 2200+, servgetrandkey line
//! 63057+). The protocol works as follows:
//!
//! 1. **Send OBF ping** to peer:TCP+12 from an EPHEMERAL local socket.
//!    Payload: 4-byte random_part + 0..14 random padding bytes.
//!    This is sent IN PLAIN — peer doesn't decrypt the OBF ping itself,
//!    only its receive handler stores our random_part as our ServerKey
//!    indexed by (our_ip, our_ephemeral_port).
//!
//! 2. **Peer responds** to our ephemeral port (back on its TCP+12, so to
//!    OUR ephemeral port) with an OBFUSCATED ed2k frame. The frame is
//!    encrypted with RC4 keyed off our_random_part — which we know because
//!    we sent it.
//!
//! 3. **Decrypt reply** using:
//!      ServerKey = our_random_part (locally known)
//!      obfuscated_byte = 0xA5 (server-to-server channel marker)
//!      salt = packet[7..9]
//!      RC4_key = MD5(ServerKey_LE(4) || 0xA5(1) || salt(2))
//!      Verify magic 0x13EF24D5 at packet[9..13]
//!      Decrypt rest from packet[13..]; padlen = decrypted[0] & 0x0F
//!      ed2k_message starts at packet[14 + padlen]
//!
//! 4. **Extract peer's ServerKey** from the decrypted message. The reply is
//!    GLOBSERVSTATRES (0x97) in its EXTENDED form (44-byte payload, not
//!    the 32-byte form used on plain channel). ServerKey is at offset 36 of
//!    the payload. We store this per-peer for use on the TCP+14 channel.
//!
//! Why this works: random_part doubles as the session key. By generating it
//! ourselves and sending it openly, we tell the peer "encrypt your reply
//! with this 4-byte value". The peer doesn't have to negotiate anything
//! cryptographic — they just stash our value and use it. Clever and
//! simple.
//!
//! Current implementation: send + read reply + parse. We DON'T yet wire
//! the extracted ServerKey into the TCP+14 outgoing path; that needs to
//! happen in server/udp.rs when sending obfuscated frames to known peers.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::state::ServerState;

/// Maximum random padding bytes appended to an OBF ping payload (4-byte
/// random_part + up to 14 padding bytes — matches Lugdunum's behavior).
pub const OBF_PING_PAYLOAD_MAX_PAD: usize = 14;


/// Send an OBF ping and listen for the peer's encrypted response.
///
/// Returns the peer's ServerKey if the round-trip succeeds — that value
/// is what we use to encrypt subsequent obfuscated frames sent to this
/// peer's TCP+14 channel.
///
/// Times out after `reply_timeout` if the peer doesn't answer; not every
/// peer responds to OBF pings (some only react to follow-up traffic).
pub async fn ping_and_handshake(
    peer_tcp_ip: Ipv4Addr,
    peer_tcp_port: u16,
    reply_timeout: Duration,
) -> Result<HandshakeResult, std::io::Error> {
    // Ephemeral local socket — OS picks the port. Lugdunum's pattern (saw
    // port 50503 in capture). We keep this socket open through the
    // round-trip so the peer's reply lands here.
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local_port = socket.local_addr()?.port();

    let random_part = quick_random();
    let pad_len = (quick_random() as usize) % 15;

    let mut payload = Vec::with_capacity(4 + pad_len);
    payload.extend_from_slice(&random_part.to_le_bytes());
    for _ in 0..pad_len {
        payload.push((quick_random() & 0xFF) as u8);
    }
    // Avoid colliding with plain frame magics on the wire.
    while matches!(payload[0], 0xE3 | 0xD4 | 0xC5) {
        let r = quick_random();
        payload[0] = (r & 0xFF) as u8;
    }

    let dst = SocketAddrV4::new(peer_tcp_ip, peer_tcp_port.wrapping_add(12));
    socket.send_to(&payload, dst).await?;

    debug!(
        peer_ip = %peer_tcp_ip,
        peer_tcp = peer_tcp_port,
        dst_port = dst.port(),
        local_port,
        random_part = format!("0x{:08x}", random_part),
        pad_len,
        "obf ping sent"
    );

    // Wait for peer's encrypted reply on our ephemeral socket.
    let mut buf = vec![0u8; 2048];
    let (n, from) = match tokio::time::timeout(reply_timeout, socket.recv_from(&mut buf)).await {
        Ok(Ok((n, from))) => (n, from),
        Ok(Err(e)) => {
            return Err(e);
        }
        Err(_) => {
            warn!(peer_ip = %peer_tcp_ip, "obf ping: no reply within timeout (3s)");
            return Ok(HandshakeResult {
                peer_ip: peer_tcp_ip,
                random_part,
                server_key: None,
            });
        }
    };

    info!(
        peer_ip = %peer_tcp_ip,
        from = %from,
        bytes = n,
        "obf ping: got reply"
    );

    // Decode the obfuscated reply. The key is our random_part.
    let result = decode_obf_s2s(&buf[..n], random_part);

    Ok(HandshakeResult {
        peer_ip: peer_tcp_ip,
        random_part,
        server_key: result,
    })
}

/// Decode a server-to-server obfuscated UDP reply (OBF ping response).
///
/// `session_key` = the random_part we sent in the OBF ping payload.
/// The seed stores that value and encrypts its reply with it.
///
/// Tries both 0xa5 and 0x00 as the obf_byte (channel marker in MD5 key
/// derivation), so we discover which the remote Lugdunum version uses.
/// Logs diagnostic hex so production logs reveal the exact failure mode.
pub fn decode_obf_s2s(packet: &[u8], session_key: u32) -> Option<u32> {
    use crate::proto::server_obfuscation::decode_with_obfbyte;

    if packet.len() < 10 {
        warn!(len = packet.len(), "obf decode: packet too short (need ≥10)");
        return None;
    }

    // Log the raw hex prefix so we can diagnose from production logs alone.
    let hex_prefix: String = packet[..packet.len().min(20)]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    info!(
        pkt_len = packet.len(),
        hex_prefix = %hex_prefix,
        session_key = format!("0x{:08x}", session_key),
        "obf decode: raw packet"
    );

    // Try obf_byte = 0xa5 first (TCP+12 / obfpingport channel, used by Lugdunum
    // when sending from its 4673 equivalent).
    if let Some(msg) = decode_with_obfbyte(packet, session_key, 0xa5) {
        info!(obf_byte = "0xa5", msg_len = msg.len(),
              proto = format!("0x{:02x}", msg.first().copied().unwrap_or(0)),
              opcode = format!("0x{:02x}", msg.get(1).copied().unwrap_or(0)),
              "obf decode: magic OK with 0xa5");
        if let Some(key) = extract_server_key(&msg) {
            return Some(key);
        }
    } else {
        info!("obf decode: magic FAILED with obf_byte=0xa5, trying 0x00");
    }

    // Fallback: obf_byte = 0x00 (main s2s channel, used by some configs).
    if let Some(msg) = decode_with_obfbyte(packet, session_key, 0x00) {
        info!(obf_byte = "0x00", msg_len = msg.len(),
              proto = format!("0x{:02x}", msg.first().copied().unwrap_or(0)),
              opcode = format!("0x{:02x}", msg.get(1).copied().unwrap_or(0)),
              "obf decode: magic OK with 0x00");
        if let Some(key) = extract_server_key(&msg) {
            return Some(key);
        }
    } else {
        warn!("obf decode: magic FAILED with both 0xa5 and 0x00 — wrong session_key?");
    }

    None
}

fn extract_server_key(msg: &[u8]) -> Option<u32> {
    if msg.len() < 2 {
        warn!("obf decode: message too short ({} bytes)", msg.len());
        return None;
    }
    if msg[0] != 0xE3 || msg[1] != 0x97 {
        info!(
            proto = format!("0x{:02x}", msg[0]),
            opcode = format!("0x{:02x}", msg[1]),
            msg_len = msg.len(),
            "obf decode: decoded but not GLOBSERVSTATRES 0x97 — logging full hex"
        );
        // Log more bytes to diagnose what message type this actually is.
        let hex: String = msg[..msg.len().min(32)]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        info!(hex = %hex, "obf decode: decoded message hex");
        return None;
    }
    let payload = &msg[2..];
    info!(payload_len = payload.len(), "obf decode: GLOBSERVSTATRES payload");
    if payload.len() < 40 {
        // Log what we have — maybe it's the SHORT form (no ServerKey).
        let hex: String = payload.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        info!(hex = %hex, "obf decode: payload too short for ServerKey (need ≥40)");
        return None;
    }
    // Extended layout: challenge+users+files+maxconn+soft+hard+pingflg+lowid
    //                  = 8 fields × 4 bytes = 32 bytes, then portUDP(2)+portTCP(2)
    //                  = 36 bytes, then ServerKey(4) at [36..40].
    let server_key = u32::from_le_bytes([
        payload[36], payload[37], payload[38], payload[39],
    ]);
    info!(
        server_key = format!("0x{:08x}", server_key),
        "obf decode: extracted peer ServerKey"
    );
    Some(server_key)
}

/// One-shot handshake result. Caller stores `server_key` in per-peer state
/// to use it for later obfuscated frames toward this peer's TCP+14.
pub struct HandshakeResult {
    pub peer_ip: Ipv4Addr,
    pub random_part: u32,
    pub server_key: Option<u32>,
}

/// Background task: periodically perform OBF ping handshakes with seeds.
///
/// Without these, peer servers never learn we support obfuscation and our
/// gossip presence on TCP+4 alone isn't enough to qualify for inclusion in
/// real seeds' server.met (Lugdunum demands obf round-trip).
#[deprecated(note = "OBF ping is now integrated into gossip's per-seed handshake — this is a no-op")]
#[allow(dead_code)]
pub async fn obf_ping_loop(_seeds: Vec<SocketAddrV4>, _state: Arc<ServerState>) {
    // Intentionally empty — gossip::seed_loop now performs OBF ping inline
    // as part of the unified 3-phase handshake.
}

fn quick_random() -> u32 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u32> = Cell::new({
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0x1234_5678);
            nanos.wrapping_mul(0x9E37_79B9).wrapping_add(1)
        });
    }
    STATE.with(|c| {
        let mut s = c.get();
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        if s == 0 {
            s = 0x0BAD_F00D;
        }
        c.set(s);
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_random_varies() {
        let a = quick_random();
        let b = quick_random();
        let c = quick_random();
        assert!(!(a == b && b == c));
    }

    #[test]
    fn decode_obf_rejects_too_short() {
        assert!(decode_obf_s2s(&[0u8; 10], 0xCAFEBABE).is_none());
    }

    #[test]
    fn decode_obf_rejects_bad_magic() {
        // 30-byte packet with random content: magic check at offset 9 will fail.
        let pkt = vec![0u8; 30];
        assert!(decode_obf_s2s(&pkt, 0xCAFEBABE).is_none());
    }

    #[test]
    fn encode_decode_round_trip() {
        // Build a valid obfuscated packet using server_obfuscation::encode
        // (which produces the real wire format), then verify that
        // decode_obf_s2s extracts the ServerKey correctly.
        //
        // This exercises the GLOBSERVSTATRES parsing and the full decode
        // path including both obf_byte variants that we try.
        let session_key: u32 = 0x42793A72;
        let peer_server_key: u32 = 0x30D37329;

        // Build ed2k message: proto(1) + opcode(1) + 44-byte payload.
        // ServerKey at payload[36..40].
        let mut payload = vec![0u8; 44];
        payload[36..40].copy_from_slice(&peer_server_key.to_le_bytes());
        let mut ed2k = vec![0xE3u8, 0x97u8];
        ed2k.extend_from_slice(&payload);

        // Encode using the 0xa5 variant (what a Lugdunum seed uses
        // when responding from its TCP+12/obfpingport channel).
        let frame_a5 = crate::proto::server_obfuscation::encode_with_obfbyte(
            &ed2k, session_key, 0xCAFE_1234, 0xa5
        );

        // decode_obf_s2s tries 0xa5 first, should succeed.
        let extracted = decode_obf_s2s(&frame_a5, session_key);
        assert_eq!(extracted, Some(peer_server_key),
            "should extract ServerKey from 0xa5-encoded frame");

        // Also test the 0x00 fallback variant.
        let frame_00 = crate::proto::server_obfuscation::encode_with_obfbyte(
            &ed2k, session_key, 0xDEAD_BEEF, 0x00
        );
        let extracted2 = decode_obf_s2s(&frame_00, session_key);
        assert_eq!(extracted2, Some(peer_server_key),
            "should extract ServerKey from 0x00-encoded frame via fallback");
    }
}


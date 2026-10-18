//! Callback flow handler (SPEC.md §3.6).
//!
//! When a HighID client wants to download from a LowID client, it sends
//! OP_CALLBACKREQUEST(low_id) to the server. The server:
//!   1. Validates that the requester is HighID (LowID→LowID is impossible).
//!   2. Looks up the LowID client by assigned_id.
//!   3. Sends OP_CALLBACKREQUESTED(requester_ip, requester_port) to the LowID,
//!      plus the requester's crypt options and user hash when both sides
//!      support obfuscation (issue #32).
//!   4. On failure sends OP_CALLBACK_FAIL to the requester.
//!
//! The LowID client then opens a direct outbound TCP connection to the HighID.
//!
//! Note: LowID↔LowID connections use the separate NAT traversal mechanism (§3.12).

use crate::proto::{opcodes::*, CryptStream, Ed2kCodec, Frame};
use crate::state::{ClientHandle, ServerState};
use anyhow::Result;
use bytes::{BufMut, BytesMut};
use futures::SinkExt;
use std::net::IpAddr;

use tokio_util::codec::Framed;

use tracing::debug;

/// Handle OP_CALLBACKREQUEST from a client.
/// `target_id` is the LowID of the client the requester wants to reach.
pub async fn handle_callback_request(
    state: &ServerState,
    requester: &ClientHandle,
    target_id: u32,
    framed: &mut Framed<CryptStream, Ed2kCodec>,
) -> Result<()> {
    // Only HighID clients can initiate callbacks — LowID has no routable address.
    if !requester.is_high_id {
        debug!(
            ip = %requester.ip,
            "CALLBACKREQUEST from LowID — ignoring"
        );
        return Ok(());
    }

    // Find the target client by assigned_id. O(1) via the id index — this used
    // to walk every connected client, on the packet that is the whole point of
    // LowID-to-LowID connectivity.
    let target = state.client_by_assigned_id(target_id);

    let Some(target) = target else {
        // Debug, not warn: a target that left between the source list and the
        // callback is routine, and clients retry, so at warn level this was a
        // steady stream of lines on a busy server.
        debug!(
            requester = %requester.ip,
            target_id,
            "CALLBACKREQUEST: target not connected"
        );
        framed.send(Frame::new(OP_CALLBACK_FAIL, vec![])).await?;
        return Ok(());
    };

    // CALLBACKREQUESTED: requester_ip(4) + requester_port(2), and the crypt
    // options and user hash when both can obfuscate (see `callback_crypt`).
    let callback_frame = build_callbackrequested(
        requester.ip,
        requester.port,
        callback_crypt(requester, &target),
    );

    // Push to target's send channel (never blocks; drops are counted)
    let outcome = target.send_frame(callback_frame);
    state
        .admission
        .push
        .note(crate::admission::PushKind::Callback, outcome);

    debug!(
        requester_ip = %requester.ip,
        target_id,
        target_ip = %target.ip,
        "callback forwarded"
    );

    Ok(())
}

/// The crypt options and user hash to add to OP_CALLBACKREQUESTED, or `None`
/// for the 6-byte form (issue #32).
///
/// Without the requester's user hash the LowID side cannot derive the
/// obfuscation key, so it connects in plain TCP: the hello, and the whole
/// upload if the slot is granted on that socket, go unobfuscated, and a
/// requester that REQUIRES obfuscation refuses the connection outright.
///
/// Sent only when both clients announced CAPABLE_SUPPORTCRYPT at login, as
/// Lugdunum does (it sends 0x0C or 0x1D bytes on exactly that condition): a
/// target that cannot obfuscate has no use for the hash. The options byte is
/// CT_SERVER_FLAGS bits 9-11 (support 0x01, request 0x02, require 0x04), the
/// layout eMule and aMule read at `packet[6]`; they treat 23 bytes or more as
/// the long form and ignore the extra bytes otherwise.
fn callback_crypt(requester: &ClientHandle, target: &ClientHandle) -> Option<(u8, [u8; 16])> {
    let both = requester.server_flags & target.server_flags & CAPABLE_SUPPORTCRYPT != 0;
    both.then_some((((requester.server_flags >> 9) & 0x07) as u8, requester.user_hash))
}

fn build_callbackrequested(ip: IpAddr, port: u16, crypt: Option<(u8, [u8; 16])>) -> Frame {
    let mut payload = BytesMut::with_capacity(23);
    // In eD2k protocol, client IDs in TCP payloads are stored as the IPv4
    // address interpreted as a uint32 in host (little-endian) byte order,
    // which means the octets appear as [octet3, octet2, octet1, octet0].
    // Example: 1.2.3.4 → u32 = 0x04030201 → LE bytes = [0x01, 0x02, 0x03, 0x04]
    // Equivalently: just write the octets in order (same result via from_le_bytes).
    match ip {
        IpAddr::V4(v4) => {
            // Store as u32 little-endian = octets in natural order
            let octets = v4.octets();
            let as_u32 = u32::from_le_bytes(octets);
            payload.put_u32_le(as_u32);
        }
        // Unreachable for an IPv6 requester, and deliberately so: the payload
        // has four bytes for an address and no way to carry a v6 one, so a
        // target told 0.0.0.0 would burn a connection attempt on nothing.
        //
        // What protects this is the LowID check at the top of
        // `handle_callback_request` combined with the rule that an IPv6 session
        // is never given a HighID — an eD2k client id IS an IPv4 address. If
        // that rule is ever relaxed, this branch becomes reachable and has to be
        // replaced by a refusal (OP_CALLBACK_FAIL), not by a zero.
        _ => payload.put_u32_le(0),
    }
    payload.put_u16_le(port);
    if let Some((options, hash)) = crypt {
        payload.put_u8(options);
        payload.put_slice(&hash);
    }
    Frame::new(OP_CALLBACKREQUESTED, payload.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callbackrequested_format() {
        use std::net::Ipv4Addr;
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let frame = build_callbackrequested(ip, 4662, None);
        assert_eq!(frame.opcode, OP_CALLBACKREQUESTED);
        assert_eq!(frame.payload.len(), 6);
        // IP 1.2.3.4 as u32 LE
        assert_eq!(&frame.payload[..4], &[1, 2, 3, 4]);
        // Port 4662 = 0x1236 LE
        assert_eq!(&frame.payload[4..6], &[0x36, 0x12]);

        // Long form: options at byte 6, user hash at 7..23 (issue #32).
        let frame = build_callbackrequested(ip, 4662, Some((0x03, [0xAB; 16])));
        assert_eq!(frame.payload.len(), 23);
        assert_eq!(&frame.payload[..6], &[1, 2, 3, 4, 0x36, 0x12]);
        assert_eq!(frame.payload[6], 0x03);
        assert_eq!(&frame.payload[7..23], &[0xAB; 16]);
    }

    fn client(flags: u32, hash: u8) -> ClientHandle {
        ClientHandle {
            user_hash: [hash; 16],
            assigned_id: 0x0A00_0001,
            ip: IpAddr::V4(std::net::Ipv4Addr::new(1, 0, 0, 10)),
            port: 4662,
            udp_port: 0,
            natt_capable: false,
            nick: "t".into(),
            server_flags: flags,
            ipv6_capable: false,
            ipv6: None,
            is_high_id: true,
            connected_at: std::time::Instant::now(),
            country: "??".into(),
            software: "test".into(),
            software_detail: "test".into(),
            login_fp: String::new(),
            csam_attempts: 0,
            soft_limit_warned: false,
            offer_policy: None,
            slot: Default::default(),
            tx: None,
            last_activity_ms: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    #[test]
    fn crypt_options_go_only_between_two_obfuscating_clients() {
        let s = CAPABLE_SUPPORTCRYPT;
        let sr = s | CAPABLE_REQUESTCRYPT;
        let srq = sr | CAPABLE_REQUIRECRYPT;
        // Bits 9-11 of the requester's flags, and its own hash.
        assert_eq!(callback_crypt(&client(0x0719, 1), &client(s, 2)), Some((0x03, [1; 16])));
        assert_eq!(callback_crypt(&client(srq, 1), &client(s, 2)), Some((0x07, [1; 16])));
        assert_eq!(callback_crypt(&client(s, 1), &client(srq, 2)), Some((0x01, [1; 16])));
        // Either side without obfuscation: the 6-byte form, as Lugdunum.
        assert_eq!(callback_crypt(&client(sr, 1), &client(0x0019, 2)), None);
        assert_eq!(callback_crypt(&client(0x0019, 1), &client(sr, 2)), None);
    }
}

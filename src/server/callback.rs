//! Callback flow handler (SPEC.md §3.6).
//!
//! When a HighID client wants to download from a LowID client, it sends
//! OP_CALLBACKREQUEST(low_id) to the server. The server:
//!   1. Validates that the requester is HighID (LowID→LowID is impossible).
//!   2. Looks up the LowID client by assigned_id.
//!   3. Sends OP_CALLBACKREQUESTED(requester_ip, requester_port) to the LowID.
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

use tracing::{debug, warn};

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

    // Find the target client by assigned_id
    let target = state.clients.iter().find(|e| e.assigned_id == target_id);

    let Some(target) = target else {
        warn!(
            requester = %requester.ip,
            target_id,
            "CALLBACKREQUEST: target not connected"
        );
        framed.send(Frame::new(OP_CALLBACK_FAIL, vec![])).await?;
        return Ok(());
    };

    // Build CALLBACKREQUESTED packet: requester_ip(4) + requester_port(2)
    let callback_frame = build_callbackrequested(requester.ip, requester.port);

    // Push to target's send channel (fire-and-forget)
    target.send_frame(callback_frame);

    debug!(
        requester_ip = %requester.ip,
        target_id,
        target_ip = %target.ip,
        "callback forwarded"
    );

    Ok(())
}

fn build_callbackrequested(ip: IpAddr, port: u16) -> Frame {
    let mut payload = BytesMut::with_capacity(6);
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
        _ => payload.put_u32_le(0),
    }
    payload.put_u16_le(port);
    Frame::new(OP_CALLBACKREQUESTED, payload.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callbackrequested_format() {
        use std::net::Ipv4Addr;
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let frame = build_callbackrequested(ip, 4662);
        assert_eq!(frame.opcode, OP_CALLBACKREQUESTED);
        assert_eq!(frame.payload.len(), 6);
        // IP 1.2.3.4 as u32 LE
        assert_eq!(&frame.payload[..4], &[1, 2, 3, 4]);
        // Port 4662 = 0x1236 LE
        assert_eq!(&frame.payload[4..6], &[0x36, 0x12]);
    }
}

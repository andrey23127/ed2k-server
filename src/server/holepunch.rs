//! LowID↔LowID NAT-traversal coordination (SPEC §3.12).
//!
//! PROBLEM: two LowID clients cannot connect. Neither has a routable address,
//! so the stock server callback (which tells a LowID to connect OUT to a
//! reachable requester) does not help — the requester is unreachable too.
//!
//! The eMule buddy mods (Neo-Mule, eMuleAI) solve this with a HighID "buddy"
//! found via Kademlia that relays a callback. That needs Kad and a willing
//! HighID third party.
//!
//! THIS server-coordinated approach needs neither. The server already has a TCP
//! control channel to every logged-in client and knows each one's public IP (as
//! seen on their TCP connection). When LowID A wants LowID B:
//!   1. A sends OP_LOWID_HOLEPUNCH_REQUEST(target_id = B, requester_udp_port).
//!   2. The server looks up B among connected clients.
//!   3. The server sends OP_LOWID_HOLEPUNCH_INFO to BOTH A and B, each carrying
//!      the OTHER side's (ip, tcp_port, udp_port, user_hash) and a role byte.
//!   4. Both clients fire UDP packets at each other simultaneously. With cone
//!      NAT on both sides the packets open the path and a connection forms.
//!
//! The server only ever sends two small address packets. It NEVER relays file
//! data — that would turn a light index server into a bandwidth relay. This is
//! essentially the stock OP_CALLBACK idea generalized to both-sides-LowID, plus
//! a UDP port exchange.
//!
//! LIMITATION (documented, not a bug): hole punching only works when each side's
//! public UDP port is predictable from what the server sees — i.e. cone NAT
//! (including cone-type carrier-grade NAT). If either side is behind a SYMMETRIC
//! NAT/CGNAT (a different external port per destination), the port the server
//! observed will not match the port needed peer-to-peer and the punch fails.
//! There is no server-only fix for symmetric-both without relaying data, which
//! we deliberately refuse. The feature is therefore best-effort.

use crate::proto::{opcodes::*, Frame};
use crate::state::ServerState;
use bytes::{BufMut, BytesMut};
use std::net::IpAddr;
use std::time::Duration;
use tracing::{debug, warn};

/// Observed external UDP ports older than this are ignored (the client may have
/// reconnected behind a fresh NAT mapping).
///
/// CRITICAL: this MUST be comfortably larger than the client's NAT-T UDP
/// keepalive interval, or the observed port expires *between* keepalives and we
/// fall back to the (wrong, internal) announced port — so a peer is told a UDP
/// port the NAT never opened and the punch dies. The mod's client sends the
/// keepalive every ~90 s of its own throttle but is only driven once per 60 s
/// tick, so in practice it arrives every ~120–132 s. A 120 s window therefore
/// expired ~10 s before each refresh, which is exactly why "freshly connected
/// peers download fine, but after a few minutes hole punching stops working":
/// the observation was stale in the gap. Use 600 s — far above the real refresh
/// period, so the observed port stays trusted continuously, while still being
/// short enough that a genuine reconnect behind a new mapping recovers quickly
/// (the next keepalive overwrites it within ~2 min anyway).
const OBSERVED_UDP_FRESH: Duration = Duration::from_secs(600);

/// Return the external (post-NAT) UDP port we last saw `ip` send from, if it is
/// fresh enough to trust. Falls back to None so the caller uses the announced
/// port. Only meaningful for IPv4 (eD2k is IPv4-only).
fn observed_udp_port(state: &ServerState, ip: IpAddr, announced: u16) -> u16 {
    if let IpAddr::V4(v4) = ip {
        if let Some(entry) = state.observed_udp_ports.get(&v4) {
            let (port, seen) = *entry;
            if port != 0 && seen.elapsed() < OBSERVED_UDP_FRESH {
                return port;
            }
        }
    }
    announced
}

/// Reasons sent in OP_LOWID_HOLEPUNCH_FAIL.
pub const FAIL_TARGET_NOT_CONNECTED: u8 = 1;
pub const FAIL_TARGET_IS_HIGHID: u8 = 2;
pub const FAIL_BAD_REQUEST: u8 = 3;
pub const FAIL_TARGET_NO_UDP: u8 = 4;

/// Handle OP_LOWID_HOLEPUNCH_REQUEST from a logged-in client.
///
/// `requester_id` / `requester_*` describe the client that sent the request
/// (already authenticated by the connection). `target_id` is the server ID of
/// the LowID client they want to reach. `requester_udp_port` is the requester's
/// own UDP port, included in the request payload.
///
/// Returns the FAIL reason code if coordination could not happen (the caller
/// has already been sent the FAIL frame), or None on success.
pub fn handle_holepunch_request(
    state: &ServerState,
    requester_user_hash: &[u8; 16],
    requester_id: u32,
    requester_ip: IpAddr,
    requester_tcp_port: u16,
    requester_udp_port: u16,
    target_id: u32,
) -> Option<u8> {
    // Record the requester's UDP port so that, if it is later a target, the
    // server already knows how to reach it. Cheap single-shard update.
    if let Some(mut me) = state.clients.get_mut(requester_user_hash) {
        me.udp_port = requester_udp_port;
    }

    // A client asking to punch to itself is a no-op/bug.
    if target_id == requester_id {
        send_fail(state, requester_user_hash, target_id, FAIL_BAD_REQUEST);
        return Some(FAIL_BAD_REQUEST);
    }

    // Look up the target by assigned server ID. We copy out the few fields we
    // need and DROP the DashMap guard immediately: holding an iterator guard
    // while calling state.clients.get(requester) below could deadlock if the two
    // keys land on the same shard. So extract-then-drop.
    let target_data = state
        .clients
        .iter()
        .find(|e| e.assigned_id == target_id)
        .map(|t| (t.ip, t.port, t.udp_port, t.user_hash, t.is_high_id, t.is_alive()));

    let Some((t_ip, t_tcp, t_udp, t_hash, t_high, t_alive)) = target_data else {
        debug!(requester_id, target_id, "holepunch: target not connected");
        send_fail(state, requester_user_hash, target_id, FAIL_TARGET_NOT_CONNECTED);
        return Some(FAIL_TARGET_NOT_CONNECTED);
    };

    // Refuse to coordinate toward a target whose control session is already
    // dead. FIELD BUG: a peer behind a provider/port-restricted NAT often has
    // its TCP control link silently dropped (it logs "Error 10061 on first
    // connect" and only reconnects on the 2nd try). Until the server sweeps the
    // stale entry, this lookup still finds it — so we used to send INFO into a
    // dead socket (lost) AND hand the requester a UDP port whose NAT mapping no
    // longer exists. The requester's punches then vanished into a black hole and
    // its tunnel never came up — exactly the "full-cone peer cannot download
    // first" symptom. The mpsc channel to the target's connection task closes as
    // soon as that task ends, so is_alive() == false is a precise, immediate
    // signal (no timeout needed). Send FAIL so the requester abandons this stale
    // source cleanly and re-asks once the target's session is healthy again.
    if !t_alive {
        debug!(requester_id, target_id, "holepunch: target session dead (channel closed), refusing");
        send_fail(state, requester_user_hash, target_id, FAIL_TARGET_NOT_CONNECTED);
        *state.block_stats.entry("holepunch_target_dead".to_string()).or_insert(0) += 1;
        return Some(FAIL_TARGET_NOT_CONNECTED);
    }

    // If the target is HighID, no punch is needed — the requester can connect
    // (or use the stock callback). Tell the requester so it takes that path.
    if t_high {
        send_fail(state, requester_user_hash, target_id, FAIL_TARGET_IS_HIGHID);
        return Some(FAIL_TARGET_IS_HIGHID);
    }

    // The target must have announced a UDP port (i.e. it is also a modified
    // client). A stock LowID client cannot participate as a target.
    if t_udp == 0 {
        debug!(target_id, "holepunch: target has no known UDP port (stock client?)");
        send_fail(state, requester_user_hash, target_id, FAIL_TARGET_NO_UDP);
        return Some(FAIL_TARGET_NO_UDP);
    }

    // Build and send INFO to BOTH sides. Each gets the other's coordinates.
    // role 0 = initiate the punch first, role 1 = the other side. Assigning the
    // lower server ID the initiator role is arbitrary but deterministic, so the
    // two clients agree on who fires first without extra negotiation.
    let requester_is_initiator = requester_id < target_id;

    // Prefer the external (post-NAT) UDP port we actually observed each side
    // send from, falling back to the announced port. This is what makes the
    // punch reach a NATed peer on cone-type NATs.
    let t_udp_eff = observed_udp_port(state, t_ip, t_udp);
    let requester_udp_eff = observed_udp_port(state, requester_ip, requester_udp_port);

    let to_requester = build_info(
        t_ip, t_tcp, t_udp_eff, &t_hash,
        if requester_is_initiator { 0 } else { 1 },
    );
    let to_target = build_info(
        requester_ip, requester_tcp_port, requester_udp_eff, requester_user_hash,
        if requester_is_initiator { 1 } else { 0 },
    );

    // Both lookups below take fresh short-lived guards (the target iterator
    // guard was already dropped above), so there is no cross-shard deadlock.
    if let Some(target) = state.clients.iter().find(|e| e.assigned_id == target_id) {
        target.send_frame(to_target);
    }
    if let Some(me) = state.clients.get(requester_user_hash) {
        me.send_frame(to_requester);
    }

    debug!(
        requester_id, requester_ip = %requester_ip,
        target_id, target_ip = %t_ip,
        "holepunch coordinated (INFO sent to both sides)"
    );
    *state.block_stats.entry("holepunch_coordinated".to_string()).or_insert(0) += 1;
    None
}

/// Re-run hole-punch coordination for the same requester/target a few times
/// after the initial call, in a detached background task.
///
/// WHY: the REQUEST/INFO control messages travel over the server TCP link. A
/// captured failure showed INFO to one side delayed ~110 s by TCP retransmit
/// while the other side punched immediately, so the punch bursts never
/// overlapped and the tunnel never formed ("freshly connected peers download,
/// older ones don't, reconnect fixes it"). Re-coordinating a couple of times,
/// a few seconds apart, lets both sides receive a fresh INFO close enough in
/// time to punch together, surviving a single lost/late control packet.
///
/// It simply calls `handle_holepunch_request` again with the SAME arguments, so
/// it reuses every check (target still alive, still LowID, freshest observed
/// UDP port) — no logic is duplicated and nothing diverges from the first send.
///
/// SAFETY — why this cannot break anything:
///   * A repeat only re-sends the same INFO (or a FAIL if the target has since
///     gone). A duplicate INFO makes a client fire another idempotent punch
///     burst (back-punches are nonce-suppressed, duplicate SYN is matched and
///     dropped), so an extra INFO is strictly best-effort help, never harmful.
///   * `handle_holepunch_request` already re-checks the target is present,
///     alive, LowID and has a UDP port, and sends FAIL otherwise — so a retry
///     toward a vanished peer degrades to a clean FAIL, not a bad punch.
///   * `send_frame` is fire-and-forget; a full channel just drops the resend.
///   * Runs in a detached task: never delays the requester's handler.
///   * block_stats counters ("holepunch_coordinated" etc.) will tick once per
///     attempt; that is acceptable (they count coordination attempts).
#[allow(clippy::too_many_arguments)]
pub fn schedule_info_retries(
    state: std::sync::Arc<ServerState>,
    requester_user_hash: [u8; 16],
    requester_id: u32,
    requester_ip: IpAddr,
    requester_tcp_port: u16,
    requester_udp_port: u16,
    target_id: u32,
) {
    tokio::spawn(async move {
        // Two extra attempts at +1.2s and +3.0s, IN ADDITION to the immediate
        // coordination already done by the caller. Small and short so a
        // genuinely unreachable pair still fails fast.
        const DELAYS_MS: [u64; 2] = [1200, 3000];
        let mut elapsed = 0u64;
        for &at in DELAYS_MS.iter() {
            tokio::time::sleep(Duration::from_millis(at - elapsed)).await;
            elapsed = at;
            // Stop early if the requester has disconnected; no point re-coordinating.
            if !state.clients.get(&requester_user_hash).map(|c| c.is_alive()).unwrap_or(false) {
                break;
            }
            let _ = handle_holepunch_request(
                &state,
                &requester_user_hash,
                requester_id,
                requester_ip,
                requester_tcp_port,
                requester_udp_port,
                target_id,
            );
        }
    });
}

/// OP_LOWID_HOLEPUNCH_INFO payload:
///   peer_ip(4 LE) + peer_tcp_port(2 LE) + peer_udp_port(2 LE)
///   + peer_user_hash(16) + role(1)
fn build_info(ip: IpAddr, tcp_port: u16, udp_port: u16, user_hash: &[u8; 16], role: u8) -> Frame {
    let mut p = BytesMut::with_capacity(4 + 2 + 2 + 16 + 1);
    match ip {
        // eD2k stores IPv4 as a u32; writing the octets in order is equivalent
        // to u32::from_le_bytes(octets) written little-endian.
        IpAddr::V4(v4) => p.put_u32_le(u32::from_le_bytes(v4.octets())),
        _ => p.put_u32_le(0),
    }
    p.put_u16_le(tcp_port);
    p.put_u16_le(udp_port);
    p.put_slice(user_hash);
    p.put_u8(role);
    Frame::new(OP_LOWID_HOLEPUNCH_INFO, p.to_vec())
}

/// Send OP_LOWID_HOLEPUNCH_FAIL(target_id, reason) to the requester.
fn send_fail(state: &ServerState, requester_user_hash: &[u8; 16], target_id: u32, reason: u8) {
    let mut p = BytesMut::with_capacity(5);
    p.put_u32_le(target_id);
    p.put_u8(reason);
    if let Some(me) = state.clients.get(requester_user_hash) {
        me.send_frame(Frame::new(OP_LOWID_HOLEPUNCH_FAIL, p.to_vec()));
    } else {
        warn!(target_id, reason, "holepunch fail: requester vanished before reply");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn info_payload_format() {
        let hash = [7u8; 16];
        let frame = build_info(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 4662, 4672, &hash, 0,
        );
        assert_eq!(frame.opcode, OP_LOWID_HOLEPUNCH_INFO);
        assert_eq!(frame.payload.len(), 25);
        assert_eq!(&frame.payload[0..4], &[1, 2, 3, 4]);        // ip
        assert_eq!(&frame.payload[4..6], &[0x36, 0x12]);        // 4662 LE
        assert_eq!(&frame.payload[6..8], &[0x40, 0x12]);        // 4672 LE
        assert_eq!(&frame.payload[8..24], &hash);              // user hash
        assert_eq!(frame.payload[24], 0);                      // role
    }

    #[test]
    fn fail_when_target_not_connected() {
        let state = ServerState::for_test();
        let req_hash = [1u8; 16];
        // Register the requester so send_fail can reach it.
        state.register_test_client(req_hash, 100, false, 0);
        let reason = handle_holepunch_request(
            &state, &req_hash, 100,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 4662, 4672,
            /*target_id*/ 999, // not connected
        );
        assert_eq!(reason, Some(FAIL_TARGET_NOT_CONNECTED));
    }

    #[test]
    fn fail_when_target_has_no_udp_port() {
        let state = ServerState::for_test();
        let req = [1u8; 16];
        let tgt = [2u8; 16];
        state.register_test_client(req, 100, false, 4672);
        state.register_test_client(tgt, 200, false, 0); // LowID, no UDP announced
        let reason = handle_holepunch_request(
            &state, &req, 100,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 4662, 4672, 200,
        );
        assert_eq!(reason, Some(FAIL_TARGET_NO_UDP));
    }

    #[test]
    fn coordinates_two_lowid_clients() {
        let state = ServerState::for_test();
        let req = [1u8; 16];
        let tgt = [2u8; 16];
        state.register_test_client(req, 100, false, 4672);
        state.register_test_client(tgt, 200, false, 5672); // target announced UDP
        let reason = handle_holepunch_request(
            &state, &req, 100,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 4662, 4672, 200,
        );
        assert_eq!(reason, None, "should coordinate successfully");
    }

    #[test]
    fn target_udp_known_from_login_no_prior_request() {
        // The improvement: target announced its UDP port at LOGIN (register_test
        // _client with udp != 0 mimics CT_EMULE_UDPPORTS), so a brand-new
        // requester can reach it WITHOUT the target having sent any REQUEST first.
        let state = ServerState::for_test();
        let req = [1u8; 16];
        let tgt = [2u8; 16];
        // Requester hasn't announced udp via login (0) but supplies it in the
        // request; target announced 5672 at login.
        state.register_test_client(req, 100, false, 0);
        state.register_test_client(tgt, 200, false, 5672);
        let reason = handle_holepunch_request(
            &state, &req, 100,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 4662, 4672, 200,
        );
        assert_eq!(reason, None, "target reachable via login-announced UDP port");
    }

    #[test]
    fn observed_udp_port_prefers_fresh_observation() {
        let state = ServerState::for_test();
        let ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        // No observation yet → falls back to announced.
        assert_eq!(observed_udp_port(&state, ip, 4672), 4672);
        // Record a fresh external port → it wins over the announced one.
        state.observed_udp_ports.insert(Ipv4Addr::new(9, 9, 9, 9), (51000, std::time::Instant::now()));
        assert_eq!(observed_udp_port(&state, ip, 4672), 51000);
    }

    #[test]
    fn observed_udp_port_ignores_stale_and_zero() {
        let state = ServerState::for_test();
        let ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 10));
        // Stale observation (older than the freshness window) → fall back.
        let stale = std::time::Instant::now()
            .checked_sub(OBSERVED_UDP_FRESH + Duration::from_secs(1))
            .unwrap_or_else(std::time::Instant::now);
        state.observed_udp_ports.insert(Ipv4Addr::new(9, 9, 9, 10), (51000, stale));
        assert_eq!(observed_udp_port(&state, ip, 4672), 4672);
        // A zero observed port is meaningless → fall back.
        state.observed_udp_ports.insert(Ipv4Addr::new(9, 9, 9, 10), (0, std::time::Instant::now()));
        assert_eq!(observed_udp_port(&state, ip, 4672), 4672);
    }
}

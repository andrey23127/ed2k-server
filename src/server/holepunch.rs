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
//!
//! EXTENSION (issue #39, flag 0x100000). Today's punch relies on the standing
//! 0x9F keepalives for the ports it hands out. When the server offers the
//! extension and BOTH peers announced it at login (0x100000 with 0x1000 in
//! `CT_SERVER_FLAGS`), a 0x60 goes like this instead:
//!   1. the requester sends a 0x9F and the 0x60, in either order;
//!   2. the target is woken with Lugdunum's 0x37, byte-identical, carrying the
//!      requester's best port so far;
//!   3. the target sends 0x9F (0, 0.5 and 1 s) and starts punching;
//!   4. on the target's first 0x9F the server sends 0x61 to both (30 bytes:
//!      the peer's crypt setting appended), then resends at +1.2 s and +3 s;
//!   5. with no 0x9F within 3 s, it sends the same 0x61 with the ports it
//!      would have used anyway. A lost 0x9F costs 3 s, never the punch.
//! Any other pair gets exactly today's punch: 29 bytes, at once, no 0x37.
//!
//! BRIDGE (issue #39). A client that implements only Lugdunum's callback
//! (NeoMule's "CanLow2Low") ignores 0x61. A 0x60 whose target set 0x1000,
//! did not announce the extension and has sent no 0x9F in its session also
//! sends that target a 0x37, so it can dial the requester. Having sent a
//! 0x9F proves a client understands 0x61.

use crate::proto::{opcodes::*, Frame};
use crate::server::lugdunum_natt::{self, SRVCAP_NATTRAVERSAL};
use crate::state::{ClientHandle, ServerState};
use bytes::{BufMut, BytesMut};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
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

/// The UDP port to hand a peer for the client `user_hash` at `ip` (issue #37).
/// In order:
///  1. the source port of the client's own last 0x9F keepalive, if fresh: it
///     is per client, so two clients behind one public IP each get theirs;
///  2. the last UDP port seen from `ip` (keepalives and global queries), only
///     when no other client is connected from that address, since it is
///     shared by every client there;
///  3. the port the client announced (0xF9 at login, or in its 0x60).
fn observed_udp_port(state: &ServerState, user_hash: &[u8; 16], ip: IpAddr, announced: u16) -> u16 {
    if let Some(e) = state.natt_udp_ports.get(user_hash) {
        let (port, seen) = *e;
        if port != 0 && seen.elapsed() < OBSERVED_UDP_FRESH {
            return port;
        }
    }
    if let IpAddr::V4(v4) = ip {
        let alone = state.conn_per_ip.get(&ip).map_or(true, |n| *n <= 1);
        if alone {
            if let Some(entry) = state.observed_udp_ports.get(&v4) {
                let (port, seen) = *entry;
                if port != 0 && seen.elapsed() < OBSERVED_UDP_FRESH {
                    return port;
                }
            }
        }
    }
    announced
}

/// Length of an OP_LOWID_HOLEPUNCH_INFO payload (25 before the peer id).
pub const INFO_LEN: usize = 4 + 2 + 2 + 16 + 1 + 4;
/// The same with the peer's crypt setting, for a pair using the extension.
pub const INFO_EXT_LEN: usize = INFO_LEN + 1;

/// How long an extension coordination waits for the target's 0x9F.
pub const EXT_WAIT: Duration = Duration::from_secs(3);

/// The server offers the extension: it is on, and so is Lugdunum's callback,
/// whose 0x37 wakes the target.
pub fn extension_enabled(cfg: &crate::config::Config) -> bool {
    cfg.network.holepunch_extension && cfg.network.lugdunum_natt
}

/// A client with these login flags uses the extension here.
pub fn has_extension(state: &ServerState, server_flags: u32) -> bool {
    const BOTH: u32 = SRVFLG_HOLEPUNCH_EXT | SRVCAP_NATTRAVERSAL;
    extension_enabled(&state.live_cfg.load()) && server_flags & BOTH == BOTH
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
    // server already knows how to reach it. Cheap single-shard update. This is
    // the announced port, the last resort of `observed_udp_port`: the port of
    // a fresh keepalive still wins over it (issue #37).
    if requester_udp_port != 0 {
        if let Some(mut me) = state.clients.get_mut(requester_user_hash) {
            me.udp_port = requester_udp_port;
        }
    }

    // A client asking to punch to itself is a no-op/bug.
    if target_id == requester_id {
        send_fail(state, requester_user_hash, target_id, FAIL_BAD_REQUEST);
        return Some(FAIL_BAD_REQUEST);
    }

    // Look up the target by assigned server ID — O(1) through the id index
    // rather than a walk over every connected client. We copy out the few fields
    // we need and DROP the guard immediately: holding a `clients` guard while
    // calling state.clients.get(requester) below could deadlock if the two keys
    // land on the same shard. So extract-then-drop.
    let target_data = state.client_by_assigned_id(target_id).map(|t| {
        (
            t.ip,
            t.port,
            t.udp_port,
            t.user_hash,
            t.is_high_id,
            t.is_alive(),
            t.server_flags,
        )
    });

    let Some((t_ip, t_tcp, t_udp, t_hash, t_high, t_alive, t_flags)) = target_data else {
        debug!(requester_id, target_id, "holepunch: target not connected");
        send_fail(
            state,
            requester_user_hash,
            target_id,
            FAIL_TARGET_NOT_CONNECTED,
        );
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
        debug!(
            requester_id,
            target_id, "holepunch: target session dead (channel closed), refusing"
        );
        send_fail(
            state,
            requester_user_hash,
            target_id,
            FAIL_TARGET_NOT_CONNECTED,
        );
        *state
            .block_stats
            .entry("holepunch_target_dead".to_string())
            .or_insert(0) += 1;
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
        debug!(
            target_id,
            "holepunch: target has no known UDP port (stock client?)"
        );
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
    let t_udp_eff = observed_udp_port(state, &t_hash, t_ip, t_udp);
    let requester_udp_eff =
        observed_udp_port(state, requester_user_hash, requester_ip, requester_udp_port);

    // A pair using the extension also gets each other's crypt setting
    // (issue #39); everyone else keeps the 29 bytes.
    let r_flags = state
        .clients
        .get(requester_user_hash)
        .map_or(0, |c| c.server_flags);
    let ext = has_extension(state, r_flags) && has_extension(state, t_flags);
    let (crypt_of_target, crypt_of_requester) = if ext {
        (
            Some(lugdunum_natt::crypt_setting(t_flags)),
            Some(lugdunum_natt::crypt_setting(r_flags)),
        )
    } else {
        (None, None)
    };

    // Each side also gets the server ID of the peer described (issue #38):
    // the requester its 0x60 target id, so it can tell which of several
    // requests in flight this answers; the target the requester's id.
    let to_requester = build_info(
        t_ip,
        t_tcp,
        t_udp_eff,
        &t_hash,
        if requester_is_initiator { 0 } else { 1 },
        target_id,
        crypt_of_target,
    );
    let to_target = build_info(
        requester_ip,
        requester_tcp_port,
        requester_udp_eff,
        requester_user_hash,
        if requester_is_initiator { 1 } else { 0 },
        requester_id,
        crypt_of_requester,
    );

    // Both lookups below take fresh short-lived guards (the earlier target guard
    // was already dropped above), so there is no cross-shard deadlock.
    //
    // Resolve by user hash, not by id: the id was already resolved once at the
    // top of this function, and re-resolving could pick up a DIFFERENT client if
    // a reconnect claimed the id in between — HighID ids are IPv4 addresses and
    // are not unique over time. The hash identifies the client we actually
    // validated, so the frame cannot be delivered to a stranger.
    use crate::admission::PushKind::Holepunch;
    if let Some(target) = state.clients.get(&t_hash) {
        state
            .admission
            .push
            .note(Holepunch, target.send_frame(to_target));
    }
    if let Some(me) = state.clients.get(requester_user_hash) {
        state
            .admission
            .push
            .note(Holepunch, me.send_frame(to_requester));
    }

    debug!(
        requester_id, requester_ip = %requester_ip,
        target_id, target_ip = %t_ip,
        "holepunch coordinated (INFO sent to both sides)"
    );
    *state
        .block_stats
        .entry("holepunch_coordinated".to_string())
        .or_insert(0) += 1;
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
    // admission (issue #25): at most one pending retry per (requester,
    // target) pair, and at most `max_retry_tasks` in all. Retrying is optional
    // help — the immediate coordination already happened — so a refusal just
    // skips it.
    let guards = match state.admission.try_retry(requester_user_hash, target_id) {
        Ok(g) => g,
        Err(why) => {
            debug!(?why, target_id, "holepunch retry skipped");
            return;
        }
    };
    tokio::spawn(async move {
        let _guards = guards;
        retry_loop(
            &state,
            requester_user_hash,
            requester_id,
            requester_ip,
            requester_tcp_port,
            requester_udp_port,
            target_id,
        )
        .await;
    });
}

/// The resends: two extra attempts at +1.2s and +3.0s after a coordination
/// that has just been done. Small and short so a genuinely unreachable pair
/// still fails fast.
async fn retry_loop(
    state: &ServerState,
    requester_user_hash: [u8; 16],
    requester_id: u32,
    requester_ip: IpAddr,
    requester_tcp_port: u16,
    requester_udp_port: u16,
    target_id: u32,
) {
    const DELAYS_MS: [u64; 2] = [1200, 3000];
    let mut elapsed = 0u64;
    for &at in DELAYS_MS.iter() {
        tokio::time::sleep(Duration::from_millis(at - elapsed)).await;
        elapsed = at;
        // Stop early if the requester has disconnected; no point re-coordinating.
        if !requester_alive(state, &requester_user_hash) {
            break;
        }
        let _ = handle_holepunch_request(
            state,
            &requester_user_hash,
            requester_id,
            requester_ip,
            requester_tcp_port,
            requester_udp_port,
            target_id,
        );
    }
}

fn requester_alive(state: &ServerState, user_hash: &[u8; 16]) -> bool {
    state
        .clients
        .get(user_hash)
        .map(|c| c.is_alive())
        .unwrap_or(false)
}

fn count(state: &ServerState, key: &str) {
    *state.block_stats.entry(key.to_string()).or_insert(0) += 1;
}

/// The whole handling of an OP_LOWID_HOLEPUNCH_REQUEST: the extension when
/// both peers use it, otherwise today's punch with its resends, plus the
/// bridge to a Lugdunum-only target.
#[allow(clippy::too_many_arguments)]
pub fn request(
    state: &Arc<ServerState>,
    requester_user_hash: [u8; 16],
    requester_id: u32,
    requester_ip: IpAddr,
    requester_tcp_port: u16,
    requester_udp_port: u16,
    target_id: u32,
) {
    // A target the punch can be coordinated with at all; the checks and
    // their FAIL answers stay in `handle_holepunch_request`.
    let target = state
        .client_by_assigned_id(target_id)
        .filter(|t| t.user_hash != requester_user_hash && !t.is_high_id && t.is_alive());
    if let Some(t) = &target {
        let r_flags = state
            .clients
            .get(&requester_user_hash)
            .map_or(0, |c| c.server_flags);
        if has_extension(state, r_flags) && has_extension(state, t.server_flags) {
            if requester_udp_port != 0 {
                if let Some(mut me) = state.clients.get_mut(&requester_user_hash) {
                    me.udp_port = requester_udp_port;
                }
            }
            match start_extension(
                state,
                requester_user_hash,
                requester_id,
                requester_ip,
                requester_tcp_port,
                requester_udp_port,
                t,
            ) {
                Ext::Started | Ext::Pending => return,
                Ext::Fallback => {}
            }
        }
    }
    handle_holepunch_request(
        state,
        &requester_user_hash,
        requester_id,
        requester_ip,
        requester_tcp_port,
        requester_udp_port,
        target_id,
    );
    if let Some(t) = &target {
        bridge(state, &requester_user_hash, requester_ip, t);
    }
    schedule_info_retries(
        Arc::clone(state),
        requester_user_hash,
        requester_id,
        requester_ip,
        requester_tcp_port,
        requester_udp_port,
        target_id,
    );
}

#[derive(Debug, PartialEq, Eq)]
enum Ext {
    /// The target was woken; 0x61 follows from the background task.
    Started,
    /// One is already running for this pair: this 0x60 adds nothing.
    Pending,
    /// Do today's punch instead.
    Fallback,
}

/// The requester's 0x37 body for the target, with the best port the server
/// has for the requester now. None when the crypt settings rule it out.
fn wake_body(state: &ServerState, requester_user_hash: &[u8; 16], requester_ip: IpAddr, target_flags: u32) -> Option<Vec<u8>> {
    let req = state.clients.get(requester_user_hash).map(|c| c.clone())?;
    let port = observed_udp_port(state, requester_user_hash, requester_ip, req.udp_port);
    lugdunum_natt::forward_body(&req, SocketAddr::new(requester_ip, port), target_flags)
}

#[allow(clippy::too_many_arguments)]
fn start_extension(
    state: &Arc<ServerState>,
    requester_user_hash: [u8; 16],
    requester_id: u32,
    requester_ip: IpAddr,
    requester_tcp_port: u16,
    requester_udp_port: u16,
    target: &ClientHandle,
) -> Ext {
    // Crypt settings that rule out the 0x37 rule out nothing in 0x61: such a
    // pair gets today's punch.
    let Some(body) = wake_body(state, &requester_user_hash, requester_ip, target.server_flags) else {
        return Ext::Fallback;
    };
    let target_id = target.assigned_id;
    let guards = match state.admission.try_retry(requester_user_hash, target_id) {
        Ok(g) => g,
        Err(crate::admission::RetrySkip::Coalesced) => return Ext::Pending,
        Err(crate::admission::RetrySkip::Busy) => return Ext::Fallback,
    };
    // Listen before waking the target, so its 0x9F cannot slip past.
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .natt_keepalive_waiters
        .entry(target.user_hash)
        .or_default()
        .push(tx);
    let outcome = target.send_frame(Frame::new(lugdunum_natt::OP_NAT_CALLBACK_TCP, body));
    state
        .admission
        .push
        .note(crate::admission::PushKind::Holepunch, outcome);
    count(state, "holepunch_ext_started");
    let state = Arc::clone(state);
    tokio::spawn(async move {
        let _guards = guards;
        let fresh = matches!(tokio::time::timeout(EXT_WAIT, rx).await, Ok(Ok(())));
        count(&state, if fresh { "holepunch_ext_fresh" } else { "holepunch_ext_timeout" });
        if !requester_alive(&state, &requester_user_hash) {
            return;
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
        retry_loop(
            &state,
            requester_user_hash,
            requester_id,
            requester_ip,
            requester_tcp_port,
            requester_udp_port,
            target_id,
        )
        .await;
    });
    Ext::Started
}

/// A 0x9F from `user_hash`'s own address was accepted: release the
/// extension coordinations waiting for it.
pub fn keepalive_arrived(state: &ServerState, user_hash: &[u8; 16]) {
    if let Some((_, waiters)) = state.natt_keepalive_waiters.remove(user_hash) {
        for w in waiters {
            let _ = w.send(());
        }
    }
}

/// Lugdunum's 0x37 for a target that cannot read 0x61: it set 0x1000, did
/// not announce the extension, and has sent no 0x9F in this session.
fn bridge(state: &ServerState, requester_user_hash: &[u8; 16], requester_ip: IpAddr, target: &ClientHandle) {
    if !state.live_cfg.load().network.lugdunum_natt
        || target.server_flags & SRVCAP_NATTRAVERSAL == 0
        || has_extension(state, target.server_flags)
        || state.natt_keepalive_seen.contains_key(&target.user_hash)
    {
        return;
    }
    let Some(body) = wake_body(state, requester_user_hash, requester_ip, target.server_flags) else {
        count(state, "holepunch_bridge_crypt_mismatch");
        return;
    };
    let outcome = target.send_frame(Frame::new(lugdunum_natt::OP_NAT_CALLBACK_TCP, body));
    state
        .admission
        .push
        .note(crate::admission::PushKind::Holepunch, outcome);
    count(state, "holepunch_bridged");
}

/// OP_LOWID_HOLEPUNCH_INFO payload, 29 bytes:
///   peer_ip(4 LE) + peer_tcp_port(2 LE) + peer_udp_port(2 LE)
///   + peer_user_hash(16) + role(1) + peer_id(4 LE)
/// `peer_id` (issue #38) is the server ID of the peer described; a client
/// reads it only from a payload of 29 bytes or more (it was 25 before).
/// For a pair using the extension, 30: + peer_crypt(1), the peer's
/// `(CT_SERVER_FLAGS >> 9) & 7` (support, request, require), as in 0x37.
fn build_info(
    ip: IpAddr,
    tcp_port: u16,
    udp_port: u16,
    user_hash: &[u8; 16],
    role: u8,
    peer_id: u32,
    peer_crypt: Option<u8>,
) -> Frame {
    let mut p = BytesMut::with_capacity(INFO_EXT_LEN);
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
    p.put_u32_le(peer_id);
    if let Some(c) = peer_crypt {
        p.put_u8(c);
    }
    Frame::new(OP_LOWID_HOLEPUNCH_INFO, p.to_vec())
}

/// Send OP_LOWID_HOLEPUNCH_FAIL(target_id, reason) to the requester.
fn send_fail(state: &ServerState, requester_user_hash: &[u8; 16], target_id: u32, reason: u8) {
    let mut p = BytesMut::with_capacity(5);
    p.put_u32_le(target_id);
    p.put_u8(reason);
    if let Some(me) = state.clients.get(requester_user_hash) {
        let outcome = me.send_frame(Frame::new(OP_LOWID_HOLEPUNCH_FAIL, p.to_vec()));
        state
            .admission
            .push
            .note(crate::admission::PushKind::Holepunch, outcome);
    } else {
        warn!(
            target_id,
            reason, "holepunch fail: requester vanished before reply"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const EXT: u32 = SRVFLG_HOLEPUNCH_EXT | SRVCAP_NATTRAVERSAL;

    /// A LowID at its own address with these login flags.
    fn peer(
        s: &ServerState,
        hash: u8,
        id: u32,
        last_octet: u8,
        flags: u32,
    ) -> tokio::sync::mpsc::Receiver<Frame> {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet));
        let rx = s.register_test_client_at([hash; 16], id, false, 4672, ip);
        s.clients.get_mut(&[hash; 16]).unwrap().server_flags = flags;
        rx
    }

    fn ask(s: &Arc<ServerState>, from: u8, from_id: u32, last_octet: u8, target_id: u32) {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet));
        request(s, [from; 16], from_id, ip, 4662, 4672, target_id);
    }

    fn drain(rx: &mut tokio::sync::mpsc::Receiver<Frame>) -> Vec<Frame> {
        std::iter::from_fn(|| rx.try_recv().ok()).collect()
    }

    fn opcodes(frames: &[Frame]) -> Vec<(u8, usize)> {
        frames.iter().map(|f| (f.opcode, f.payload.len())).collect()
    }

    async fn settle(ms: u64) {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    /// Issue #39, the extension: 0x37 wakes the target, nothing else goes out
    /// until its 0x9F, then 0x61 (30 bytes) with that fresh port.
    #[tokio::test]
    async fn an_extension_pair_waits_for_the_targets_keepalive() {
        let s = Arc::new(ServerState::for_test());
        let mut a = peer(&s, 0xA, 11, 1, EXT | 0x200);
        let mut b = peer(&s, 0xB, 13, 2, EXT | 0x600);
        ask(&s, 0xA, 11, 1, 13);
        settle(50).await;
        assert!(drain(&mut a).is_empty(), "the requester waits");
        let woke = drain(&mut b);
        assert_eq!(opcodes(&woke), vec![(0x37, 27)]);
        // B's fresh port, as the 0x9F handler records it.
        s.natt_udp_ports.insert([0xB; 16], (50000, std::time::Instant::now()));
        s.natt_keepalive_seen.insert([0xB; 16], true);
        keepalive_arrived(&s, &[0xB; 16]);
        settle(50).await;
        let to_a = drain(&mut a);
        assert_eq!(opcodes(&to_a), vec![(OP_LOWID_HOLEPUNCH_INFO, 30)]);
        assert_eq!(&to_a[0].payload[6..8], &50000u16.to_le_bytes());
        assert_eq!(to_a[0].payload[29], 0x03, "B supports and requests");
        let to_b = drain(&mut b);
        assert_eq!(opcodes(&to_b), vec![(OP_LOWID_HOLEPUNCH_INFO, 30)]);
        assert_eq!(to_b[0].payload[29], 0x01, "A supports");
        assert_eq!(s.block_stats.get("holepunch_ext_fresh").map(|v| *v), Some(1));
    }

    /// A lost 0x9F costs the wait, never the punch.
    #[tokio::test]
    async fn without_the_keepalive_the_punch_goes_ahead_after_the_wait() {
        let s = Arc::new(ServerState::for_test());
        let mut a = peer(&s, 0xA, 11, 1, EXT);
        let mut b = peer(&s, 0xB, 13, 2, EXT);
        ask(&s, 0xA, 11, 1, 13);
        ask(&s, 0xA, 11, 1, 13); // coalesced: no second 0x37
        settle(100).await;
        assert_eq!(opcodes(&drain(&mut b)), vec![(0x37, 11)]);
        assert!(drain(&mut a).is_empty());
        tokio::time::sleep(EXT_WAIT).await;
        settle(100).await;
        let to_a = drain(&mut a);
        assert_eq!(opcodes(&to_a), vec![(OP_LOWID_HOLEPUNCH_INFO, 30)]);
        assert_eq!(&to_a[0].payload[6..8], &4672u16.to_le_bytes(), "today's port");
        assert_eq!(opcodes(&drain(&mut b)), vec![(OP_LOWID_HOLEPUNCH_INFO, 30)]);
    }

    /// Mixed pairs and legacy pairs: today's 29-byte 0x61 at once, no 0x37,
    /// whichever side has the extension.
    #[tokio::test]
    async fn a_pair_without_the_extension_on_both_sides_is_unchanged() {
        for (fa, fb) in [(EXT, SRVCAP_NATTRAVERSAL), (SRVCAP_NATTRAVERSAL, EXT), (0, 0), (EXT, 0)] {
            let s = Arc::new(ServerState::for_test());
            let mut a = peer(&s, 0xA, 11, 1, fa);
            let mut b = peer(&s, 0xB, 13, 2, fb);
            // B has proven it reads 0x61, so no bridge either.
            s.natt_keepalive_seen.insert([0xB; 16], false);
            ask(&s, 0xA, 11, 1, 13);
            assert_eq!(opcodes(&drain(&mut a)), vec![(OP_LOWID_HOLEPUNCH_INFO, 29)], "{fa:#x} {fb:#x}");
            assert_eq!(opcodes(&drain(&mut b)), vec![(OP_LOWID_HOLEPUNCH_INFO, 29)], "{fa:#x} {fb:#x}");
        }
    }

    /// The extension off: an extension pair is a legacy pair.
    #[tokio::test]
    async fn with_the_extension_off_nothing_changes() {
        let s = Arc::new(ServerState::for_test());
        let mut cfg = (**s.live_cfg.load()).clone();
        cfg.network.holepunch_extension = false;
        s.live_cfg.store(Arc::new(cfg));
        let mut a = peer(&s, 0xA, 11, 1, EXT);
        let mut b = peer(&s, 0xB, 13, 2, EXT);
        s.natt_keepalive_seen.insert([0xB; 16], false);
        ask(&s, 0xA, 11, 1, 13);
        assert_eq!(opcodes(&drain(&mut a)), vec![(OP_LOWID_HOLEPUNCH_INFO, 29)]);
        assert_eq!(opcodes(&drain(&mut b)), vec![(OP_LOWID_HOLEPUNCH_INFO, 29)]);
    }

    /// The bridge: a target that set 0x1000 and never sent a 0x9F also gets
    /// Lugdunum's 0x37; the requester's side is today's.
    #[tokio::test]
    async fn a_lugdunum_only_target_is_bridged() {
        for requester_flags in [0, SRVCAP_NATTRAVERSAL, EXT] {
            let s = Arc::new(ServerState::for_test());
            let mut a = peer(&s, 0xA, 11, 1, requester_flags);
            let mut b = peer(&s, 0xB, 13, 2, SRVCAP_NATTRAVERSAL);
            ask(&s, 0xA, 11, 1, 13);
            assert_eq!(opcodes(&drain(&mut a)), vec![(OP_LOWID_HOLEPUNCH_INFO, 29)]);
            let to_b = drain(&mut b);
            assert_eq!(opcodes(&to_b), vec![(OP_LOWID_HOLEPUNCH_INFO, 29), (0x37, 11)]);
            // ip, the requester's port, its id, crypt 0.
            assert_eq!(to_b[1].payload, vec![10, 0, 0, 1, 0x40, 0x12, 11, 0, 0, 0, 0]);
        }
        // Not to a stock client, nor with the callback off.
        let s = Arc::new(ServerState::for_test());
        let _a = peer(&s, 0xA, 11, 1, 0);
        let mut b = peer(&s, 0xB, 13, 2, 0);
        ask(&s, 0xA, 11, 1, 13);
        assert_eq!(opcodes(&drain(&mut b)), vec![(OP_LOWID_HOLEPUNCH_INFO, 29)]);
        let s = Arc::new(ServerState::for_test());
        let mut cfg = (**s.live_cfg.load()).clone();
        cfg.network.lugdunum_natt = false;
        s.live_cfg.store(Arc::new(cfg));
        let _a = peer(&s, 0xA, 11, 1, 0);
        let mut b = peer(&s, 0xB, 13, 2, SRVCAP_NATTRAVERSAL);
        ask(&s, 0xA, 11, 1, 13);
        assert_eq!(opcodes(&drain(&mut b)), vec![(OP_LOWID_HOLEPUNCH_INFO, 29)]);
    }

    /// A bridged target without a UDP port still gets the 0x37: it dials
    /// the requester, and needs no port of its own for that.
    #[tokio::test]
    async fn the_bridge_does_not_need_the_targets_port() {
        let s = Arc::new(ServerState::for_test());
        let mut a = peer(&s, 0xA, 11, 1, 0);
        let mut b = peer(&s, 0xB, 13, 2, SRVCAP_NATTRAVERSAL);
        s.clients.get_mut(&[0xB; 16]).unwrap().udp_port = 0;
        ask(&s, 0xA, 11, 1, 13);
        assert_eq!(opcodes(&drain(&mut a)), vec![(OP_LOWID_HOLEPUNCH_FAIL, 5)]);
        assert_eq!(opcodes(&drain(&mut b)), vec![(0x37, 11)]);
    }

    #[test]
    fn info_payload_format() {
        let hash = [7u8; 16];
        let frame = build_info(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 4662, 4672, &hash, 0, 0x0102_0304, None);
        assert_eq!(frame.opcode, OP_LOWID_HOLEPUNCH_INFO);
        assert_eq!(frame.payload.len(), 29);
        assert_eq!(&frame.payload[0..4], &[1, 2, 3, 4]); // ip
        assert_eq!(&frame.payload[4..6], &[0x36, 0x12]); // 4662 LE
        assert_eq!(&frame.payload[6..8], &[0x40, 0x12]); // 4672 LE
        assert_eq!(&frame.payload[8..24], &hash); // user hash
        assert_eq!(frame.payload[24], 0); // role
        assert_eq!(&frame.payload[25..29], &[4, 3, 2, 1]); // peer id LE
    }

    fn info_of(rx: &mut tokio::sync::mpsc::Receiver<Frame>) -> (u16, u16, [u8; 16], u32) {
        let f = rx.try_recv().expect("an INFO frame");
        assert_eq!(f.opcode, OP_LOWID_HOLEPUNCH_INFO);
        let p = &f.payload;
        let tcp = u16::from_le_bytes([p[4], p[5]]);
        let udp = u16::from_le_bytes([p[6], p[7]]);
        let hash: [u8; 16] = p[8..24].try_into().unwrap();
        let id = u32::from_le_bytes(p[25..29].try_into().unwrap());
        (tcp, udp, hash, id)
    }

    /// Issue #37, as reported: two LowID clients behind one public IP, each
    /// with its own keepalive port. Each must get the other's port, whatever
    /// UDP packet came last from that IP, and B's 0x60 port (its local one)
    /// must not replace B's keepalive port.
    #[test]
    fn two_clients_behind_one_ip_each_get_the_others_port() {
        let state = ServerState::for_test();
        let ip = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        let (a, b) = ([0xAA; 16], [0xBB; 16]);
        let mut rx_a = state.register_test_client_at(a, 100, false, 24825, ip);
        let mut rx_b = state.register_test_client_at(b, 200, false, 24835, ip);
        state.conn_per_ip.insert(ip, 2);
        let now = std::time::Instant::now();
        // Keepalives as the NAT mapped them, then a global query from A's
        // other socket (aMule: TCP + 3) last of all.
        state.natt_udp_ports.insert(a, (40001, now));
        state.natt_udp_ports.insert(b, (40002, now));
        state.observed_udp_ports.insert(Ipv4Addr::new(5, 6, 7, 8), (40099, now));

        // B asks for A; its 0x60 carries its local port.
        let r = handle_holepunch_request(&state, &b, 200, ip, 24830, 24835, 100);
        assert_eq!(r, None);
        let (_, udp, hash, id) = info_of(&mut rx_b);
        assert_eq!((udp, hash, id), (40001, a, 100), "B is told A's port and id");
        let (tcp, udp, hash, id) = info_of(&mut rx_a);
        assert_eq!((tcp, udp, hash, id), (24830, 40002, b, 200), "A is told B's port and id");
    }

    #[test]
    fn the_per_ip_port_is_used_only_for_a_client_alone_on_its_ip() {
        let state = ServerState::for_test();
        let ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 11));
        let h = [3u8; 16];
        state
            .observed_udp_ports
            .insert(Ipv4Addr::new(9, 9, 9, 11), (51000, std::time::Instant::now()));
        state.conn_per_ip.insert(ip, 1);
        assert_eq!(observed_udp_port(&state, &h, ip, 4672), 51000);
        state.conn_per_ip.insert(ip, 2);
        assert_eq!(observed_udp_port(&state, &h, ip, 4672), 4672);
        // The client's own keepalive port wins either way.
        state.natt_udp_ports.insert(h, (52000, std::time::Instant::now()));
        assert_eq!(observed_udp_port(&state, &h, ip, 4672), 52000);
    }

    #[test]
    fn fail_when_target_not_connected() {
        let state = ServerState::for_test();
        let req_hash = [1u8; 16];
        // Register the requester so send_fail can reach it.
        state.register_test_client(req_hash, 100, false, 0);
        let reason = handle_holepunch_request(
            &state,
            &req_hash,
            100,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            4662,
            4672,
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
            &state,
            &req,
            100,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            4662,
            4672,
            200,
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
            &state,
            &req,
            100,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            4662,
            4672,
            200,
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
            &state,
            &req,
            100,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            4662,
            4672,
            200,
        );
        assert_eq!(
            reason, None,
            "target reachable via login-announced UDP port"
        );
    }

    #[test]
    fn observed_udp_port_prefers_fresh_observation() {
        let state = ServerState::for_test();
        let ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        // No observation yet → falls back to announced.
        assert_eq!(observed_udp_port(&state, &[0u8; 16], ip, 4672), 4672);
        // Record a fresh external port → it wins over the announced one.
        state.observed_udp_ports.insert(
            Ipv4Addr::new(9, 9, 9, 9),
            (51000, std::time::Instant::now()),
        );
        assert_eq!(observed_udp_port(&state, &[0u8; 16], ip, 4672), 51000);
    }

    #[test]
    fn observed_udp_port_ignores_stale_and_zero() {
        let state = ServerState::for_test();
        let ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 10));
        // Stale observation (older than the freshness window) → fall back.
        let stale = std::time::Instant::now()
            .checked_sub(OBSERVED_UDP_FRESH + Duration::from_secs(1))
            .unwrap_or_else(std::time::Instant::now);
        state
            .observed_udp_ports
            .insert(Ipv4Addr::new(9, 9, 9, 10), (51000, stale));
        assert_eq!(observed_udp_port(&state, &[0u8; 16], ip, 4672), 4672);
        // A zero observed port is meaningless → fall back.
        state
            .observed_udp_ports
            .insert(Ipv4Addr::new(9, 9, 9, 10), (0, std::time::Instant::now()));
        assert_eq!(observed_udp_port(&state, &[0u8; 16], ip, 4672), 4672);
    }
}

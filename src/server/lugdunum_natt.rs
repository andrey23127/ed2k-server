//! Lugdunum's NAT callback, as the original eserver 17.x runs it (issue #39).
//!
//! Two server-coordinated NAT-T schemes exist. This server's own (0x60-0x62,
//! `server::holepunch`) and Lugdunum's, below. aMule and emule-qt speak both;
//! with this module a client written for Lugdunum works here unchanged. The
//! two share nothing on the wire and run side by side.
//!
//! Read from Lugdunum's `nat_callback()` and its login code:
//!
//! - **Capability.** The client sets 0x1000 (SRVCAP_NATTRAVERSAL) in
//!   `CT_SERVER_FLAGS`. It gets an odd LowID, and `OP_IDCHANGE` with four
//!   more bytes: the client's TCP port as the server sees it (the source port
//!   of its connection for a LowID, its own port for a HighID). The server
//!   sets 0x1000 in its `OP_IDCHANGE` TCP flags.
//! - **Request**, UDP `0xA6`, server-key obfuscated only:
//!   `<target_id 4><requester_id 4>`. Both must be logged-in LowIDs, and the
//!   requester must send from the address of its TCP session. The source port
//!   of this datagram is the requester's UDP endpoint as the server sees it.
//! - **Forward to the target**:
//!   `<requester_ip 4><requester_udp_port 2><requester_id 4><crypt 1>`, plus
//!   the requester's user hash (16) with bit 0x80 in `crypt` when both sides
//!   support the crypt layer and one of them asks for it. `crypt` is the
//!   requester's `(CT_SERVER_FLAGS >> 9) & 7` (support, request, require). If
//!   one side requires the crypt layer and they cannot both use it, nothing
//!   is sent. It goes out as UDP `0xA7` to the target's own endpoint when the
//!   target itself sent `0xA6` less than 20 s ago (its NAT mapping to us is
//!   fresh), else as TCP `0x37` on its server connection.
//! - **The requester gets nothing back.** The target punches towards the
//!   requester's endpoint; aMule also sends the reverse `0xA6` a few seconds
//!   later, which brings the target's endpoint to the requester the same way.
//!
//! Two things here are stricter than Lugdunum, and neither costs a client
//! that speaks the protocol anything:
//! - The target must have set 0x1000 at login. Lugdunum forwards to any
//!   LowID, so a stock client got an opcode it does not know.
//! - Requests are rate limited per requester (a burst of 10, then one a
//!   second); aMule itself sends at most 20 a minute per server.

use crate::proto::Frame;
use crate::state::{ClientHandle, ServerState};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Client capability in `CT_SERVER_FLAGS`, and this server's flag in the
/// `OP_IDCHANGE` TCP flags: Lugdunum's NAT callback. (Not IPv6: some clients
/// once sent this bit for that; this server keys IPv6 on `CT_MOD_IP_V6`.)
pub const SRVCAP_NATTRAVERSAL: u32 = 0x1000;
/// Client to server, UDP: the request.
pub const OP_NAT_CALLBACK_REQUEST: u8 = 0xA6;
/// Server to target, UDP: the forward, when the target's endpoint is fresh.
pub const OP_NAT_CALLBACK_UDP: u8 = 0xA7;
/// Server to target, TCP: the forward otherwise.
pub const OP_NAT_CALLBACK_TCP: u8 = 0x37;

/// Lugdunum answers by UDP only when the target sent `0xA6` within this long
/// (its test is "more than 19 s ago: use TCP").
const UDP_FRESH: Duration = Duration::from_secs(20);
/// How long a requester's endpoint is kept, for the sweep.
pub const SEEN_TTL: Duration = Duration::from_secs(120);

/// A client's last `0xA6`: where it came from, how to answer it, and its
/// request allowance.
pub struct Seen {
    pub at: Instant,
    pub addr: SocketAddr,
    /// Key and formula the request was decoded with, to encode a `0xA7`.
    pub obf: (u32, u8),
    /// Our UDP port it arrived on: a reply must leave from it.
    pub local_port: u16,
    bucket: crate::admission::TokenBucket,
}

/// Why a request was not forwarded. Counted, never answered: Lugdunum sends
/// the requester nothing either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    Disabled,
    NotObfuscated,
    Short,
    UnknownRequester,
    RequesterHighId,
    WrongAddress,
    RateLimited,
    SameClient,
    UnknownTarget,
    TargetHighId,
    TargetNotCapable,
    TargetGone,
    CryptMismatch,
}

impl Refused {
    pub fn stat_key(self) -> &'static str {
        match self {
            Refused::Disabled => "natcb_disabled",
            Refused::NotObfuscated => "natcb_not_obfuscated",
            Refused::Short => "natcb_short",
            Refused::UnknownRequester => "natcb_unknown_requester",
            Refused::RequesterHighId => "natcb_requester_highid",
            Refused::WrongAddress => "natcb_wrong_address",
            Refused::RateLimited => "natcb_rate_limited",
            Refused::SameClient => "natcb_same_client",
            Refused::UnknownTarget => "natcb_unknown_target",
            Refused::TargetHighId => "natcb_target_highid",
            Refused::TargetNotCapable => "natcb_target_not_capable",
            Refused::TargetGone => "natcb_target_gone",
            Refused::CryptMismatch => "natcb_crypt_mismatch",
        }
    }
}

/// What to send.
#[derive(Debug)]
pub enum Forward {
    /// `0x37` to the client with this user hash.
    Tcp { target: [u8; 16], frame: Frame },
    /// `[0xE3][0xA7]…` to `addr`, obfuscated with `obf`, from our `local_port`.
    Udp {
        addr: SocketAddr,
        obf: (u32, u8),
        local_port: u16,
        packet: Vec<u8>,
    },
}

fn v4(ip: IpAddr) -> Option<std::net::Ipv4Addr> {
    match ip {
        IpAddr::V4(a) => Some(a),
        IpAddr::V6(a) => a.to_ipv4_mapped(),
    }
}

/// `(CT_SERVER_FLAGS >> 9) & 7`: bit 0 supports the crypt layer, bit 1
/// requests it, bit 2 requires it. Lugdunum's `c_osetting`.
pub fn crypt_setting(server_flags: u32) -> u8 {
    ((server_flags >> 9) & 7) as u8
}

/// The forward body for `req`, or None when one side requires the crypt
/// layer and the two cannot use it.
pub fn forward_body(
    req: &ClientHandle,
    req_addr: SocketAddr,
    target_flags: u32,
) -> Option<Vec<u8>> {
    let r = crypt_setting(req.server_flags);
    let t = crypt_setting(target_flags);
    let both = r & t & 1 != 0;
    let asked = (r | t) & 2 != 0;
    let with_hash = both && asked;
    if !with_hash && (r | t) & 4 != 0 {
        return None;
    }
    let ip = v4(req.ip)?;
    let mut b = Vec::with_capacity(27);
    b.extend_from_slice(&ip.octets());
    b.extend_from_slice(&req_addr.port().to_le_bytes());
    b.extend_from_slice(&req.assigned_id.to_le_bytes());
    if with_hash {
        b.push(r | 0x80);
        b.extend_from_slice(&req.user_hash);
    } else {
        b.push(r);
    }
    Some(b)
}

/// Handle a `0xA6` from `peer`. `obf` is the key the datagram was decoded
/// with (None: it came in the clear), `local_port` our port it arrived on.
pub fn handle_request(
    state: &ServerState,
    payload: &[u8],
    peer: SocketAddr,
    obf: Option<(u32, u8)>,
    local_port: u16,
) -> Result<Forward, Refused> {
    if !state.live_cfg.load().network.lugdunum_natt {
        return Err(Refused::Disabled);
    }
    let Some(obf) = obf else {
        return Err(Refused::NotObfuscated);
    };
    if payload.len() < 8 {
        return Err(Refused::Short);
    }
    let target_id = u32::from_le_bytes(payload[0..4].try_into().unwrap());
    let requester_id = u32::from_le_bytes(payload[4..8].try_into().unwrap());

    let req = state
        .client_by_assigned_id(requester_id)
        .ok_or(Refused::UnknownRequester)?;
    if req.is_high_id {
        return Err(Refused::RequesterHighId);
    }
    if v4(req.ip).is_none() || v4(req.ip) != v4(peer.ip()) {
        return Err(Refused::WrongAddress);
    }
    // Record the requester's endpoint (for a reverse request towards it)
    // and charge its allowance.
    {
        let now = Instant::now();
        let mut e = state
            .lugdunum_natt_seen
            .entry(req.user_hash)
            .or_insert_with(|| Seen {
                at: now,
                addr: peer,
                obf,
                local_port,
                bucket: crate::admission::TokenBucket::new(1, 10, now),
            });
        e.at = now;
        e.addr = peer;
        e.obf = obf;
        e.local_port = local_port;
        if !e.bucket.take(1, now) {
            return Err(Refused::RateLimited);
        }
    }
    if target_id == requester_id {
        return Err(Refused::SameClient);
    }
    let target = state
        .client_by_assigned_id(target_id)
        .ok_or(Refused::UnknownTarget)?;
    if target.is_high_id {
        return Err(Refused::TargetHighId);
    }
    if target.server_flags & SRVCAP_NATTRAVERSAL == 0 {
        return Err(Refused::TargetNotCapable);
    }
    if !target.is_alive() {
        return Err(Refused::TargetGone);
    }
    let body = forward_body(&req, peer, target.server_flags).ok_or(Refused::CryptMismatch)?;

    // The target's own endpoint, if it asked for a callback itself just now.
    let fresh = state
        .lugdunum_natt_seen
        .get(&target.user_hash)
        .filter(|s| s.at.elapsed() < UDP_FRESH && v4(s.addr.ip()) == v4(target.ip))
        .map(|s| (s.addr, s.obf, s.local_port));
    Ok(match fresh {
        Some((addr, obf, local_port)) => {
            let mut packet = Vec::with_capacity(2 + body.len());
            packet.push(0xE3);
            packet.push(OP_NAT_CALLBACK_UDP);
            packet.extend_from_slice(&body);
            Forward::Udp {
                addr,
                obf,
                local_port,
                packet,
            }
        }
        None => Forward::Tcp {
            target: target.user_hash,
            frame: Frame::new(OP_NAT_CALLBACK_TCP, body),
        },
    })
}

/// LowID parity, as Lugdunum hands them out: odd for a client that set
/// 0x1000, so a peer can tell from a source's id alone that the callback is
/// worth asking for. Lugdunum gives the others whatever comes next; here they
/// get even ids, so an odd id always means a capable client.
pub fn wants_odd_low_id(state: &ServerState, server_flags: u32) -> bool {
    state.live_cfg.load().network.lugdunum_natt && server_flags & SRVCAP_NATTRAVERSAL != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn st() -> ServerState {
        ServerState::for_test()
    }

    /// Register a LowID client at `ip` with `flags`, returning its receiver.
    fn client(
        s: &ServerState,
        hash: u8,
        id: u32,
        ip: [u8; 4],
        flags: u32,
    ) -> tokio::sync::mpsc::Receiver<Frame> {
        let rx =
            s.register_test_client_at([hash; 16], id, false, 0, IpAddr::V4(Ipv4Addr::from(ip)));
        s.clients.get_mut(&[hash; 16]).unwrap().server_flags = flags;
        rx
    }

    const NATT: u32 = SRVCAP_NATTRAVERSAL;
    const KEY: Option<(u32, u8)> = Some((0x1234_5678, 1));

    fn req(target: u32, requester: u32) -> Vec<u8> {
        let mut p = target.to_le_bytes().to_vec();
        p.extend_from_slice(&requester.to_le_bytes());
        p
    }

    #[test]
    fn a_request_is_forwarded_to_the_target_by_tcp() {
        let s = st();
        let _a = client(&s, 0xA, 11, [5, 6, 7, 8], NATT);
        let _b = client(&s, 0xB, 13, [9, 9, 9, 9], NATT);
        let peer: SocketAddr = "5.6.7.8:40000".parse().unwrap();
        let f = handle_request(&s, &req(13, 11), peer, KEY, 6086).unwrap();
        let Forward::Tcp { target, frame } = f else {
            panic!("{f:?}")
        };
        assert_eq!(target, [0xB; 16]);
        assert_eq!(frame.opcode, 0x37);
        // ip, port 40000 LE, requester id 11, crypt 0: Lugdunum's 11 bytes.
        assert_eq!(frame.payload, vec![5, 6, 7, 8, 0x40, 0x9C, 11, 0, 0, 0, 0]);
    }

    #[test]
    fn the_hash_rides_along_when_both_use_the_crypt_layer() {
        let s = st();
        // 0x200 supports, 0x400 requests.
        let _a = client(&s, 0xA, 11, [5, 6, 7, 8], NATT | 0x600);
        let _b = client(&s, 0xB, 13, [9, 9, 9, 9], NATT | 0x200);
        let peer: SocketAddr = "5.6.7.8:40000".parse().unwrap();
        let Forward::Tcp { frame, .. } = handle_request(&s, &req(13, 11), peer, KEY, 6086).unwrap()
        else {
            panic!()
        };
        assert_eq!(frame.payload.len(), 27);
        assert_eq!(frame.payload[10], 0x03 | 0x80);
        assert_eq!(&frame.payload[11..27], &[0xA; 16]);
    }

    #[test]
    fn a_required_crypt_layer_the_other_side_lacks_stops_it() {
        let s = st();
        let _a = client(&s, 0xA, 11, [5, 6, 7, 8], NATT | 0xE00); // requires
        let _b = client(&s, 0xB, 13, [9, 9, 9, 9], NATT); // no crypt
        let peer: SocketAddr = "5.6.7.8:40000".parse().unwrap();
        assert_eq!(
            handle_request(&s, &req(13, 11), peer, KEY, 6086).unwrap_err(),
            Refused::CryptMismatch
        );
    }

    #[test]
    fn the_rules_lugdunum_applies_and_ours() {
        let s = st();
        let _a = client(&s, 0xA, 11, [5, 6, 7, 8], NATT);
        let _b = client(&s, 0xB, 13, [9, 9, 9, 9], NATT);
        let _c = client(&s, 0xC, 14, [8, 8, 8, 8], 0); // stock client
        let peer: SocketAddr = "5.6.7.8:40000".parse().unwrap();
        assert_eq!(
            handle_request(&s, &req(13, 11), peer, None, 6086).unwrap_err(),
            Refused::NotObfuscated
        );
        assert_eq!(
            handle_request(&s, &[1, 2, 3], peer, KEY, 6086).unwrap_err(),
            Refused::Short
        );
        let elsewhere: SocketAddr = "1.1.1.1:40000".parse().unwrap();
        assert_eq!(
            handle_request(&s, &req(13, 11), elsewhere, KEY, 6086).unwrap_err(),
            Refused::WrongAddress
        );
        assert_eq!(
            handle_request(&s, &req(14, 11), peer, KEY, 6086).unwrap_err(),
            Refused::TargetNotCapable
        );
        assert_eq!(
            handle_request(&s, &req(99, 11), peer, KEY, 6086).unwrap_err(),
            Refused::UnknownTarget
        );
        assert_eq!(
            handle_request(&s, &req(11, 11), peer, KEY, 6086).unwrap_err(),
            Refused::SameClient
        );
        let mut cfg = (**s.live_cfg.load()).clone();
        cfg.network.lugdunum_natt = false;
        s.live_cfg.store(std::sync::Arc::new(cfg));
        assert_eq!(
            handle_request(&s, &req(13, 11), peer, KEY, 6086).unwrap_err(),
            Refused::Disabled
        );
    }

    #[test]
    fn a_target_that_asked_just_now_is_answered_by_udp() {
        let s = st();
        let _a = client(&s, 0xA, 11, [5, 6, 7, 8], NATT);
        let _b = client(&s, 0xB, 13, [9, 9, 9, 9], NATT);
        // B asks for A first (B's endpoint becomes fresh)…
        let b_peer: SocketAddr = "9.9.9.9:50000".parse().unwrap();
        handle_request(&s, &req(11, 13), b_peer, Some((7, 1)), 6090).unwrap();
        // …then A's reverse request reaches B over UDP, from the port B used.
        let a_peer: SocketAddr = "5.6.7.8:40000".parse().unwrap();
        let f = handle_request(&s, &req(13, 11), a_peer, KEY, 6086).unwrap();
        let Forward::Udp {
            addr,
            obf,
            local_port,
            packet,
        } = f
        else {
            panic!("{f:?}")
        };
        assert_eq!((addr, obf, local_port), (b_peer, (7, 1), 6090));
        assert_eq!(&packet[..2], &[0xE3, 0xA7]);
        assert_eq!(&packet[2..], &[5, 6, 7, 8, 0x40, 0x9C, 11, 0, 0, 0, 0]);
    }

    #[test]
    fn requests_are_rate_limited_per_requester() {
        let s = st();
        let _a = client(&s, 0xA, 11, [5, 6, 7, 8], NATT);
        let _b = client(&s, 0xB, 13, [9, 9, 9, 9], NATT);
        let peer: SocketAddr = "5.6.7.8:40000".parse().unwrap();
        let ok = (0..30)
            .filter(|_| handle_request(&s, &req(13, 11), peer, KEY, 6086).is_ok())
            .count();
        assert!((10..=11).contains(&ok), "{ok}");
    }
}

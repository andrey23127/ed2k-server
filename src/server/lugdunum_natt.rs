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
//!
//! **Cross-server (issue #40).** A client logged in to another server can
//! reach a target logged in here: it learns the target's server and LowID
//! from source exchange, takes this server's UDP key from the status ping
//! and sends `0xA6` `<target_id><0>[<crypt 1>]`, obfuscated. Requester id 0
//! marks it foreign. The key is `IPObfuscate(secret, sender IP)`, so a
//! datagram that decodes proves the sender's IP; its source port is the
//! requester's endpoint. The target gets the usual `0x37` with requester id
//! 0, and no hash (the server does not know the requester's). A target with
//! the extension (0x100000) answers with `0x9F`; the requester then gets
//! `0xA7` `<target_ip><target_udp_port><target_id><crypt><hash>` by UDP,
//! obfuscated, from the port it wrote to; without that `0x9F` within 3 s,
//! the same with the port the server has. Nothing else is ever answered, so
//! an unknown or unsuitable target is indistinguishable from a lost
//! datagram. Without a session to kick, the limits sit on the source IP: a
//! burst of 10 then one a second, at most 60 different targets in 10
//! minutes, and at most 6 foreign wake-ups a minute per target.

use crate::proto::Frame;
use crate::state::{ClientHandle, ServerState};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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

/// Cross-server requests (issue #40): how many different targets one source
/// IP may name in `FOREIGN_TARGET_WINDOW`. A downloader has a handful of LowID
/// sources on one server; a sweep over LowIDs hits this within a minute.
pub const FOREIGN_MAX_TARGETS: usize = 60;
pub const FOREIGN_TARGET_WINDOW: Duration = Duration::from_secs(600);
/// Foreign wake-ups one target may get a minute.
pub const FOREIGN_WAKES_PER_MIN: usize = 6;

/// One foreign requester (by source IP): its allowance and the targets it
/// named recently.
pub struct ForeignSource {
    bucket: crate::admission::TokenBucket,
    targets: HashMap<u32, Instant>,
    last: Instant,
}

impl ForeignSource {
    /// Nothing left to remember: the sweep may drop it.
    pub fn idle(&self) -> bool {
        self.last.elapsed() >= FOREIGN_TARGET_WINDOW
    }
}

/// The answer a foreign requester is owed once the target has sent its
/// `0x9F` (or the wait is over). The caller waits on `rx`, then sends
/// `answer_packet` to `to`.
pub struct ForeignAnswer {
    pub rx: tokio::sync::oneshot::Receiver<()>,
    pub target: [u8; 16],
    pub to: SocketAddr,
    pub obf: (u32, u8),
    pub local_port: u16,
    pub requester_crypt: u8,
    /// One wait per (requester address, target), within the shared retry
    /// pool; released when the answer is sent.
    pub guards: (crate::admission::RetryKey, tokio::sync::OwnedSemaphorePermit),
}

impl std::fmt::Debug for ForeignAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForeignAnswer")
            .field("to", &self.to)
            .field("local_port", &self.local_port)
            .field("requester_crypt", &self.requester_crypt)
            .finish()
    }
}

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
    ForeignDisabled,
    ForeignRateLimited,
    ForeignTooManyTargets,
    ForeignTargetLimited,
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
            Refused::ForeignDisabled => "natcb_foreign_disabled",
            Refused::ForeignRateLimited => "natcb_foreign_rate_limited",
            Refused::ForeignTooManyTargets => "natcb_foreign_too_many_targets",
            Refused::ForeignTargetLimited => "natcb_foreign_target_limited",
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
    // ID 0 marks a foreign request (issue #40); a same-server forward never
    // carries it. LowIDs start at 1, so this is a guard, not a case.
    if req.assigned_id == 0 {
        return None;
    }
    let ip = v4(req.ip)?;
    body(
        ip,
        req_addr.port(),
        req.assigned_id,
        crypt_setting(req.server_flags),
        Some(&req.user_hash),
        crypt_setting(target_flags),
    )
}

/// `<ip><port><id><crypt>[<hash>]` describing the peer `ip`, whose crypt
/// setting is `own`, for a reader whose setting is `other`. The hash rides
/// along (and 0x80 in `crypt`) when both support the crypt layer and one
/// asks for it, if it is known; None when one side requires the layer and
/// the pair cannot use it.
fn body(ip: Ipv4Addr, port: u16, id: u32, own: u8, hash: Option<&[u8; 16]>, other: u8) -> Option<Vec<u8>> {
    let both = own & other & 1 != 0;
    let asked = (own | other) & 2 != 0;
    let with_hash = both && asked && hash.is_some();
    if !with_hash && (own | other) & 4 != 0 {
        return None;
    }
    let mut b = Vec::with_capacity(27);
    b.extend_from_slice(&ip.octets());
    b.extend_from_slice(&port.to_le_bytes());
    b.extend_from_slice(&id.to_le_bytes());
    match hash.filter(|_| with_hash) {
        Some(h) => {
            b.push(own | 0x80);
            b.extend_from_slice(h);
        }
        None => b.push(own),
    }
    Some(b)
}

/// The cross-server path is offered: it builds on the extension.
pub fn foreign_enabled(cfg: &crate::config::Config) -> bool {
    cfg.network.holepunch_foreign && crate::server::holepunch::extension_enabled(cfg)
}

/// A `0xA6` of either kind: requester id 0 is a client logged in elsewhere
/// (issue #40), anything else one logged in here.
pub fn handle(
    state: &ServerState,
    payload: &[u8],
    peer: SocketAddr,
    obf: Option<(u32, u8)>,
    local_port: u16,
) -> Result<(Forward, Option<ForeignAnswer>), Refused> {
    if payload.len() >= 8 && payload[4..8] == [0; 4] {
        crate::server::holepunch::count(state, "foreign_natcb_requests");
        handle_foreign(state, payload, peer, obf, local_port)
    } else {
        crate::server::holepunch::count(state, "natcbx_requests");
        handle_request(state, payload, peer, obf, local_port).map(|f| (f, None))
    }
}

/// The forward of `body` to `target`: by UDP when the target asked for a
/// callback itself just now, else by TCP.
fn deliver(state: &ServerState, target: &ClientHandle, body: Vec<u8>) -> Forward {
    let fresh = state
        .lugdunum_natt_seen
        .get(&target.user_hash)
        .filter(|s| s.at.elapsed() < UDP_FRESH && v4(s.addr.ip()) == v4(target.ip))
        .map(|s| (s.addr, s.obf, s.local_port));
    match fresh {
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
    }
}

/// A `0xA6` from a client not logged in here (requester id 0, issue #40).
pub fn handle_foreign(
    state: &ServerState,
    payload: &[u8],
    peer: SocketAddr,
    obf: Option<(u32, u8)>,
    local_port: u16,
) -> Result<(Forward, Option<ForeignAnswer>), Refused> {
    let cfg = state.live_cfg.load();
    if !cfg.network.lugdunum_natt {
        return Err(Refused::Disabled);
    }
    if !foreign_enabled(&cfg) {
        return Err(Refused::ForeignDisabled);
    }
    let Some(obf) = obf else {
        return Err(Refused::NotObfuscated);
    };
    if payload.len() < 8 {
        return Err(Refused::Short);
    }
    let target_id = u32::from_le_bytes(payload[0..4].try_into().unwrap());
    let requester_crypt = payload.get(8).map_or(0, |b| b & 7);
    let ip = v4(peer.ip()).ok_or(Refused::WrongAddress)?;
    let now = Instant::now();
    {
        let mut src = state
            .natcb_foreign_sources
            .entry(IpAddr::V4(ip))
            .or_insert_with(|| ForeignSource {
                bucket: crate::admission::TokenBucket::new(1, 10, now),
                targets: HashMap::new(),
                last: now,
            });
        src.last = now;
        if !src.bucket.take(1, now) {
            return Err(Refused::ForeignRateLimited);
        }
        // Every target id named counts, known or not: a sweep finds out
        // nothing either way, and is stopped all the same.
        src.targets.retain(|_, t| t.elapsed() < FOREIGN_TARGET_WINDOW);
        if !src.targets.contains_key(&target_id) && src.targets.len() >= FOREIGN_MAX_TARGETS {
            return Err(Refused::ForeignTooManyTargets);
        }
        src.targets.insert(target_id, now);
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
    let body = body(
        ip,
        peer.port(),
        0,
        requester_crypt,
        None,
        crypt_setting(target.server_flags),
    )
    .ok_or(Refused::CryptMismatch)?;
    {
        let mut w = state.natcb_foreign_wakes.entry(target.user_hash).or_default();
        while w.front().is_some_and(|t| t.elapsed() >= Duration::from_secs(60)) {
            w.pop_front();
        }
        if w.len() >= FOREIGN_WAKES_PER_MIN {
            return Err(Refused::ForeignTargetLimited);
        }
        w.push_back(now);
    }
    // The requester's answer, when the target can give one: a target with
    // the extension sends 0x9F on the 0x37. Listen before it is woken.
    crate::server::holepunch::count(
        state,
        if crate::server::holepunch::has_extension(state, target.server_flags) {
            "natcbx_foreign_target_extension"
        } else {
            "natcbx_foreign_target_lugdunum_only"
        },
    );
    let answer = if crate::server::holepunch::has_extension(state, target.server_flags) {
        let mut pseudo = [0xFFu8; 16];
        pseudo[..4].copy_from_slice(&ip.octets());
        pseudo[4..6].copy_from_slice(&peer.port().to_le_bytes());
        match state.admission.try_retry(pseudo, target_id) {
            Ok(guards) => {
                let (tx, rx) = tokio::sync::oneshot::channel();
                state
                    .natt_keepalive_waiters
                    .entry(target.user_hash)
                    .or_default()
                    .push(tx);
                Some(ForeignAnswer {
                    rx,
                    target: target.user_hash,
                    to: peer,
                    obf,
                    local_port,
                    requester_crypt,
                    guards,
                })
            }
            // One already waits for this pair, or the pool is full: the
            // target is still woken; the answer comes from the one waiting.
            Err(_) => None,
        }
    } else {
        None
    };
    Ok((deliver(state, &target, body), answer))
}

/// `[0xE3][0xA7]<target_ip><target_udp_port><target_id><crypt><hash>` for a
/// foreign requester, with the best port the server has for the target now.
/// Always 27 bytes of body: the requester dials and needs the hash. None
/// when the target has gone or has no UDP port.
pub fn answer_packet(state: &ServerState, target: &[u8; 16], requester_crypt: u8) -> Option<Vec<u8>> {
    let t = state.clients.get(target).map(|c| c.clone())?;
    if !t.is_alive() || t.is_high_id {
        return None;
    }
    let ip = v4(t.ip)?;
    let port = crate::server::holepunch::observed_udp_port(state, &t.user_hash, t.ip, t.udp_port);
    if port == 0 {
        return None;
    }
    let mut b = body(
        ip,
        port,
        t.assigned_id,
        crypt_setting(t.server_flags),
        Some(&t.user_hash),
        requester_crypt,
    )?;
    // The requester dials (issue #40), and its first QUIC Initial is
    // obfuscated with the target's hash: it always gets the hash here. 0x80
    // in `crypt` keeps Lugdunum's meaning, "use the crypt layer".
    if b.len() == 11 {
        b.extend_from_slice(&t.user_hash);
    }
    let mut packet = Vec::with_capacity(2 + b.len());
    packet.push(0xE3);
    packet.push(OP_NAT_CALLBACK_UDP);
    packet.extend_from_slice(&b);
    Some(packet)
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
        // NAT-T analysis: requesters that ignore the parity rule ask for even
        // LowIDs, which never set 0x1000 here.
        crate::server::holepunch::count(
            state,
            if target_id & 1 == 0 {
                "natcbx_not_capable_even_target"
            } else {
                "natcbx_not_capable_odd_target"
            },
        );
        crate::server::holepunch::count(
            state,
            &format!("natcbx_not_capable_from_sw:{}", crate::server::holepunch::sw_family(state, &req.user_hash)),
        );
        return Err(Refused::TargetNotCapable);
    }
    if !target.is_alive() {
        return Err(Refused::TargetGone);
    }
    let body = forward_body(&req, peer, target.server_flags).ok_or(Refused::CryptMismatch)?;
    crate::server::holepunch::count(
        state,
        &format!("natcbx_forward_from_sw:{}", crate::server::holepunch::sw_family(state, &req.user_hash)),
    );
    Ok(deliver(state, &target, body))
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

    fn foreign(target: u32) -> Vec<u8> {
        req(target, 0)
    }

    const EXT: u32 = crate::proto::opcodes::SRVFLG_HOLEPUNCH_EXT | NATT;

    /// Issue #40: a client logged in elsewhere wakes a target here; the
    /// target gets Lugdunum's 0x37 with requester id 0 and no hash.
    #[test]
    fn a_foreign_request_wakes_the_target() {
        let s = st();
        let _b = client(&s, 0xB, 13, [9, 9, 9, 9], NATT | 0x600);
        let peer: SocketAddr = "5.6.7.8:40000".parse().unwrap();
        let mut p = foreign(13);
        p.push(0x03); // the requester supports and requests the crypt layer
        let (f, answer) = handle(&s, &p, peer, KEY, 6086).unwrap();
        let Forward::Tcp { target, frame } = f else { panic!("{f:?}") };
        assert_eq!(target, [0xB; 16]);
        assert_eq!(frame.opcode, 0x37);
        assert_eq!(frame.payload, vec![5, 6, 7, 8, 0x40, 0x9C, 0, 0, 0, 0, 0x03]);
        assert!(answer.is_none(), "a Lugdunum-only target gives no answer");
        // Plain, or with the feature off: nothing.
        assert_eq!(handle(&s, &foreign(13), peer, None, 6086).unwrap_err(), Refused::NotObfuscated);
        let mut cfg = (**s.live_cfg.load()).clone();
        cfg.network.holepunch_foreign = false;
        s.live_cfg.store(std::sync::Arc::new(cfg));
        assert_eq!(handle(&s, &foreign(13), peer, KEY, 6086).unwrap_err(), Refused::ForeignDisabled);
    }

    /// A target with the extension owes the requester an answer: its
    /// endpoint, id, crypt setting and hash (both use the crypt layer).
    #[tokio::test]
    async fn a_foreign_request_to_an_extension_target_is_answered() {
        let s = st();
        let _b = client(&s, 0xB, 13, [9, 9, 9, 9], EXT | 0x200);
        s.natt_udp_ports.insert([0xB; 16], (50000, Instant::now()));
        let peer: SocketAddr = "5.6.7.8:40000".parse().unwrap();
        let mut p = foreign(13);
        p.push(0x03);
        let (_, answer) = handle(&s, &p, peer, KEY, 6086).unwrap();
        let a = answer.expect("an answer is owed");
        assert_eq!((a.to, a.obf, a.local_port), (peer, KEY.unwrap(), 6086));
        // The target's 0x9F releases it.
        crate::server::holepunch::keepalive_arrived(&s, &[0xB; 16]);
        assert!(matches!(a.rx.await, Ok(())));
        let packet = answer_packet(&s, &[0xB; 16], 0x03).unwrap();
        assert_eq!(&packet[..2], &[0xE3, 0xA7]);
        assert_eq!(&packet[2..12], &[9, 9, 9, 9, 0x50, 0xC3, 13, 0, 0, 0]);
        assert_eq!(packet[12], 0x01 | 0x80);
        assert_eq!(&packet[13..29], &[0xB; 16]);
        // Without the crypt layer on both sides: no 0x80, the hash all the same.
        let packet = answer_packet(&s, &[0xB; 16], 0).unwrap();
        assert_eq!(packet.len(), 2 + 27);
        assert_eq!(packet[12], 0x01);
        assert_eq!(&packet[13..29], &[0xB; 16]);
        // A second request for the same pair while one waits: woken, no
        // second answer.
        let (_, again) = handle(&s, &p, peer, KEY, 6086).unwrap();
        assert!(again.is_none());
    }

    #[test]
    fn the_rules_for_foreign_targets() {
        let s = st();
        let _h = s.register_test_client_at([0xC; 16], 0x0A00_0001, true, 0, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        let _c = client(&s, 0xD, 14, [8, 8, 8, 8], 0); // stock
        let _e = client(&s, 0xE, 15, [7, 7, 7, 7], NATT); // no crypt layer
        let peer: SocketAddr = "5.6.7.8:40000".parse().unwrap();
        assert_eq!(handle(&s, &foreign(99), peer, KEY, 6086).unwrap_err(), Refused::UnknownTarget);
        assert_eq!(handle(&s, &foreign(0x0A00_0001), peer, KEY, 6086).unwrap_err(), Refused::TargetHighId);
        assert_eq!(handle(&s, &foreign(14), peer, KEY, 6086).unwrap_err(), Refused::TargetNotCapable);
        // The requester requires the crypt layer; the target can't, and the
        // server has no hash to give it anyway.
        let mut p = foreign(15);
        p.push(0x07);
        assert_eq!(handle(&s, &p, peer, KEY, 6086).unwrap_err(), Refused::CryptMismatch);
        let v6: SocketAddr = "[2001:db8::1]:40000".parse().unwrap();
        assert_eq!(handle(&s, &foreign(15), v6, KEY, 6086).unwrap_err(), Refused::WrongAddress);
    }

    /// The limits: a burst then 1/s per source, 60 different targets in 10
    /// minutes per source, 6 foreign wake-ups a minute per target.
    #[test]
    fn foreign_requests_are_limited() {
        let s = st();
        let _b = client(&s, 0xB, 13, [9, 9, 9, 9], NATT);
        let from = |i: u8| -> SocketAddr { format!("5.6.7.{i}:40000").parse().unwrap() };
        // Per target: six wake-ups from six sources, then no more.
        let woke = (1..=10u8)
            .filter(|&i| handle(&s, &foreign(13), from(i), KEY, 6086).is_ok())
            .count();
        assert_eq!(woke, FOREIGN_WAKES_PER_MIN);
        assert_eq!(
            handle(&s, &foreign(13), from(20), KEY, 6086).unwrap_err(),
            Refused::ForeignTargetLimited
        );
        // Per source: a burst of 10.
        let sweeper = from(50);
        let allowed = (0..30u32)
            .filter(|&t| handle(&s, &foreign(1000 + t), sweeper, KEY, 6086).err() != Some(Refused::ForeignRateLimited))
            .count();
        assert!((10..=11).contains(&allowed), "{allowed}");
        // Distinct targets: with the allowance refilled, the 61st is refused.
        let mut e = s.natcb_foreign_sources.get_mut(&sweeper.ip()).unwrap();
        e.bucket = crate::admission::TokenBucket::new(1, 1000, Instant::now());
        for t in 0..60u32 {
            e.targets.insert(2000 + t, Instant::now());
        }
        drop(e);
        assert_eq!(
            handle(&s, &foreign(5000), sweeper, KEY, 6086).unwrap_err(),
            Refused::ForeignTooManyTargets
        );
        // A target it already named still goes through the checks.
        assert_eq!(handle(&s, &foreign(2000), sweeper, KEY, 6086).unwrap_err(), Refused::UnknownTarget);
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

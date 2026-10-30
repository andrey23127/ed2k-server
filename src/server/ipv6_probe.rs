//! Dial-back of a client's IPv6 before it is published as a source (issue #43).
//!
//! A client tells the server its IPv6 in `CT_MOD_IP_V6` (or in
//! `OP_IPV6_UPDATE`), nearly always over an IPv4 session, so nothing has
//! checked the address. Most dual-stack homes have a global address behind a
//! router that drops unsolicited inbound IPv6: published as-is, it sends
//! requesters to an address that never answers, and a client cannot test its
//! own inbound IPv6 before peers dial it.
//!
//! So the server dials `[v6]:login port` with the identity probe the HighID
//! check uses: the answer must carry the user hash that logged in, since the
//! address is only the client's word. Until it succeeds the client is handled
//! as one without IPv6 — not published, though it stays sentinel-capable. The
//! verdict goes back in `ST_IPV6_STATUS`: `HAVE|REACHABLE|PROBED` on success,
//! `HAVE|PROBED` on failure, in a fresh `OP_SERVERIDENT`.
//!
//! Active only when the server publishes IPv6 sources, `network.ipv6_probe`
//! is on and the server has an IPv6 route to dial with; it then sets
//! `SRVFLG_IPV6_PROBE` (0x400000) in `OP_IDCHANGE`. Otherwise everything
//! works as before: the address is published on trust, status `HAVE|REACHABLE`.

use crate::proto::Frame;
use crate::state::{ServerState, UserHash};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

/// One client's probe: the address it is about, and the verdict (None while
/// it runs, or when it could not run).
#[derive(Debug, Clone, Copy)]
pub struct Probe {
    pub addr: Ipv6Addr,
    pub verdict: Option<bool>,
    pub at: Instant,
    /// Dials made for this session. The address is the client's word, so
    /// each dial goes wherever the client points it; this caps how often.
    pub dials: u8,
}

/// Dials per session. The login address and a few `OP_IPV6_UPDATE` changes;
/// past that a new address stays unpublished.
pub const MAX_DIALS: u8 = 4;

/// Is the dial-back in force?
pub fn active(state: &ServerState) -> bool {
    let live = state.live_cfg.load();
    live.network.ipv6_probe
        && live.network.ipv6_publish_sources
        && state.ipv6_route.load(Ordering::Relaxed)
}

/// Does this host have a route to the IPv6 internet? A UDP "connect" picks a
/// source address and route without sending anything.
pub fn detect_route() -> bool {
    std::net::UdpSocket::bind("[::]:0")
        .and_then(|s| s.connect("[2001:4860:4860::8888]:53").map(|_| s))
        .and_then(|s| s.local_addr())
        .map(|a| matches!(a.ip(), IpAddr::V6(v6) if !v6.is_loopback() && !v6.is_unspecified()))
        .unwrap_or(false)
}

/// The verdict for `addr`, when the last probe was about that address.
pub fn verdict(state: &ServerState, user_hash: &UserHash, addr: Ipv6Addr) -> Option<bool> {
    state
        .ipv6_probe
        .get(user_hash)
        .filter(|p| p.addr == addr)
        .and_then(|p| p.verdict)
}

/// `ST_IPV6_STATUS` bits for a client holding `addr`.
pub fn status_bits(state: &ServerState, user_hash: &UserHash, addr: Option<Ipv6Addr>) -> u8 {
    use crate::server::login::{
        IPV6ST_HAVE as HAVE, IPV6ST_PROBED as PROBED, IPV6ST_REACHABLE as REACHABLE,
    };
    let Some(a) = addr else { return 0 };
    if !active(state) {
        // On trust, as before the probe existed.
        return HAVE | REACHABLE;
    }
    match verdict(state, user_hash, a) {
        Some(true) => HAVE | REACHABLE | PROBED,
        Some(false) => HAVE | PROBED,
        // Running: no claim yet.
        None => HAVE,
    }
}

/// Hold `addr` back until its probe has run: not published, status `HAVE`.
/// Called before the welcome batch at login, so its `OP_SERVERIDENT` cannot
/// claim more than that. Returns whether a probe should start: not when this
/// address already has its verdict (re-applied) or a probe running.
pub fn mark_pending(state: &ServerState, user_hash: UserHash, addr: Ipv6Addr) -> bool {
    let prev = state.ipv6_probe.get(&user_hash).map(|p| *p);
    if let Some(p) = prev.filter(|p| p.addr == addr) {
        match p.verdict {
            Some(true) => {
                state.client_ipv6.insert(user_hash, addr);
            }
            _ => {
                state.client_ipv6.remove(&user_hash);
            }
        }
        return false;
    }
    state.client_ipv6.remove(&user_hash);
    state.ipv6_probe.insert(
        user_hash,
        Probe {
            addr,
            verdict: None,
            at: Instant::now(),
            dials: prev.map_or(0, |p| p.dials),
        },
    );
    true
}

/// Dial `[addr]:port` and expect `user_hash`; `mark_pending` first. On the
/// verdict, publish (or not) and send the session a fresh `OP_SERVERIDENT`.
/// Left unpublished when the server-wide probe ceiling is full or the
/// session has used its dials.
pub fn start(
    state: &Arc<ServerState>,
    user_hash: UserHash,
    addr: Ipv6Addr,
    port: u16,
    client_flags: u32,
) {
    {
        let Some(mut p) = state.ipv6_probe.get_mut(&user_hash) else {
            return;
        };
        if p.addr != addr || p.verdict.is_some() {
            return;
        }
        if p.dials >= MAX_DIALS {
            drop(p);
            crate::server::holepunch::count(state, "ipv6_probe_skipped_limit");
            return;
        }
        p.dials += 1;
    }
    let Some(permit) = state.admission.probes.try_take() else {
        crate::server::holepunch::count(state, "ipv6_probe_skipped_busy");
        return;
    };
    crate::server::holepunch::count(state, "ipv6_probe_started");
    let live = state.live_cfg.load_full();
    let ident = crate::server::login::HighIdProbeIdent::from_config(&live);
    let timeout_ms = live.network.login_timeout_ms;
    let supports_crypt = client_flags & crate::server::login::SRVCAP_SUPPORTCRYPT != 0;
    let state = Arc::clone(state);
    tokio::spawn(async move {
        let _permit = permit;
        let answer = crate::server::login::highid_identity_answer(
            IpAddr::V6(addr),
            port,
            user_hash,
            ident,
            timeout_ms,
            supports_crypt,
        )
        .await;
        let ok = matches!(&answer, Ok(h) if crate::server::highid_probe::same_client_hash(h, &user_hash));
        crate::server::holepunch::count(
            &state,
            match &answer {
                Ok(_) if ok => "ipv6_probe_ok",
                Ok(_) => "ipv6_probe_wrong_hash",
                Err(_) => "ipv6_probe_no_answer",
            },
        );
        // Why there was no answer: dropped on the way (a firewall that
        // discards: timeout), turned away (refused: the host is reachable
        // but nothing takes the port on IPv6, or a rejecting firewall), no
        // route (unreachable), or something answered but not as a client.
        if let Err(e) = &answer {
            crate::server::holepunch::count(&state, fail_key(e));
        }
        conclude(&state, user_hash, addr, ok);
    });
}

/// Each minute: recheck the route, drop entries of sessions gone without
/// the logout path, and retry a probe that never ran (the ceiling was full)
/// once it has waited a minute, within the session's dials.
pub fn sweep(state: &Arc<ServerState>) {
    state.ipv6_route.store(detect_route(), Ordering::Relaxed);
    state
        .ipv6_probe
        .retain(|h, _| state.clients.contains_key(h));
    if !active(state) {
        return;
    }
    let stalled: Vec<(UserHash, Ipv6Addr)> = state
        .ipv6_probe
        .iter()
        .filter(|p| p.verdict.is_none() && p.dials < MAX_DIALS && p.at.elapsed().as_secs() >= 60)
        .map(|p| (*p.key(), p.addr))
        .collect();
    for (h, a) in stalled {
        let Some((port, flags, cur)) = state
            .clients
            .get(&h)
            .map(|c| (c.port, c.server_flags, c.ipv6))
        else {
            continue;
        };
        if cur == Some(a) {
            if let Some(mut p) = state.ipv6_probe.get_mut(&h) {
                p.at = Instant::now();
            }
            start(state, h, a, port, flags);
        }
    }
}

/// The counter for a probe that got no answer, by stage.
fn fail_key(e: &str) -> &'static str {
    match e {
        "connect timeout" => "ipv6_probe_fail_timeout",
        "connect refused" => "ipv6_probe_fail_refused",
        "connect unreachable" => "ipv6_probe_fail_unreachable",
        _ => "ipv6_probe_fail_after_connect",
    }
}

/// Record the verdict and act on it, if the session still holds `addr`.
pub fn conclude(state: &ServerState, user_hash: UserHash, addr: Ipv6Addr, ok: bool) {
    let Some(client) = state.clients.get(&user_hash).map(|c| c.clone()) else {
        state.ipv6_probe.remove(&user_hash);
        return;
    };
    if client.ipv6 != Some(addr) {
        // Superseded by an OP_IPV6_UPDATE; its own probe decides.
        return;
    }
    match state.ipv6_probe.get_mut(&user_hash) {
        Some(mut p) if p.addr == addr => {
            p.verdict = Some(ok);
            p.at = Instant::now();
        }
        // The session ended and another began meanwhile.
        _ => return,
    }
    if ok {
        state.client_ipv6.insert(user_hash, addr);
    } else {
        state.client_ipv6.remove(&user_hash);
    }
    let live = state.live_cfg.load();
    let ident: Frame = crate::server::login::build_server_ident(&live, state, &client);
    let outcome = client.send_frame(ident);
    state
        .admission
        .push
        .note(crate::admission::PushKind::Holepunch, outcome);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on(s: &ServerState) {
        let mut cfg = (**s.live_cfg.load()).clone();
        cfg.network.ipv6_publish_sources = true;
        cfg.network.ipv6_probe = true;
        s.live_cfg.store(Arc::new(cfg));
        s.ipv6_route.store(true, Ordering::Relaxed);
    }

    #[test]
    fn the_status_follows_the_verdict() {
        let s = ServerState::for_test();
        let a: Ipv6Addr = "2001:db8::7".parse().unwrap();
        let h = [7u8; 16];
        // Off: on trust, as before.
        assert_eq!(status_bits(&s, &h, Some(a)), 0x03);
        assert_eq!(status_bits(&s, &h, None), 0);
        on(&s);
        assert_eq!(status_bits(&s, &h, Some(a)), 0x01, "running: HAVE only");
        let mut rx = s.register_test_client_at(h, 5, false, 0, "10.0.0.5".parse().unwrap());
        s.clients.get_mut(&h).unwrap().ipv6 = Some(a);
        assert!(mark_pending(&s, h, a));
        assert!(!mark_pending(&s, h, a), "already running");
        conclude(&s, h, a, true);
        assert_eq!(status_bits(&s, &h, Some(a)), 0x07);
        assert_eq!(s.client_ipv6.get(&h).map(|e| *e), Some(a), "published");
        assert!(rx.try_recv().is_ok(), "a fresh SERVERIDENT went out");
        conclude(&s, h, a, false);
        assert_eq!(status_bits(&s, &h, Some(a)), 0x05);
        assert!(s.client_ipv6.get(&h).is_none(), "withdrawn");
        // The same address again keeps its verdict, no new dial.
        assert!(!mark_pending(&s, h, a));
        assert_eq!(status_bits(&s, &h, Some(a)), 0x05);
        // A verdict about another address does not count.
        let b: Ipv6Addr = "2001:db8::8".parse().unwrap();
        assert_eq!(status_bits(&s, &h, Some(b)), 0x01);
        assert!(mark_pending(&s, h, b), "a new address is dialled");
        assert!(s.client_ipv6.get(&h).is_none());
    }
}

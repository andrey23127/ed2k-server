//! Server-to-server gossip — complete implementation based on captured
//! Lugdunum 17.15 ↔ Lugdunum 17.15 wire trace.
//!
//! ## Protocol (verified from real pcap)
//!
//! The handshake has three phases. **All three are required** for a seed to
//! include us in its server list / propagate us to other seeds:
//!
//! ### Phase 1 — Plain bootstrap (from main UDP socket, port 4665)
//!
//! ```text
//! our:4665 → seed:4665   PLAIN 0xA0 SERVER_LIST_REQ
//!     payload: proto(1) + opcode(1) + our_ip(4 net order) + our_tcp_port(2 LE) + challenge(4)
//! our:4665 → seed:4665   PLAIN 0x96 GLOBSERVSTATREQ
//!     payload: proto(1) + opcode(1) + challenge(4)  // challenge has 0x55AA marker
//! ```
//!
//! ### Phase 2 — OBF ping handshake (from a **fresh ephemeral socket**)
//!
//! ```text
//! our:EPH  → seed:4673   OBF PING (4-byte random_part + 0..14 padding bytes)
//! seed:4673 → our:EPH    OBF REPLY (RC4-encrypted GLOBSERVSTATRES with seed's ServerKey)
//! ```
//!
//! Both packets cross the same ephemeral local port. The seed indexes the
//! random_part by (our_ip, our_ephemeral_port) so it can later encrypt UDP
//! traffic back to us.
//!
//! ### Phase 3 — Obfuscated gossip (from the **same ephemeral socket**)
//!
//! ```text
//! our:EPH  → seed:4675   OBF encode(0xA0, seed_serverkey)   // re-register obfuscated
//! our:EPH  → seed:4675   OBF encode(0xA4, seed_serverkey)   // request server list
//! seed:4675 → our:EPH    OBF encode(0xA1 server list, our_random_part)
//! ```
//!
//! **Critical:** the obfuscated gossip MUST come from the same ephemeral
//! source port as the OBF ping — that's how the seed knows the (ip, port)
//! pair to look up our random_part. Sending obfuscated traffic from the
//! main 4665 socket silently fails because the seed has no random_part
//! recorded for that (ip, port) tuple.
//!
//! ### Why TCP+14 specifically
//!
//! Lugdunum binds two distinct UDP sockets:
//!   - `serv_to_serv_sock` on TCP+4 — for plain server-to-server traffic
//!   - `udpsockobf`         on TCP+14 — for **obfuscated** server-to-server
//!
//! Plain to TCP+4 ✓. Obfuscated to TCP+14 ✓. Anything else is dropped.

use crate::proto::opcodes::PROTO_EDONKEY;
use crate::proto::server_obfuscation;
use crate::server::obf_ping::{decode_obf_s2s, OBF_PING_PAYLOAD_MAX_PAD};
use crate::state::ServerState;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

const OP_SERVER_LIST_REQ:  u8 = 0xA0;
const OP_SERVER_LIST_RES:  u8 = 0xA1;
const OP_GLOB_SERVSTATREQ: u8 = 0x96;
const OP_SERVER_LIST_REQ2: u8 = 0xA4; // explicit "send me server list"

/// Full handshake cycle interval — Lugdunum keepalive is ~165s.
const KEEPALIVE_SECS: u64 = 150;

/// How long to wait for a reply at each step (OBF ping reply, gossip reply).
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// Challenge for GLOBSERVSTATREQ. The 0x55AA marker in low bytes tells
/// Lugdunum-family servers this is a server-to-server probe and they should
/// reply with the full extended GLOBSERVSTATRES (32+ bytes, not the short
/// 12-byte form sent to clients).
const PROBE_CHALLENGE: u32 = 0x55AA_0001;

pub use parse_seed_fn as parse_seed;

pub fn parse_seed_fn(s: &str) -> Option<SocketAddrV4> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 { return None; }
    let ip: Ipv4Addr = parts[0].parse().ok()?;
    let port: u16 = parts[1].parse().ok()?;
    Some(SocketAddrV4::new(ip, port))
}

/// Start a gossip task for each seed. Each task runs an independent loop
/// that performs the full handshake, then sleeps until next keepalive.
///
/// `seeds` contains the seed's **TCP** port; +4/+12/+14 offsets are derived.
pub fn spawn_gossip(
    state: Arc<ServerState>,
    seeds: Vec<SocketAddrV4>,
    our_ip: Ipv4Addr,
    our_tcp_port: u16,
    main_udp_sock: Arc<UdpSocket>,
    seckey: [u8; 16],
) {
    if seeds.is_empty() {
        debug!("no seed servers configured — skipping gossip");
        return;
    }
    info!(seeds = seeds.len(), "starting gossip — full handshake per seed");

    for seed in seeds {
        let state = Arc::clone(&state);
        let main_sock = Arc::clone(&main_udp_sock);
        tokio::spawn(seed_loop(seed, state, our_ip, our_tcp_port, main_sock, seckey));
    }
}

/// Per-seed loop: do the full 3-phase handshake, then sleep, then repeat.
async fn seed_loop(
    seed: SocketAddrV4,
    state: Arc<ServerState>,
    our_ip: Ipv4Addr,
    our_tcp_port: u16,
    main_sock: Arc<UdpSocket>,
    seckey: [u8; 16],
) {
    // Stagger initial start — different seeds shouldn't all fire at once.
    let stagger = Duration::from_millis(500 + (seed.port() as u64 % 5) * 200);
    tokio::time::sleep(stagger).await;

    loop {
        match handshake_with_seed(&seed, &state, our_ip, our_tcp_port, &main_sock, &seckey).await {
            Ok((server_count, packets_received)) => {
                info!(
                    seed = %seed,
                    server_count,
                    packets_received,
                    "gossip cycle complete — full handshake succeeded"
                );
            }
            Err(e) => {
                warn!(seed = %seed, error = %e, "gossip cycle failed");
            }
        }

        tokio::time::sleep(Duration::from_secs(KEEPALIVE_SECS)).await;
    }
}

/// Full handshake against one seed. Returns the number of servers learned
/// from the obfuscated SERVER_LIST_RES reply.
async fn handshake_with_seed(
    seed: &SocketAddrV4,
    state: &Arc<ServerState>,
    our_ip: Ipv4Addr,
    our_tcp_port: u16,
    main_sock: &Arc<UdpSocket>,
    seckey: &[u8; 16],
) -> std::io::Result<(usize, usize)> {
    let seed_tcp = seed.port();
    let seed_plain_port = seed_tcp + 4;   // TCP+4 = serv_to_serv_sock
    let seed_obfping_port = seed_tcp + 12; // TCP+12 = obfpingport
    let seed_obfgossip_port = seed_tcp + 14; // TCP+14 = udpsockobf

    // ─── PHASE 1: plain bootstrap from main socket ─────────────────────────
    {
        // 0xA0 SERVER_LIST_REQ: proto + opcode + our_ip(net) + our_tcp_port(LE) + challenge
        let challenge = rand_u32();
        let mut req_a0 = Vec::with_capacity(12);
        req_a0.push(PROTO_EDONKEY);
        req_a0.push(OP_SERVER_LIST_REQ);
        req_a0.extend_from_slice(&our_ip.octets());
        req_a0.extend_from_slice(&our_tcp_port.to_le_bytes());
        req_a0.extend_from_slice(&challenge.to_le_bytes());
        let dst = SocketAddrV4::new(*seed.ip(), seed_plain_port);
        main_sock.send_to(&req_a0, SocketAddr::V4(dst)).await?;

        // 0x96 GLOBSERVSTATREQ with 0x55AA marker — asks for extended status.
        let req_96 = build_globservstatreq(PROBE_CHALLENGE);
        main_sock.send_to(&req_96, SocketAddr::V4(dst)).await?;

        info!(
            seed = %seed.ip(),
            port = seed_plain_port,
            challenge = format!("0x{:08x}", challenge),
            "gossip phase 1: plain bootstrap (0xA0+0x96) sent"
        );
    }

    // Tiny gap so the seed processes our plain packets before we ping.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // ─── PHASE 2: OBF ping from a fresh ephemeral socket ───────────────────
    let eph_sock = UdpSocket::bind("0.0.0.0:0").await?;
    let eph_port = eph_sock.local_addr()?.port();

    let random_part = rand_u32();
    let pad_len = (rand_u32() as usize) % (OBF_PING_PAYLOAD_MAX_PAD + 1);

    let mut ping = Vec::with_capacity(4 + pad_len);
    ping.extend_from_slice(&random_part.to_le_bytes());
    for _ in 0..pad_len {
        ping.push((rand_u32() & 0xFF) as u8);
    }
    // First byte must NOT collide with plain eD2k magics, or the seed routes
    // it to its plain handler instead of the OBF ping handler.
    while matches!(ping[0], 0xE3 | 0xD4 | 0xC5) {
        ping[0] = (rand_u32() & 0xFF) as u8;
    }

    let ping_dst = SocketAddrV4::new(*seed.ip(), seed_obfping_port);
    eph_sock.send_to(&ping, ping_dst).await?;

    info!(
        seed = %seed.ip(),
        dst_port = seed_obfping_port,
        eph_port,
        random_part = format!("0x{:08x}", random_part),
        pad_len,
        "gossip phase 2: OBF ping sent"
    );

    // Stash our random_part — udp.rs will need it to decode incoming
    // obfuscated frames from this seed (it encrypts replies with this value).
    state.our_sent_random_parts.insert(*seed.ip(), random_part);

    // Wait for OBF reply. Reply arrives on our ephemeral socket from seed:4673.
    let mut buf = vec![0u8; 4096];
    let (n, from) = match tokio::time::timeout(REPLY_TIMEOUT, eph_sock.recv_from(&mut buf)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            warn!(seed = %seed.ip(), eph_port, "gossip phase 2: no OBF ping reply within 5s");
            return Ok((0, 0));
        }
    };

    info!(seed = %seed.ip(), from = %from, bytes = n, "gossip phase 2: OBF reply received");

    let seed_serverkey = match decode_obf_s2s(&buf[..n], random_part) {
        Some(k) => {
            state.seed_server_keys.insert(*seed.ip(), k);
            info!(seed = %seed.ip(), server_key = format!("0x{:08x}", k),
                  "stored peer ServerKey from obf handshake");
            k
        }
        None => {
            warn!(seed = %seed.ip(), "gossip phase 2: could not decode OBF reply — aborting");
            return Ok((0, 0));
        }
    };

    // The seed just proved itself a real eD2k server via the obfuscated
    // handshake (it returned a valid ServerKey — an mldonkey CLIENT cannot do
    // this). Make sure it is actually present in `server_list`, because the
    // verified-only filters in build_tcp_server_list / build_server_list_res
    // iterate `server_list` and only THEN check seed_server_keys: an IP that is
    // not in server_list at all can never be handed out, no matter how verified.
    //
    // Plain seeds reach server_list "for free" because the other seeds advertise
    // them back to us in their 0xA1 lists (via merge_server_list). An obf-only
    // seed whose plain 0x96 port is closed (e.g. 176.123.5.89) and that returns
    // an empty server list (server_count=0) is advertised by nobody, so without
    // this it stays invisible in every server.met we distribute despite a stored
    // ServerKey. Add it here, mirroring merge_server_list's "skip current client
    // IPs" hygiene; the `contains` guard makes this idempotent across cycles.
    {
        let is_client = state.clients.iter().any(|e| {
            matches!(e.ip, std::net::IpAddr::V4(v4) if v4 == *seed.ip())
        });
        if !is_client {
            let mut list = state.server_list.write().await;
            if !list.contains(seed) {
                list.push(*seed);
                state
                    .server_list_added_at
                    .insert(*seed.ip(), std::time::Instant::now());
                info!(seed = %seed, "added verified obf-only seed to server_list");
            }
        }
    }

    // ─── PHASE 3: obfuscated gossip from SAME ephemeral socket ─────────────
    let gossip_dst = SocketAddrV4::new(*seed.ip(), seed_obfgossip_port);

    // Build plain 0xA0 SERVER_LIST_REQ (same as Phase 1 — the obfuscated wrap
    // adds the encryption header; the inner ed2k packet structure is identical).
    let challenge2 = rand_u32();
    let mut plain_a0 = Vec::with_capacity(12);
    plain_a0.push(PROTO_EDONKEY);
    plain_a0.push(OP_SERVER_LIST_REQ);
    plain_a0.extend_from_slice(&our_ip.octets());
    plain_a0.extend_from_slice(&our_tcp_port.to_le_bytes());
    plain_a0.extend_from_slice(&challenge2.to_le_bytes());

    // CRITICAL: Lugdunum's TCP+14 (udpsockobf) channel uses obfbyte = 0x6b
    // in the MD5 key derivation. The Lugdunum verbose log explicitly shows
    // "(ServerKey=0x..,6b)" for every send on this channel:
    //   - obfbyte 0xa5 = TCP+12 (obfpingport) — what we just received from
    //   - obfbyte 0x6b = TCP+14 (udpsockobf)  — what we MUST use for gossip
    //   - obfbyte 0x00 = generic plain s2s channel — what encode() defaults to
    // Sending with 0x00 to TCP+14 means the seed cannot decrypt our frame
    // and silently drops it (no error response on the wire). This was the
    // root cause of "server_count=0" for every seed despite the OBF handshake
    // succeeding — phase 3 frames reached the seed but failed decryption.
    let obf_a0 = server_obfuscation::encode_with_obfbyte(
        &plain_a0, seed_serverkey, rand_u32(), 0x6b,
    );
    eph_sock.send_to(&obf_a0, gossip_dst).await?;

    // 0xA4 — explicit "send me your server list NOW". Some Lugdunum versions
    // gate the list reply on 0xA4 (0xA0 only does the registration step).
    let mut plain_a4 = Vec::with_capacity(2);
    plain_a4.push(PROTO_EDONKEY);
    plain_a4.push(OP_SERVER_LIST_REQ2);
    let obf_a4 = server_obfuscation::encode_with_obfbyte(
        &plain_a4, seed_serverkey, rand_u32(), 0x6b,
    );
    eph_sock.send_to(&obf_a4, gossip_dst).await?;

    // 0x97 GLOBSERVSTATRES with extended 44-byte trailer (containing our
    // ServerKey for this seed). Per Lugdunum's decomp (FUN_0042b840 around
    // line 28765), entry.ServerKey is extracted from the 0x97 trailer ONLY
    // when the packet arrived obfuscated (param_2+0x18 != 0). Our PLAIN
    // 0x97 replies to seed's :96 probes don't qualify. So we additionally
    // send our 0x97 obfuscated here, on the same channel, so seed extracts
    // and stores our ServerKey. Once seed has it, seed sends us obf 0xA2
    // SERVER_DESC_REQ encrypted with it (and our decoder on :4675 derives
    // the same key from sender_ip via IPObfuscate).
    //
    // CRITICAL: the challenge in this 0x97 must match what Lugdunum stored
    // at entry+0x28 when it sent its OWN 0x96 to us. Echoing a constant
    // (e.g. PROBE_CHALLENGE) is REJECTED as "bad challenge" — seed silently
    // drops the packet without extracting our ServerKey. So we look up the
    // most recent 0x96 challenge from state.incoming_seed_challenges
    // (populated by handle_servstat). If seed hasn't probed us yet, skip
    // sending obf 0x97 from gossip — handle_servstat's synchronous obf 0x97
    // follow-up handles the case where seed *has* probed us.
    if let Some(chal_ref) = state.incoming_seed_challenges.get(seed.ip()) {
        let challenge_97 = *chal_ref;
        drop(chal_ref);
        let users    = state.client_count() as u32;
    let files    = state.file_count() as u32;
    let lowid    = state.lowid_count() as u32;
    let max_conn = 50_000u32;       // matches DEFAULT_MAX_CLIENTS
    let soft     = 7_500u32;
    let hard     = 7_500u32;
    let pingflg: u32 = 0x0000_17FB;

    // ServerKey: IPObfuscate(our_seckey, seed_ip) — what seed will use to
    // encrypt obf traffic back to us. Our :4675 decoder computes the same
    // value from sender's IP, so the keys match.
    let seed_ip_le = u32::from_le_bytes(seed.ip().octets());
    let our_server_key_for_seed = crate::proto::server_obfuscation::ip_obfuscate(
        seckey, seed_ip_le,
    );

    let mut plain_97 = Vec::with_capacity(46);
    plain_97.push(PROTO_EDONKEY);
    plain_97.push(0x97);
    plain_97.extend_from_slice(&challenge_97.to_le_bytes());
    plain_97.extend_from_slice(&users.to_le_bytes());
    plain_97.extend_from_slice(&files.to_le_bytes());
    plain_97.extend_from_slice(&max_conn.to_le_bytes());
    plain_97.extend_from_slice(&soft.to_le_bytes());
    plain_97.extend_from_slice(&hard.to_le_bytes());
    plain_97.extend_from_slice(&pingflg.to_le_bytes());
    plain_97.extend_from_slice(&lowid.to_le_bytes());
    // Extended trailer: portUDPobf + portTCPobf + ServerKey + our_ip
    plain_97.extend_from_slice(&our_tcp_port.wrapping_add(14).to_le_bytes());
    plain_97.extend_from_slice(&our_tcp_port.wrapping_add(12).to_le_bytes());
    plain_97.extend_from_slice(&our_server_key_for_seed.to_le_bytes());
    plain_97.extend_from_slice(&our_ip.octets());

    let obf_97 = server_obfuscation::encode_with_obfbyte(
        &plain_97, seed_serverkey, rand_u32(), 0x6b,
    );
    eph_sock.send_to(&obf_97, gossip_dst).await?;

    info!(
        seed = %seed.ip(),
        dst_port = seed_obfgossip_port,
        eph_port,
        server_key = format!("0x{:08x}", seed_serverkey),
        echoed_chal = format!("0x{:08x}", challenge_97),
        "gossip phase 3: obfuscated 0xA0+0xA4+0x97 sent to udpsockobf"
    );
    } else {
        debug!(
            seed = %seed.ip(),
            "gossip phase 3: skipping obf 0x97 — seed hasn't sent us a 0x96 \
             yet (no challenge to echo). The synchronous follow-up in \
             handle_servstat will send it as soon as seed probes us."
        );
    }

    // Receive the obfuscated server list reply on the SAME ephemeral socket.
    // The reply is encrypted with OUR random_part (not the seed's ServerKey).
    let mut count = 0usize;
    let mut packets_received = 0usize;
    let deadline = tokio::time::Instant::now() + REPLY_TIMEOUT;
    while let Ok(Ok((n, from))) = tokio::time::timeout_at(
        deadline,
        eph_sock.recv_from(&mut buf),
    ).await {
        packets_received += 1;
        let hex_prefix: String = buf[..n.min(24)]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        info!(seed = %seed.ip(), from = %from, bytes = n, hex_prefix = %hex_prefix,
              "gossip phase 3: reply on ephemeral socket");

        // Try to decode with our random_part (what seed encrypts replies
        // with for THIS ephemeral session) first, then with seed_serverkey
        // (used by some implementations). For each key, try the three known
        // channel markers: 0x6b (TCP+14 udpsockobf — the most likely match
        // since that's where we sent to and where the reply originated),
        // 0xa5 (TCP+12 obfpingport), and 0x00 (default encode()).
        let decoded = server_obfuscation::decode_with_obfbyte(&buf[..n], random_part, 0x6b)
            .map(|m| ("random_part+0x6b", m))
            .or_else(|| server_obfuscation::decode(&buf[..n], random_part)
                .map(|m| ("random_part+0x00", m)))
            .or_else(|| server_obfuscation::decode_with_obfbyte(&buf[..n], random_part, 0xa5)
                .map(|m| ("random_part+0xa5", m)))
            .or_else(|| server_obfuscation::decode_with_obfbyte(&buf[..n], seed_serverkey, 0x6b)
                .map(|m| ("seed_key+0x6b", m)))
            .or_else(|| server_obfuscation::decode(&buf[..n], seed_serverkey)
                .map(|m| ("seed_key+0x00", m)))
            .or_else(|| server_obfuscation::decode_with_obfbyte(&buf[..n], seed_serverkey, 0xa5)
                .map(|m| ("seed_key+0xa5", m)));

        if let Some((method, inner)) = decoded {
            info!(seed = %seed.ip(), method, msg_len = inner.len(),
                  proto = format!("0x{:02x}", inner.first().copied().unwrap_or(0)),
                  opcode = format!("0x{:02x}", inner.get(1).copied().unwrap_or(0)),
                  "gossip phase 3: decoded reply");
            if inner.len() >= 3 && inner[0] == PROTO_EDONKEY && inner[1] == OP_SERVER_LIST_RES {
                if let Some(list) = parse_server_list_res(&inner) {
                    count = list.len();
                    merge_server_list(state, list).await;
                    info!(
                        seed = %seed.ip(),
                        count,
                        "gossip phase 3: server list received and merged"
                    );
                    break;
                }
            }
        } else {
            info!(seed = %seed.ip(),
                  "gossip phase 3: undecodable reply — tried all 6 key+obfbyte combinations");
        }
    }

    Ok((count, packets_received))
}

/// Build a GLOBSERVSTATREQ packet: proto(0xE3) + opcode(0x96) + challenge(4 LE).
fn build_globservstatreq(challenge: u32) -> Vec<u8> {
    let mut p = Vec::with_capacity(6);
    p.push(PROTO_EDONKEY);
    p.push(OP_GLOB_SERVSTATREQ);
    p.extend_from_slice(&challenge.to_le_bytes());
    p
}

/// Parse SERVER_LIST_RES (0xA1): proto(1) + opcode(1) + count(1) + (ip(4) port(2 LE))[count]
pub fn parse_server_list_res(data: &[u8]) -> Option<Vec<SocketAddrV4>> {
    if data.len() < 3 { return None; }
    if data[0] != PROTO_EDONKEY || data[1] != OP_SERVER_LIST_RES { return None; }
    let count = data[2] as usize;
    if data.len() < 3 + count * 6 { return None; }

    let mut servers = Vec::with_capacity(count);
    let mut pos = 3;
    for _ in 0..count {
        let ip = Ipv4Addr::new(data[pos], data[pos+1], data[pos+2], data[pos+3]);
        let port = u16::from_le_bytes([data[pos+4], data[pos+5]]);
        pos += 6;
        if port > 0 && !ip.is_unspecified() && !ip.is_loopback() {
            servers.push(SocketAddrV4::new(ip, port));
        }
    }
    Some(servers)
}

async fn merge_server_list(state: &Arc<ServerState>, new_list: Vec<SocketAddrV4>) {
    const CLIENT_BLOCK_TTL: std::time::Duration = std::time::Duration::from_secs(30 * 60);

    // Purge stale entries from recent_client_ips (older than 30 minutes).
    state.recent_client_ips.retain(|_, ts| ts.elapsed() < CLIENT_BLOCK_TTL);

    // Build the full set of IPs to block: currently connected clients +
    // recently seen clients (within TTL). This catches mldonkey that registered
    // to seeds, disconnected from us, and whose IP then comes back in a seed's
    // 0xA1 server list.
    let blocked_ips: std::collections::HashSet<std::net::Ipv4Addr> = {
        let mut set = std::collections::HashSet::new();
        // Currently connected
        for e in state.clients.iter() {
            if let std::net::IpAddr::V4(v4) = e.ip { set.insert(v4); }
        }
        // Recently connected (within TTL)
        for e in state.recent_client_ips.iter() {
            set.insert(*e.key());
        }
        set
    };

    let mut list = state.server_list.write().await;
    // Purge stale client IPs that leaked into server_list previously.
    let before_purge = list.len();
    list.retain(|s| !blocked_ips.contains(s.ip()));
    let purged = before_purge - list.len();
    if purged > 0 {
        info!(purged, "merge_server_list: removed stale client IPs");
    }
    let existing: std::collections::HashSet<_> = list.iter().copied().collect();
    let before = list.len();
    for addr in new_list {
        let ip = *addr.ip();
        // Drop private, loopback, multicast, broadcast, and client IPs.
        if ip.is_private() || ip.is_loopback() || ip.is_unspecified()
            || ip.is_multicast() || ip.is_broadcast()
            || blocked_ips.contains(&ip)
        {
            continue;
        }
        if !existing.contains(&addr) {
            list.push(addr);
            state.server_list_added_at.insert(*addr.ip(), std::time::Instant::now());
        }
    }
    let added = list.len() - before;
    if added > 0 {
        info!(total = list.len(), added, "gossip: server list updated");
    }
}

/// Build TCP SERVER_LIST_RES payload for OP_SERVERLIST response to clients.
///
/// Only VERIFIED servers are handed out. A server counts as verified if it
/// proved itself a real eD2k server in EITHER of two ways:
///   1. it answered our plain 0x96 GLOBSERVSTATREQ with a 0x97 → recorded in
///      `verified_servers`; or
///   2. it completed an OBFUSCATED handshake, giving us its ServerKey →
///      recorded in `seed_server_keys`.
/// Both are things an mldonkey CLIENT advertising itself as a server cannot do,
/// so this is the reliable mldonkey filter. Case (2) matters because some real
/// servers answer ONLY on their obfuscated port (their plain 0x96 port is
/// closed/filtered); keying verification on plain 0x97 alone wrongly dropped
/// them (observed with 176.123.5.89, which speaks only obfuscated).
pub async fn build_tcp_server_list(state: &ServerState) -> Vec<u8> {
    let list = state.server_list.read().await;
    let verified: Vec<&SocketAddrV4> = list
        .iter()
        .filter(|addr| {
            state.verified_servers.contains_key(addr.ip())
                || state.seed_server_keys.contains_key(addr.ip())
        })
        .take(255)
        .collect();
    let count = verified.len().min(255) as u8;
    let mut out = vec![count];
    for addr in verified {
        out.extend_from_slice(&addr.ip().octets());
        out.extend_from_slice(&addr.port().to_le_bytes());
    }
    out
}

/// Build UDP SERVER_LIST_RES payload for 0xA0/0xA4 requests from other servers.
/// Same verified-only policy as `build_tcp_server_list` (plain 0x97 OR obf
/// handshake) — we never propagate an unverified (possibly mldonkey) IP.
pub async fn build_server_list_res(state: &ServerState) -> Vec<u8> {
    let list = state.server_list.read().await;
    let verified: Vec<&SocketAddrV4> = list
        .iter()
        .filter(|addr| {
            state.verified_servers.contains_key(addr.ip())
                || state.seed_server_keys.contains_key(addr.ip())
        })
        .take(255)
        .collect();
    let count = verified.len().min(255) as u8;
    let mut out = vec![PROTO_EDONKEY, OP_SERVER_LIST_RES, count];
    for addr in verified {
        out.extend_from_slice(&addr.ip().octets());
        out.extend_from_slice(&addr.port().to_le_bytes());
    }
    out
}

fn rand_u32() -> u32 {
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
        if s == 0 { s = 0x0BAD_F00D; }
        c.set(s);
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_seed_works() {
        assert_eq!(
            parse_seed("1.2.3.4:5687"),
            Some(SocketAddrV4::new(Ipv4Addr::new(1,2,3,4), 5687))
        );
        assert_eq!(parse_seed("not-an-ip"), None);
        assert_eq!(parse_seed("1.2.3.4"), None);
    }

    #[test]
    fn parse_server_list_res_works() {
        // count=2, two servers
        let mut data = vec![PROTO_EDONKEY, OP_SERVER_LIST_RES, 2];
        // server 1: 1.2.3.4:5687
        data.extend_from_slice(&[1,2,3,4]);
        data.extend_from_slice(&5687u16.to_le_bytes());
        // server 2: 10.20.30.40:4661
        data.extend_from_slice(&[10,20,30,40]);
        data.extend_from_slice(&4661u16.to_le_bytes());
        let r = parse_server_list_res(&data).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0], SocketAddrV4::new(Ipv4Addr::new(1,2,3,4), 5687));
        assert_eq!(r[1], SocketAddrV4::new(Ipv4Addr::new(10,20,30,40), 4661));
    }
}

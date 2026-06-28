//! UDP listener (SPEC.md §3.8, §3.10).
//!
//! Handles 96% of real server traffic (empirical, §A.7):
//!
//!   0x9A  GLOBGETSOURCES     — single-hash source lookup
//!   0x94  GLOBGETSOURCES2    — packed multi-hash source lookup (up to 33 hashes)
//!   0x96  GLOBSERVSTATREQ    — server status / load probe
//!   0xA2  SERVER_DESC_REQ    — server name + description
//!   0x98  GLOBSEARCHREQ      — UDP search (limited results)
//!   0x90  GLOBSEARCHREQ3     — UDP search with leading tagset (ignored for now)
//!
//! All responses are sent back to the originating address as individual
//! datagrams (UDP is connectionless, no state retained per sender).
//!
//! Protocol marker for all UDP eD2k frames: 0xE3.
//! UDP frames have no length prefix — each datagram is exactly one frame.

use crate::config::Config;
use crate::proto::{
    opcodes::*,
    search::{collect_terms, evaluate, parse as parse_search},
    tags::{write_tag_list, Tag, TagValue},
};
use crate::state::ServerState;
use anyhow::Result;
use bytes::{BufMut, BytesMut};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// Maximum sources returned in a single UDP GLOBFOUNDSOURCES response.
const UDP_MAX_SOURCES: usize = 30;

/// Maximum search results in a single UDP GLOBSEARCHRES response.
const UDP_MAX_SEARCH_RESULTS: usize = 10;

pub struct UdpServer {
    cfg: Arc<Config>,
    state: Arc<ServerState>,
    socket: Arc<UdpSocket>,
    /// 16-byte secret for server-to-server UDP obfuscation. Resolved once
    /// at bind time from config (hex string) or randomly generated.
    seckey: [u8; 16],
}

/// Resolve the 16-byte server secret from config. Accepts a 32-char hex
/// string; falls back to a process-random key if unset or malformed.
/// Call ONCE in main and pass the result to all UDP listeners so they
/// share a consistent key (all three listeners must derive the same
/// per-peer keys, or the server can't decrypt its own peers consistently).
/// Derive the server-to-server obfuscation secret from **server IP + TCP port
/// only**. The seckey seeds per-peer ServerKeys = IPObfuscate(seckey, peer_ip),
/// which seeds cache; it must be STABLE for a given identity so caches stay
/// valid across restarts, and must ROTATE when the identity genuinely changes.
///
/// IP+port *is* the server's network identity: a different IP or port is, for
/// all practical purposes, a different server, so rotating the seckey then is
/// correct and happens automatically. Crucially the key does NOT depend on the
/// server name/description, so renaming the server no longer breaks the
/// obfuscation handshake. It is never read from or written to config — it is
/// purely derived and shown only in the web UI.
///
/// The key is not cryptographically secret; it only needs to be stable.
///
/// `this_ip` must be set in config (a mandatory setup parameter). If it cannot
/// be determined, we fall back to a port-only key and warn — degraded but
/// functional, so the server still starts.
pub fn resolve_seckey(cfg: &Config) -> [u8; 16] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let ip = cfg.server.this_ip.trim();
    let have_ip = !ip.is_empty() && ip != "0.0.0.0";
    if !have_ip {
        tracing::warn!(
            "server.this_ip is not set — deriving seckey from TCP port only \
             (degraded). Set this_ip in config: it is required for a stable \
             obfuscation seckey."
        );
    }

    // Two independent hashes fill the 16-byte key. Both fold in the IP (when
    // known) and the TCP port, with a small offset on the second so the halves
    // differ. No server name/desc — rename must not change the key.
    let mut h1 = DefaultHasher::new();
    if have_ip {
        ip.hash(&mut h1);
    }
    cfg.network.tcp_port.hash(&mut h1);
    let v1 = h1.finish();

    let mut h2 = DefaultHasher::new();
    cfg.network.tcp_port.wrapping_add(0x9E37).hash(&mut h2);
    if have_ip {
        ip.hash(&mut h2);
    }
    let v2 = h2.finish();

    let mut key = [0u8; 16];
    key[..8].copy_from_slice(&v1.to_le_bytes());
    key[8..].copy_from_slice(&v2.to_le_bytes());
    key
}

impl UdpServer {
    pub async fn bind(cfg: Arc<Config>, state: Arc<ServerState>, seckey: [u8; 16]) -> Result<Self> {
        let bind_addr = format!("{}:{}", cfg.network.listen_ip, cfg.network.udp_port);
        let socket = UdpSocket::bind(&bind_addr).await?;
        tracing::info!(addr = %bind_addr, "UDP listener ready");
        let socket = Arc::new(socket);
        state.udp_sockets.insert(cfg.network.udp_port, Arc::clone(&socket));
        Ok(Self {
            cfg,
            state,
            socket,
            seckey,
        })
    }

    /// Bind an additional UDP listener on a specific port — used for Lugdunum-style
    /// multi-channel UDP (port_4669 = TCP+8, portUDPobf = TCP+14).
    /// All listeners share the same dispatch logic.
    pub async fn bind_on_port(
        cfg: Arc<Config>,
        state: Arc<ServerState>,
        port: u16,
        seckey: [u8; 16],
    ) -> Result<Self> {
        let bind_addr = format!("{}:{}", cfg.network.listen_ip, port);
        let socket = UdpSocket::bind(&bind_addr).await?;
        tracing::info!(addr = %bind_addr, "additional UDP listener ready");
        let socket = Arc::new(socket);
        state.udp_sockets.insert(port, Arc::clone(&socket));
        Ok(Self {
            cfg,
            state,
            socket,
            seckey,
        })
    }

    /// Returns a clone of the shared UDP socket.
    /// Used by gossip to send requests FROM the server's real UDP port (4665)
    /// so that seed servers recognise us as a valid eD2k server.
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    pub async fn run(self) {
        let mut buf = vec![0u8; 65535];
        loop {
            let (len, peer) = match self.socket.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => { warn!(error = %e, "UDP recv error"); continue; }
            };

            let data = &buf[..len];
            if data.len() < 2 { continue; }

            // Drop datagrams from temporarily-banned flood bots BEFORE any
            // parsing, crypto, or response. One DashMap lookup; the bot's entire
            // flood becomes essentially free. Ban is set by the bot detector
            // (24h TTL, swept by the 60s cleanup task).
            if let std::net::IpAddr::V4(v4) = peer.ip() {
                if self.state.is_bot_banned(&v4) {
                    continue;
                }
            }

            // Plain eD2k datagram — first byte is the 0xE3 proto marker.
            // Anything else MAY be an obfuscated server-to-server datagram:
            // try to decrypt it with the key derived from our seckey and the
            // sender's IP. If that fails, drop it (it's noise or not for us).
            let (opcode, payload, decoded_buf);
            if data[0] == PROTO_EDONKEY {
                opcode = data[1];
                payload = &data[2..];
            } else {
                // Pre-flight: obfuscated packets are AT LEAST 10 bytes (1B random
                // pad + 2B salt + 4B magic + 1B padlen + 2B inner). Anything
                // shorter is definitely garbage; skip all crypto. Same for
                // suspiciously-large junk (>2KB is never an obf s2s packet in
                // practice — the typical obfuscated 0xA1 reply is ~50-300B).
                if data.len() < 10 || data.len() > 1500 {
                    continue;
                }

                // Obfuscated path.
                let sender_ip_le = match peer.ip() {
                    std::net::IpAddr::V4(v4) => u32::from_le_bytes(v4.octets()),
                    _ => { continue; } // eD2k is IPv4-only
                };
                let sender_v4 = match peer.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => { continue; }
                };

                // Try multiple key+formula combinations to decode the packet.
                // Seeds can use different obfuscation channels depending on
                // which socket they're replying from.
                //
                // Formula A (derive_cipher): MD5(key || salt || 0x00) — our main s2s encode/decode
                // Formula B (decode_with_obfbyte 0xa5): MD5(key || 0xa5 || salt) — obfpingport replies
                // Formula B (decode_with_obfbyte 0x6b): MD5(key || 0x6b || salt) — portUDPobf
                //
                // Keys to try (in order):
                //  1. our_sent_random_parts[sender] — what seed uses after OBF ping
                //  2. seed_server_keys[sender]      — seed's ServerKey we learned
                //  3. ip_obfuscate(our_seckey, sender_ip) — fallback for unknown senders
                //
                // OPTIMIZATION (v0.9.31): cache the (key, formula) tuple that
                // last worked for this sender. Trying it first turns a typical
                // 9-attempt decode into 1 attempt for legitimate peers, saving
                // ~8 MD5+RC4 ops per packet on the hot path.

                use crate::proto::server_obfuscation::{decode, decode_with_obfbyte, ip_obfuscate};

                #[derive(Clone, Copy, PartialEq)]
                enum Formula { Plain, ObfA5, Obf6B }
                fn try_decode(data: &[u8], key: u32, f: Formula) -> Option<Vec<u8>> {
                    let inner = match f {
                        Formula::Plain => decode(data, key)?,
                        Formula::ObfA5 => decode_with_obfbyte(data, key, 0xa5)?,
                        Formula::Obf6B => decode_with_obfbyte(data, key, 0x6b)?,
                    };
                    if inner.len() >= 2 && inner[0] == PROTO_EDONKEY {
                        Some(inner)
                    } else { None }
                }

                let last = self.state.obf_decode_cache.get(&sender_v4).map(|e| *e);

                // First: try the cached (key, formula) if any — covers 99% of legit packets.
                let mut decoded_opt = last.and_then(|(k, f)| {
                    let formula = match f {
                        0 => Formula::Plain,
                        1 => Formula::ObfA5,
                        _ => Formula::Obf6B,
                    };
                    try_decode(data, k, formula)
                });

                // Cold path: cache miss or stale entry — enumerate combinations.
                if decoded_opt.is_none() {
                    let ip_obf_key = ip_obfuscate(&self.seckey, sender_ip_le);
                    let keys_to_try: [Option<u32>; 3] = [
                        self.state.our_sent_random_parts.get(&sender_v4).map(|r| *r),
                        self.state.seed_server_keys.get(&sender_v4).map(|r| *r),
                        Some(ip_obf_key),
                    ];
                    let formulas = [Formula::Plain, Formula::ObfA5, Formula::Obf6B];
                    'outer: for &kopt in &keys_to_try {
                        let Some(k) = kopt else { continue };
                        for &f in &formulas {
                            // Skip the combination we already tried as the cached one.
                            if let Some((lk, lf)) = last {
                                let fnum = match f {
                                    Formula::Plain => 0u8,
                                    Formula::ObfA5 => 1u8,
                                    Formula::Obf6B => 2u8,
                                };
                                if lk == k && lf == fnum { continue; }
                            }
                            if let Some(inner) = try_decode(data, k, f) {
                                decoded_opt = Some(inner);
                                // Remember what worked so the next packet hits the fast path.
                                let fnum = match f {
                                    Formula::Plain => 0u8,
                                    Formula::ObfA5 => 1u8,
                                    Formula::Obf6B => 2u8,
                                };
                                self.state.obf_decode_cache.insert(sender_v4, (k, fnum));
                                break 'outer;
                            }
                        }
                    }
                }

                match decoded_opt {
                    Some(inner) => {
                        debug!(ip = %peer.ip(), "decoded obfuscated server-to-server UDP");
                        decoded_buf = inner;
                        opcode = decoded_buf[1];
                        payload = &decoded_buf[2..];
                    }
                    None => {
                        // Could not decode. The most important case here is
                        // an INBOUND OBF PING: a peer Lugdunum server sends
                        // 4 bytes of random_part + up to 14 bytes of padding
                        // to our TCP+12 (obfpingport). These bytes are NOT
                        // obfuscated eD2k — they ARE the random_part itself,
                        // delivered in cleartext. The peer expects us to
                        // reply with an obfuscated 0x97 GLOBSERVSTATRES
                        // encrypted using their random_part as the key.
                        //
                        // Without this reply, the peer never completes the
                        // obfuscated round-trip with us and won't propagate
                        // our IP in its 0xA1 responses to clients (this is
                        // the verification step Lugdunum requires before a
                        // peer "trusts" a new server for propagation).
                        //
                        // Heuristic: short packet (4..=18 bytes), not a
                        // plain eD2k frame (we're already in the obfuscated
                        // branch), arriving on our obfpingport (TCP+12).
                        let local_port = self.socket.local_addr()
                            .map(|a| a.port())
                            .unwrap_or(0);
                        let our_tcp_port = self.cfg.network.tcp_port;
                        let is_obfping_port = local_port == our_tcp_port.wrapping_add(12);
                        if is_obfping_port && (4..=18).contains(&data.len()) {
                            // Extract peer's random_part (first 4 bytes, LE).
                            let random_part = u32::from_le_bytes([
                                data[0], data[1], data[2], data[3],
                            ]);
                            if let Err(e) = self
                                .reply_to_obf_ping(peer, random_part)
                                .await
                            {
                                debug!(ip = %peer.ip(), error = %e,
                                       "failed to send OBF ping reply");
                            } else {
                                info!(
                                    ip = %peer.ip(),
                                    eph_port = peer.port(),
                                    random_part = format!("0x{:08x}", random_part),
                                    "replied to inbound OBF ping with obfuscated 0x97"
                                );
                            }
                            continue;
                        }

                        // Other undecodable: log if from a known seed,
                        // otherwise silently drop.
                        if self.state.our_sent_random_parts.contains_key(&sender_v4)
                            || self.state.seed_server_keys.contains_key(&sender_v4)
                        {
                            debug!(
                                ip = %peer.ip(),
                                pkt_len = data.len(),
                                hex3 = format!("{:02x}{:02x}{:02x}", data[0], data[1], data.get(2).copied().unwrap_or(0)),
                                "UDP: known seed sent undecodable obfuscated packet"
                            );
                        }
                        continue;
                    }
                }
            }

            if let Err(e) = self.dispatch(opcode, payload, peer).await {
                if tracing::enabled!(tracing::Level::DEBUG) {
                    debug!(ip = %peer.ip(), opcode = format!("0x{opcode:02x}"), error = %e, "UDP handler error");
                }
            }
        }
    }

    async fn dispatch(&self, opcode: u8, payload: &[u8], peer: SocketAddr) -> Result<()> {
        if tracing::enabled!(tracing::Level::DEBUG) {
            debug!(
                ip = %peer.ip(),
                opcode = format!("0x{opcode:02x}"),
                len = payload.len(),
                "UDP frame in"
            );
        }

        // Track CLIENT IPs that send UDP-only queries. Opcodes 0x9A, 0x94, 0x98,
        // 0x90 are CLIENT-ONLY operations (search, get_sources) — servers never
        // send these. By recording the source IP we can filter it out of our
        // gossip server_list, preventing mldonkey/eMule UDP-only clients that
        // skip TCP login from appearing as "peer servers".
        match opcode {
            OP_GLOB_GETSOURCES | OP_GLOB_GETSOURCES2
            | OP_GLOB_SEARCHREQ | OP_GLOB_SEARCHREQ3 => {
                if let std::net::IpAddr::V4(v4) = peer.ip() {
                    self.state.recent_client_ips.insert(v4, std::time::Instant::now());
                    // Bot detector: track query rate and interval patterns.
                    crate::server::bot_detector::record_query(&self.state, v4);
                    // NAT-traversal: remember the EXTERNAL (post-NAT) UDP port this
                    // client just sent from. handle_holepunch_request prefers this
                    // observed port over the client-announced (internal) one when
                    // building OP_LOWID_HOLEPUNCH_INFO, so the peer punches the port
                    // the NAT actually opened. Cone NATs reuse this port toward the
                    // peer; symmetric NATs don't, and there we fall back gracefully.
                    self.state.observed_udp_ports.insert(v4, (peer.port(), std::time::Instant::now()));
                }
            }
            _ => {}
        }

        match opcode {
            OP_GLOB_GETSOURCES   => self.handle_getsources_single(payload, peer).await,
            OP_GLOB_GETSOURCES2  => self.handle_getsources_multi(payload, peer).await,
            OP_SERVER_NATT_KEEPALIVE => {
                // NAT-traversal keepalive: payload is the sender's 16-byte
                // userhash. Record the EXTERNAL UDP port we saw it arrive from
                // (peer.port()) directly on the client's handle, so a later
                // HOLEPUNCH_INFO hands peers the port the NAT actually opened.
                // Binding by userhash (not IP) keeps it correct when several
                // clients sit behind one NAT IP. This is the path that makes a
                // LowID *source* (which never sends source queries) reachable.
                if payload.len() >= 16 {
                    let mut uh = [0u8; 16];
                    uh.copy_from_slice(&payload[..16]);
                    let matched = if let Some(mut h) = self.state.clients.get_mut(&uh) {
                        h.udp_port = peer.port();
                        // Count this UDP keepalive as client activity so the TCP
                        // connection task's idle timer is reset. A NAT-T LowID
                        // source is otherwise silent on TCP and would be wrongly
                        // evicted after the idle timeout despite a live link.
                        h.touch_activity();
                        true
                    } else {
                        false
                    };
                    // DIAGNOSTIC: shows in the server log whether NAT-T keepalives
                    // actually arrive and whether the userhash matches a connected
                    // client. If you see "matched=false", the hash in the packet
                    // differs from the login hash (so the wrong client is kept
                    // warm). If you see no line at all every ~2 min, the keepalive
                    // never reaches the server (wrong UDP port / NAT / firewall).
                    info!(
                        ip = %peer.ip(),
                        udp_src_port = peer.port(),
                        user_hash = hex::encode(uh),
                        matched,
                        "NAT-T keepalive received"
                    );
                    if let std::net::IpAddr::V4(v4) = peer.ip() {
                        self.state.observed_udp_ports.insert(v4, (peer.port(), std::time::Instant::now()));
                    }
                }
                Ok(())
            }
            OP_GLOB_SERVSTATREQ  => self.handle_servstat(payload, peer).await,
            // 0x97 = GLOBSERVSTATRES — seed server responding to our keepalive ping
            0x97 => self.handle_pingreply(payload, peer).await,
            OP_SERVER_DESC_REQ   => self.handle_server_desc(payload, peer).await,
            OP_GLOB_SEARCHREQ    => self.handle_search(payload, peer).await,
            OP_GLOB_SEARCHREQ3   => self.handle_search(payload, peer).await,
            // 0xA1 SERVER_LIST_RES — response to our gossip SERVER_LIST_REQ.
            // Seed servers send this back after we query them on startup.
            0xA1 => self.handle_server_list_res(payload, peer).await,
            // SERVER_LIST_REQ (0xA0): other server registers with us (includes their ip+port).
            // After registering them, Lugdunum falls through to 0xA4 and sends our list back.
            // We replicate this: register + send list.
            0xA0 => {
                // The payload is: their_ip(4 LE) + their_port(2 LE) [+ optional extras]
                // We just note they exist and send our list back.
                // (Full ServerAdd logic would add them to our peer table — MVP: skip)
                let data = crate::server::gossip::build_server_list_res(&self.state).await;
                if data.len() > 3 { // only send if we have servers
                    self.socket.send_to(&data, peer).await?;
                    debug!(ip = %peer.ip(), "server_list_req(0xA0): registered + sent list");
                }
                Ok(())
            }
            other => {
                if tracing::enabled!(tracing::Level::DEBUG) {
                    debug!(ip = %peer.ip(), opcode = format!("0x{other:02x}"), "UDP: unhandled opcode");
                }
                Ok(())
            }
        }
    }

    // ─── GLOBGETSOURCES (0x9A) ──────────────────────────────────────────────

    /// Single-hash source lookup. Payload: hash(16) [+ size_lo(4) [+ size_hi(4)]]
    async fn handle_getsources_single(&self, payload: &[u8], peer: SocketAddr) -> Result<()> {
        if payload.len() < 16 { return Ok(()); }
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&payload[..16]);
        self.send_found_sources(&hash, peer).await
    }

    // ─── GLOBGETSOURCES2 (0x94) ─────────────────────────────────────────────

    /// Multi-hash source lookup (SPEC.md §2.3.3, variant A or B).
    ///
    /// Variant A (observed in production): packed list of N × 16-byte hashes.
    /// Variant B (newer clients):          hash(16) + size_lo(4) [+ size_hi(4)].
    ///
    /// Distinguish: if (payload.len() % 16 == 0) → variant A, else → variant B.
    async fn handle_getsources_multi(&self, payload: &[u8], peer: SocketAddr) -> Result<()> {
        if payload.len() < 16 { return Ok(()); }

        if payload.len() % 16 == 0 {
            // Variant A: packed hashes
            let count = payload.len() / 16;
            for i in 0..count {
                let mut hash = [0u8; 16];
                hash.copy_from_slice(&payload[i * 16..(i + 1) * 16]);
                self.send_found_sources(&hash, peer).await?;
            }
        } else {
            // Variant B: single hash + size
            let mut hash = [0u8; 16];
            hash.copy_from_slice(&payload[..16]);
            self.send_found_sources(&hash, peer).await?;
        }

        Ok(())
    }

    /// Look up sources for a file hash and send GLOBFOUNDSOURCES response.
    async fn send_found_sources(&self, hash: &[u8; 16], peer: SocketAddr) -> Result<()> {
        let sources: Vec<(std::net::IpAddr, u16)> = self.state
            .file_slab
            .get_by_hash(hash)
            .map(|e| {
                e.sources.iter()
                    .take(UDP_MAX_SOURCES)
                    .map(|s| (s.ip(), s.port()))
                    .collect()
            })
            .unwrap_or_default();

        // Build GLOBFOUNDSOURCES: E3 0x9B hash(16) count(1) sources…
        let mut out = BytesMut::new();
        out.put_u8(PROTO_EDONKEY);
        out.put_u8(OP_GLOB_FOUNDSOURCES);
        out.put_slice(hash);
        out.put_u8(sources.len() as u8);
        for (ip, port) in &sources {
            let id = match ip {
                std::net::IpAddr::V4(v4) => u32::from_le_bytes(v4.octets()),
                _ => 0,
            };
            out.put_u32_le(id);
            out.put_u16_le(*port);
        }

        self.socket.send_to(&out, peer).await?;
        if tracing::enabled!(tracing::Level::DEBUG) {
            debug!(ip = %peer.ip(), hash = hex::encode(hash), sources = sources.len(), "glob_getsources");
        }
        Ok(())
    }

    // ─── GLOBSERVSTATREQ (0x96) ─────────────────────────────────────────────

    /// Server status probe. Payload: challenge(4).
    ///
    /// Lugdunum sends TWO forms (from eserver.c line 11102-11120):
    ///   SHORT (12 bytes payload): when challenge bytes [2:3] != 0x55AA
    ///     → challenge(4) + users(4) + files(4)
    ///   FULL  (32 bytes payload): when challenge bytes [2:3] == 0x55AA or obfuscated
    ///     → challenge(4)+users(4)+files(4)+maxconn(4)+soft(4)+hard(4)+pingflg(4)+lowid(4)
    ///
    /// The 0x55AA magic identifies server-to-server probes (sendping() in Lugdunum
    /// always puts 0x55AA at challenge bytes [2:3]). eMule clients use random challenge.
    async fn handle_servstat(&self, payload: &[u8], peer: SocketAddr) -> Result<()> {
        let challenge = if payload.len() >= 4 {
            u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
        } else {
            0
        };

        let users    = self.state.client_count() as u32;
        let files    = self.state.file_count() as u32;
        let lowid    = self.state.lowid_count() as u32;
        // Read limits from live_cfg (hot-reloadable via /api/config).
        let live = self.state.live_cfg.load();
        let max_conn = live.limits.max_clients;
        let soft     = live.limits.soft_limit_files;
        let hard     = live.limits.hard_limit_files;
        // Full capability flags — matches Lugdunum 17.15 (0x17fb observed in captures)
        let pingflg: u32 = 0x0000_17FB;

        // Check for server-to-server magic: challenge bytes [2:3] == 0x55AA
        // (payload[2] == 0xAA, payload[3] == 0x55 in LE)
        let is_server_probe = payload.len() >= 4
            && payload[2] == 0xAA && payload[3] == 0x55;

        let mut out = BytesMut::new();
        out.put_u8(PROTO_EDONKEY);
        out.put_u8(OP_GLOB_SERVSTATRES);
        out.put_u32_le(challenge);
        out.put_u32_le(users);
        out.put_u32_le(files);

        if is_server_probe {
            // EXTENDED form — matches the 44-byte payload real Lugdunum
            // servers send each other (confirmed from pcap captures of
            // Lugdunum ↔ Lugdunum traffic). When a peer probes us with
            // 0x96 + 0x55AA marker, it expects all 11 fields, including
            // OUR ServerKey at offset 36. Without ServerKey, peers see
            // us as a non-obfuscation-capable server and refuse to
            // propagate our IP in their 0xA1 responses to their clients.
            //
            // Layout (44 bytes, matching captured Lugdunum sendping reply):
            //   [0..4]   challenge (echoed)
            //   [4..8]   users
            //   [8..12]  files
            //   [12..16] max_conn
            //   [16..20] soft_limit
            //   [20..24] hard_limit
            //   [24..28] pingflg
            //   [28..32] lowid
            //   [32..34] portUDPobf  (our TCP port + 14 = udpsockobf)
            //   [34..36] portTCPobf  (our TCP port + 12 = obfpingport)
            //   [36..40] ServerKey   ← THE KEY FIELD
            //   [40..44] our_ip      (network byte order, per Lugdunum)
            out.put_u32_le(max_conn);
            out.put_u32_le(soft);
            out.put_u32_le(hard);
            out.put_u32_le(pingflg);
            out.put_u32_le(lowid);

            // portUDPobf = TCP_port + 14 (udpsockobf channel)
            // portTCPobf = TCP_port + 12 (obfpingport channel)
            let tcp_port = self.cfg.network.tcp_port;
            out.put_u16_le(tcp_port.wrapping_add(14));
            out.put_u16_le(tcp_port.wrapping_add(12));

            // KEY field: peers use this to encrypt obfuscated UDP traffic
            // back to us on :4675. Lugdunum semantics (from eserver.c
            // disasm): the RECEIVER of an OBF ping computes
            // `IPObfuscate(my_seckey, PEER_ip)` and publishes it. The peer
            // then encrypts with this key when sending back; we decrypt by
            // independently computing the same value from peer_ip (this is
            // why our :4675 decoder already does `IPObfuscate(our_seckey,
            // sender_ip)` for each inbound obf packet — they match).
            //
            // EARLIER MISTAKE (fixed): publishing
            // `IPObfuscate(our_seckey, our_ip)` — that's a CONSTANT
            // independent of the peer, and peers using it to encrypt their
            // replies produced packets we couldn't decrypt because our
            // decoder uses `IPObfuscate(our_seckey, peer_ip)`.
            let peer_ip_le = match peer.ip() {
                std::net::IpAddr::V4(v4) => u32::from_le_bytes(v4.octets()),
                _ => 0,
            };
            let our_server_key = crate::proto::server_obfuscation::ip_obfuscate(
                &self.seckey, peer_ip_le,
            );
            out.put_u32_le(our_server_key);

            // Trailer: our own public IP (network byte order). Matches what
            // captured Lugdunum 0x97 extended replies put here.
            let our_ip: std::net::Ipv4Addr = self.cfg.server.this_ip
                .parse()
                .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

            // Our IP — Lugdunum embeds the recipient's view of the
            // sender's IP here. Using our own public IP matches what
            // captured Lugdunum replies do.
            out.extend_from_slice(&our_ip.octets());

            // Save seed's challenge for gossip Phase 3 to echo in its own
            // unsolicited obf 0x97. Lugdunum's 0x97 handler rejects any
            // 0x97 whose challenge doesn't match `entry+0x28` (the chal
            // Lugdunum stored when it sent the 0x96). Without this map,
            // gossip can only use a placeholder (which gets rejected).
            if let std::net::IpAddr::V4(v4) = peer.ip() {
                self.state.incoming_seed_challenges.insert(v4, challenge);
            }
        }
        // Short form: 12 bytes payload (just challenge+users+files)

        self.socket.send_to(&out, peer).await?;

        // After replying plain to a server probe (0x55AA marker), ALSO send
        // an OBFUSCATED copy of the same 0x97 to seed's portUDPobf if we
        // have seed's ServerKey on hand. This is the only way Lugdunum will
        // extract our ServerKey/portUDPobf/portTCPobf from our reply:
        //
        //   - Lugdunum's 0x97 handler (FUN_0042b840 line 28768) extracts the
        //     extended trailer fields (UDPobf, TCPobf, ServerKey) only when
        //     `*(param_2 + 0x18) != 0` — the "packet arrived obfuscated"
        //     flag. Our PLAIN 0x97 to peer:4665 doesn't qualify.
        //
        //   - Lugdunum's challenge gate (~line 28741) requires the echoed
        //     challenge to match entry.our_outgoing_chal (+0x28), which is
        //     the value Lugdunum picked when it sent us THIS 0x96. We have
        //     that value right here in `challenge`.
        //
        // So we send the same extended 0x97 bytes obfuscated to peer:5701
        // (peer_TCP+14 = src_udp+10 since src_udp = peer_TCP+4 for plain
        // probes from serv_to_serv_sock).
        if is_server_probe {
            let peer_ip_v4 = match peer.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => return Ok(()),
            };
            if let Some(seed_key_ref) = self.state.seed_server_keys.get(&peer_ip_v4) {
                let seed_key = *seed_key_ref;
                drop(seed_key_ref);

                // src_udp = peer_TCP+4 (plain probe channel)
                // peer_TCP = src_udp - 4
                // peer_portUDPobf = peer_TCP + 14 = src_udp + 10
                let dst_obf_port = peer.port().wrapping_add(10);
                let dst_obf = std::net::SocketAddr::new(peer.ip(), dst_obf_port);

                let rng_seed = {
                    let nanos = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.subsec_nanos())
                        .unwrap_or(0x1234_ABCD);
                    nanos.wrapping_mul(0x9E37_79B9).wrapping_add(challenge)
                };
                let wire = crate::proto::server_obfuscation::encode_with_obfbyte(
                    &out, seed_key, rng_seed, 0x6b,
                );

                // CRITICAL: send FROM our portUDPobf (TCP+14), NOT from our
                // main :4665 socket. Lugdunum's FUN_0042c480 looks up our
                // ServerKey by (our_ip, sender_port); if sender_port doesn't
                // match our_TCP+12 (4673) or our_TCP+14 (4675), the lookup
                // fails and the packet is dropped as "received a message
                // from unknown server" with no ServerKey extracted. Using
                // self.socket here (which is :4665) was the v0.9.19 bug.
                let our_obf_port = self.cfg.network.tcp_port.wrapping_add(14);
                let send_socket = match self.state.udp_sockets.get(&our_obf_port) {
                    Some(s) => Arc::clone(&s),
                    None => {
                        debug!(port = our_obf_port,
                               "no socket registered for portUDPobf — skipping obf 0x97 follow-up");
                        return Ok(());
                    }
                };

                if let Err(e) = send_socket.send_to(&wire, dst_obf).await {
                    debug!(ip = %peer.ip(), error = %e,
                           "couldn't send obf 0x97 follow-up");
                } else {
                    info!(
                        ip = %peer.ip(),
                        dst_obf_port,
                        src_port = our_obf_port,
                        challenge = format!("0x{:08x}", challenge),
                        seed_key = format!("0x{:08x}", seed_key),
                        "sent obfuscated 0x97 follow-up (from portUDPobf, echoes seed's challenge)"
                    );
                }
            }
        }

        debug!(ip = %peer.ip(), users, files, is_server_probe, "glob_servstat");
        Ok(())
    }

    /// Reply to an inbound OBF ping with an obfuscated 0x97 GLOBSERVSTATRES.
    ///
    /// Wire layout we send (matching captured Lugdunum reply from
    /// 91.107:4673 → 65.109:56283 = 68 bytes total):
    /// ```text
    ///   random_byte(1) + salt(2) + RC4(magic(4) + padlen(1) + padding +
    ///                                  eD2k_msg(0xE3 0x97 [44-byte payload]))
    /// ```
    /// The RC4 key derivation uses MD5(random_part_LE || 0xa5 || salt).
    /// The 0xa5 byte identifies this as a TCP+12 (obfpingport) channel reply,
    /// which is exactly what Lugdunum logs as `(ServerKey=0xXX,a5)`.
    ///
    /// The 44-byte payload mirrors what we send in `handle_servstat` for a
    /// plain server probe: 8 stat fields + portUDPobf + portTCPobf +
    /// ServerKey + our_ip. That gives the peer everything it needs to mark
    /// us as a verified obfuscation-capable server.
    async fn reply_to_obf_ping(
        &self,
        peer: SocketAddr,
        random_part: u32,
    ) -> Result<()> {
        // Build the inner eD2k 0x97 GLOBSERVSTATRES message (same fields as
        // handle_servstat's extended form).
        let users    = self.state.client_count() as u32;
        let files    = self.state.file_count() as u32;
        let lowid    = self.state.lowid_count() as u32;
        // Read limits from live_cfg (hot-reloadable via /api/config).
        let live = self.state.live_cfg.load();
        let max_conn = live.limits.max_clients;
        let soft     = live.limits.soft_limit_files;
        let hard     = live.limits.hard_limit_files;
        let pingflg: u32 = 0x0000_17FB;

        // Use the peer's random_part as the implicit challenge — Lugdunum
        // doesn't carry a separate challenge in the OBF ping wire format.
        let challenge = random_part;

        let our_ip: std::net::Ipv4Addr = self.cfg.server.this_ip
            .parse()
            .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
        // ServerKey: IPObfuscate(my_seckey, PEER_ip) — peer-specific, see
        // long comment in handle_servstat. Peer will use this key to encrypt
        // obfuscated UDP back to our :4675; we decrypt by recomputing the
        // same value from sender's IP.
        let peer_ip_le = match peer.ip() {
            std::net::IpAddr::V4(v4) => u32::from_le_bytes(v4.octets()),
            _ => 0,
        };
        let our_server_key = crate::proto::server_obfuscation::ip_obfuscate(
            &self.seckey, peer_ip_le,
        );

        let mut inner = BytesMut::new();
        inner.put_u8(PROTO_EDONKEY);
        inner.put_u8(0x97); // OP_GLOBSERVSTATRES
        inner.put_u32_le(challenge);
        inner.put_u32_le(users);
        inner.put_u32_le(files);
        inner.put_u32_le(max_conn);
        inner.put_u32_le(soft);
        inner.put_u32_le(hard);
        inner.put_u32_le(pingflg);
        inner.put_u32_le(lowid);
        // Trailer: portUDPobf, portTCPobf, ServerKey, our_ip (network order).
        let tcp_port = self.cfg.network.tcp_port;
        inner.put_u16_le(tcp_port.wrapping_add(14));
        inner.put_u16_le(tcp_port.wrapping_add(12));
        inner.put_u32_le(our_server_key);
        inner.extend_from_slice(&our_ip.octets());

        // Wrap with the TCP+12 obfuscation (key = peer's random_part, obfbyte = 0xa5).
        // Random rng_seed for salt/padding — the only thing that matters for
        // decryption is that we use the same key+obfbyte as the peer expects.
        let rng_seed = {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0xABCD_1234);
            nanos.wrapping_mul(0x9E37_79B9).wrapping_add(random_part)
        };
        let wire = crate::proto::server_obfuscation::encode_with_obfbyte(
            &inner, random_part, rng_seed, 0xa5,
        );

        self.socket.send_to(&wire, peer).await?;
        Ok(())
    }

    // ─── GLOBSERVSTATRES (0x97) ──────────────────────────────────────────────

    /// Incoming GLOBSERVSTATRES from a known seed server (pingreply in Lugdunum).
    /// The seed is responding to our GLOBSERVSTATREQ keepalive/probe.
    /// We update our knowledge of the seed's stats (users/files) for the server list.
    async fn handle_pingreply(&self, payload: &[u8], from: SocketAddr) -> Result<()> {
        if payload.len() < 12 { return Ok(()); }
        let users = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let files = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);

        // Receiving 0x97 from this IP proves it is a real eD2k server (mldonkey
        // CLIENTS never reply to 0x96 ping). Mark verified so the periodic
        // cleanup won't evict it.
        if let std::net::IpAddr::V4(v4) = from.ip() {
            self.state.verified_servers.insert(v4, std::time::Instant::now());
        }

        // Obfuscated GLOBSERVSTATRES carries extra fields beyond the 32-byte
        // plain form (eserver.c pingreply, line ~65265):
        //   ...udpflags(4) lowusers(4) portUDPobf(2) portTCPobf(2) ServerKey(4)
        // ServerKey sits at offset 0x24 (36). It is the key WE must use to
        // encrypt outbound obfuscated UDP to this seed. Store it so gossip
        // can switch from plain to obfuscated for this peer.
        if payload.len() >= 40 {
            let server_key = u32::from_le_bytes([
                payload[36], payload[37], payload[38], payload[39],
            ]);
            if let std::net::IpAddr::V4(v4) = from.ip() {
                let previous = self.state.seed_server_keys.insert(v4, server_key);
                if previous != Some(server_key) {
                    info!(
                        seed = %v4,
                        server_key = format!("0x{server_key:08x}"),
                        "learned seed ServerKey — gossip will use obfuscated UDP"
                    );
                }
            }
        }

        debug!(from = %from, users, files, "pingreply (GLOBSERVSTATRES from peer server)");
        Ok(())
    }

    // ─── SERVER_LIST_RES (0xA1) ─────────────────────────────────────────────

    /// Response from a seed server to our SERVER_LIST_REQ gossip packet.
    /// Merges the received server list into state.server_list.
    ///
    /// **Important**: 0xA1 is overloaded. Lugdunum servers use it to send
    /// `count(1) + (ip(4)+port(2))*count`. mldonkey CLIENTS also send 0xA1
    /// (`QueryServersReplyUdp`) with a DIFFERENT wire layout —
    /// `server_ip(4) + server_port(2) + count(1) + (ip(4)+port(2))*count`.
    /// If we parse a mldonkey-client 0xA1 with our Lugdunum format we read
    /// the sender's own IP byte as `count`, then sender's port bytes as the
    /// first server's partial IP, ending up with garbage entries.
    ///
    /// That bug surfaced in production: clients with IPs like 218.85.30.175
    /// appeared as both clients and "peer servers". Defense:
    ///
    ///   1. If sender's IP is currently connected as a client → drop.
    ///   2. If we never initiated gossip with sender → drop (only seeds and
    ///      peers we've learned ServerKeys from are trusted to send 0xA1).
    async fn handle_server_list_res(&self, payload: &[u8], from: SocketAddr) -> Result<()> {
        let sender_v4 = match from.ip() {
            std::net::IpAddr::V4(v4) => v4,
            _ => return Ok(()),
        };

        // Guard 1: connected client → certainly not a peer server.
        let sender_is_client = self.state.clients.iter()
            .any(|e| match e.ip { std::net::IpAddr::V4(v4) => v4 == sender_v4, _ => false });
        if sender_is_client {
            debug!(ip = %from.ip(),
                   "rejecting 0xA1 from connected client (mldonkey-style packet)");
            return Ok(());
        }

        // Guard 2: only accept from peer servers we've gossiped with. Seeds
        // populate `our_sent_random_parts` (we sent them an OBF ping) and
        // `seed_server_keys` (we received their obf reply). Either marks
        // them as a real peer in our books.
        let is_known_peer = self.state.our_sent_random_parts.contains_key(&sender_v4)
            || self.state.seed_server_keys.contains_key(&sender_v4);
        if !is_known_peer {
            debug!(ip = %from.ip(),
                   "rejecting 0xA1 from unknown sender (not a gossiped peer)");
            return Ok(());
        }

        if payload.is_empty() {
            return Ok(());
        }
        let count = payload[0] as usize;
        if payload.len() < 1 + count * 6 {
            debug!(ip = %from.ip(), "server_list_res: truncated");
            return Ok(());
        }

        let mut new_servers: Vec<std::net::SocketAddrV4> = Vec::new();
        let mut pos = 1;
        // Snapshot of currently-connected client IPs — we filter these out of
        // gossiped server lists. mldonkey clients sometimes advertise their
        // own IP to seeds, which then propagate them back to us as "servers".
        // Without this filter, a single mldonkey client appears in both our
        // Clients tab and Peer servers tab (the bug reported in v0.9.17).
        //
        // We block both CURRENTLY connected clients AND IPs seen as clients
        // within the last 30 minutes (recent_client_ips). The latter is
        // important because mldonkey clients often disconnect quickly but
        // re-appear in 0xA1 from seeds for many minutes afterwards.
        const CLIENT_BLOCK_TTL: std::time::Duration = std::time::Duration::from_secs(30 * 60);
        // Opportunistically purge stale entries to keep the set bounded.
        self.state.recent_client_ips.retain(|_, ts| ts.elapsed() < CLIENT_BLOCK_TTL);
        let client_ips: std::collections::HashSet<std::net::Ipv4Addr> = {
            let mut set = std::collections::HashSet::new();
            for e in self.state.clients.iter() {
                if let std::net::IpAddr::V4(v4) = e.ip { set.insert(v4); }
            }
            for e in self.state.recent_client_ips.iter() {
                set.insert(*e.key());
            }
            set
        };
        for _ in 0..count {
            let ip = std::net::Ipv4Addr::new(
                payload[pos], payload[pos+1], payload[pos+2], payload[pos+3]
            );
            let port = u16::from_le_bytes([payload[pos+4], payload[pos+5]]);
            pos += 6;
            // Reject obvious garbage: unspecified, loopback, private RFC1918,
            // and multicast IPs cannot be public eD2k servers.
            if port == 0 || ip.is_unspecified() || ip.is_loopback()
                || ip.is_private() || ip.is_multicast() || ip.is_broadcast()
            {
                continue;
            }
            // Reject IPs of our currently-connected clients (mldonkey leak).
            if client_ips.contains(&ip) {
                continue;
            }
            new_servers.push(std::net::SocketAddrV4::new(ip, port));
        }

        info!(
            from = %from,
            count = new_servers.len(),
            "gossip: received server list"
        );

        let mut list = self.state.server_list.write().await;
        // Purge any existing entries whose IPs are in client_ips (catches
        // mldonkey IPs that leaked into server_list before the TTL filter
        // was added in v0.9.29).
        let before_purge = list.len();
        list.retain(|s| !client_ips.contains(s.ip()));
        let purged = before_purge - list.len();
        if purged > 0 {
            info!(purged, "server_list: removed stale client IPs");
        }
        let before = list.len();
        // Defensive cap. server_list is gossip-driven and unbounded growth
        // would slowly leak memory; 2048 is way more than the real eD2k
        // network has and is plenty for our purposes.
        const SERVER_LIST_CAP: usize = 2048;
        for s in new_servers {
            if list.len() >= SERVER_LIST_CAP {
                break;
            }
            if !list.contains(&s) {
                list.push(s);
                self.state.server_list_added_at.insert(*s.ip(), std::time::Instant::now());
            }
        }
        if list.len() > before {
            info!(total = list.len(), added = list.len() - before, "gossip: server list updated");
        }

        Ok(())
    }

    // ─── SERVER_DESC_REQ (0xA2) ─────────────────────────────────────────────

    /// Server description request (UDP OP_SERVER_DESC_REQ = 0xA2).
    ///
    /// There are THREE distinct packet formats, differentiated by what the
    /// client sends in the 4-byte challenge field of the request:
    ///
    /// A) eMule ≥ 16.45 (new format):
    ///    Request:  E3 A2 [XX XX F0 FF]  — challenge low 2 bytes always 0xF0FF
    ///    Response: E3 A3 [same challenge 4B] [tag_count 4B] [tags...]
    ///    eMule checks PeekUInt16(response) == 0xF0FF to detect this path.
    ///
    /// B) Lugdunum server-to-server format:
    ///    Request:  E3 A2 [7F 7E 7D 7C] [random 4B]  — fixed 0x7c7d7e7f
    ///    Response: E3 A3 [7F 7E 7D 7C] [tag_count 4B] [tags...]
    ///    Same taglist path, but Lugdunum validates challenge == 0x7c7d7e7f.
    ///
    /// C) Legacy eMule / no challenge:
    ///    Request:  E3 A2  (empty or 0 bytes payload)
    ///    Response: E3 A3 [name_len 2B][name...][desc_len 2B][desc...]
    ///
    /// eMule uses stored DescReqChallenge to validate: if PeekUInt16 == 0xF0FF
    /// AND PeekUInt32 == stored challenge → parse tags for name/desc/version.
    /// Otherwise → old format ReadString(name) + ReadString(desc).
    async fn handle_server_desc(&self, payload: &[u8], peer: SocketAddr) -> Result<()> {
        // Read server name/desc/version from live_cfg (hot-reloadable).
        let live = self.state.live_cfg.load();
        let version_str = format!("{}.{}", live.server.version_major,
                                            live.server.version_minor);
        let name = live.server.name.clone();
        let desc = live.server.desc.clone();

        // Helper: old-format string tag (type=0x02, name_len_u16=1, name_byte, str_len_u16, str)
        fn write_old_str_tag(out: &mut BytesMut, name_byte: u8, value: &str) {
            out.put_u8(0x02);
            out.put_u16_le(1);
            out.put_u8(name_byte);
            out.put_u16_le(value.len() as u16);
            out.put_slice(value.as_bytes());
        }

        let challenge = if payload.len() >= 4 {
            u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
        } else {
            0
        };

        // Find the send socket — our main UDP (:4665) for Lugdunum's port check.
        let main_udp_port = self.cfg.network.udp_port;
        let send_socket = match self.state.udp_sockets.get(&main_udp_port) {
            Some(s) => Arc::clone(&s),
            None => {
                debug!(port = main_udp_port,
                       "no main UDP socket — falling back to self.socket");
                Arc::clone(&self.socket)
            }
        };

        // Strategy: send TWO responses to maximize compatibility.
        //
        // RESPONSE 1: OLD FORMAT — always sent.
        //   E3 A3 [name_len 2B][name][desc_len 2B][desc]
        //   eMule and pre-16.45 clients parse this unconditionally when
        //   the first 2 bytes are NOT 0xF0FF. Since name_len is normally
        //   small (e.g. 0x000B for "Test_server"), it's NOT 0xF0FF, so
        //   this packet always hits eMule's old-format parser. Even if
        //   eMule's DescReqChallenge state is 0 (e.g. cached server entry,
        //   never sent 0xA2), this populates name + description.
        //
        // RESPONSE 2: NEW FORMAT — sent ONLY when we have a challenge that
        //   matches the new format (low 2 bytes == 0xF0FF) OR Lugdunum's
        //   fixed 0x7c7d7e7f. eMule's challenge-validation gate accepts
        //   our taglist (containing name, desc, AND version). If state
        //   matches, eMule overwrites name/desc from RESPONSE 1 with the
        //   tag values (same content) and ADDITIONALLY parses version.

        // ─── RESPONSE 1: OLD FORMAT ──────────────────────────────────────────
        let mut old_pkt = BytesMut::new();
        old_pkt.put_u8(PROTO_EDONKEY);
        old_pkt.put_u8(OP_SERVER_DESC_RES);
        old_pkt.put_u16_le(name.len() as u16);
        old_pkt.put_slice(name.as_bytes());
        old_pkt.put_u16_le(desc.len() as u16);
        old_pkt.put_slice(desc.as_bytes());
        send_socket.send_to(&old_pkt, peer).await?;

        // ─── RESPONSE 2: NEW FORMAT (taglist with version) ───────────────────
        let low2 = u16::from_le_bytes([payload.get(0).copied().unwrap_or(0),
                                        payload.get(1).copied().unwrap_or(0)]);
        let is_new_format_request = payload.len() >= 4
            && (low2 == 0xF0FF || challenge == 0x7c7d7e7f);

        if is_new_format_request {
            let mut new_pkt = BytesMut::new();
            new_pkt.put_u8(PROTO_EDONKEY);
            new_pkt.put_u8(OP_SERVER_DESC_RES);
            new_pkt.put_u32_le(challenge);   // echo the exact challenge
            new_pkt.put_u32_le(3u32);        // tag_count
            write_old_str_tag(&mut new_pkt, ST_SERVERNAME,  &name);
            write_old_str_tag(&mut new_pkt, ST_DESCRIPTION, &desc);
            write_old_str_tag(&mut new_pkt, ST_VERSION,     &version_str);
            send_socket.send_to(&new_pkt, peer).await?;
        }

        info!(
            ip = %peer.ip(),
            challenge = format!("0x{challenge:08x}"),
            new_format_sent = is_new_format_request,
            src_port = main_udp_port,
            "server_desc_req answered (old format always + new format if matched)"
        );
        Ok(())
    }

    // ─── GLOBSEARCHREQ (0x98) ───────────────────────────────────────────────

    /// UDP global search — one result per datagram (SPEC.md §2.3.4).
    async fn handle_search(&self, payload: &[u8], peer: SocketAddr) -> Result<()> {
        let tree = match parse_search(payload) {
            Ok(t) => t,
            Err(e) => {
                debug!(ip = %peer.ip(), error = %e, "UDP search parse failed");
                return Ok(());
            }
        };

        let tokens: Vec<String> = collect_terms(&tree).iter()
            .map(|t| t.to_lowercase())
            .collect();

        if tokens.is_empty() { return Ok(()); }

        let candidate_ids = self.state.keyword_index.find_intersection(&tokens);

        let mut sent = 0;
        for fid in candidate_ids {
            if sent >= UDP_MAX_SEARCH_RESULTS { break; }
            // Resolve the compact FileId to its hash (keyword_index keys on id).
            let hash = match self.state.file_slab.hash_of(fid) {
                Some(h) => h,
                None => continue, // tombstoned id
            };
            let entry = match self.state.file_slab.get_by_hash(&hash) {
                Some(e) => e,
                None => continue,
            };
            // Skip orphans (no live source). See src/server/search.rs for the
            // full rationale — orphans are useless to return.
            if entry.sources.is_empty() {
                continue;
            }
            let name_lower = entry.name.to_lowercase();
            if !evaluate(&tree, &name_lower, entry.size) { continue; }

            // One file per UDP datagram
            let mut out = BytesMut::new();
            out.put_u8(PROTO_EDONKEY);
            out.put_u8(OP_GLOB_SEARCHRES);
            out.put_slice(&hash);

            // source id + port from first source
            if let Some(src) = entry.sources.first() {
                let id = src.ipv4;
                out.put_u32_le(id);
                out.put_u16_le(src.port());
            } else {
                out.put_u32_le(0);
                out.put_u16_le(0);
            }

            let size_lo = entry.size as u32;
            let size_hi = (entry.size >> 32) as u32;
            let mut tags = vec![
                Tag::byte(FT_FILENAME, TagValue::String(entry.name.to_string())),
                Tag::byte(FT_FILESIZE, TagValue::U32(size_lo)),
            ];
            if size_hi > 0 {
                tags.push(Tag::byte(FT_FILESIZE_HI, TagValue::U32(size_hi)));
            }
            tags.push(Tag::byte(FT_SOURCES, TagValue::U32(entry.sources.len() as u32)));
            // FT_COMPLETE_SOURCES (0x30) MUST be sent or eMule's "Complete"
            // column stays at "0% (0)" forever — the UDP search response path
            // was missing this tag before v0.9.40. Server-side we use the
            // Lugdunum convention: total sources == complete sources (see
            // FileEntry::complete_source_count in state/mod.rs for full rationale).
            tags.push(Tag::byte(
                FT_COMPLETE_SOURCES,
                TagValue::U32(entry.complete_source_count()),
            ));
            write_tag_list(&mut out, &tags);

            self.socket.send_to(&out, peer).await?;
            sent += 1;
        }

        debug!(ip = %peer.ip(), results = sent, "glob_search");
        Ok(())
    }
}

// ─── Additional opcode constants used only by UDP ──────────────────────────

const OP_GLOB_GETSOURCES:  u8 = 0x9A;
const OP_GLOB_GETSOURCES2: u8 = 0x94;
const OP_GLOB_SERVSTATREQ: u8 = 0x96;
const OP_SERVER_DESC_REQ:  u8 = 0xA2;
const OP_GLOB_SEARCHREQ:   u8 = 0x98;
const OP_GLOB_SEARCHREQ3:  u8 = 0x90;
// NAT-traversal: client→server UDP keepalive carrying the sender's userhash.
// Lets us record the client's external (post-NAT) UDP port for hole punching.
const OP_SERVER_NATT_KEEPALIVE: u8 = 0x9F;

const OP_GLOB_FOUNDSOURCES: u8 = 0x9B;
const OP_GLOB_SERVSTATRES:  u8 = 0x97;
const OP_SERVER_DESC_RES:   u8 = 0xA3;
const OP_GLOB_SEARCHRES:    u8 = 0x99;

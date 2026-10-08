//! Login + welcome batch handlers (SPEC.md §3.1).

use crate::config::Config;
use crate::proto::tags::read_tag_list;
use crate::proto::{opcodes::*, write_tag_list, Frame, Tag, TagName, TagValue};
use crate::state::{ClientHandle, ServerState, UserHash};
use anyhow::{anyhow, Result};
use bytes::{BufMut, BytesMut};
use std::net::IpAddr;
use std::time::Instant;
use tracing::{debug, info, warn};

/// Decoded LOGINREQUEST payload (SPEC.md §3.1.3).
#[derive(Debug)]
pub struct LoginRequest {
    pub user_hash: UserHash,
    pub claimed_id: u32, // usually 0.0.0.0; real ID assigned by server
    pub port: u16,
    pub tags: Vec<Tag>,
}

impl LoginRequest {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() < 22 {
            return Err(anyhow!(
                "LOGINREQUEST payload too short ({})",
                payload.len()
            ));
        }
        let mut user_hash = [0u8; 16];
        user_hash.copy_from_slice(&payload[0..16]);
        let claimed_id = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
        let port = u16::from_le_bytes([payload[20], payload[21]]);
        // Tag count and the tag area are read together, or not at all.
        //
        // These used to be separate: the count was guarded by `len() >= 26`, the
        // slice `&payload[26..]` was not. A payload of 22..=25 bytes therefore
        // passed the `< 22` check, took the `else { 0 }` branch — which exists
        // precisely for that length — and then panicked on the slice. Remotely
        // reachable by an unauthenticated peer on its first message, since
        // connection.rs calls this straight off the wire.
        //
        // 22 bytes is a legitimate minimum: user_hash(16) + id(4) + port(2) with
        // no tag section at all. Stock eMule always sends the count (see
        // ServerConnect.cpp, which writes 4 tags unconditionally), but a leaner
        // client may not, and either way a short frame must be answered with an
        // error rather than a panic.
        let (tag_count, mut slice): (u32, &[u8]) = if payload.len() >= 26 {
            (
                u32::from_le_bytes([payload[22], payload[23], payload[24], payload[25]]),
                &payload[26..],
            )
        } else {
            (0, &[])
        };
        // read_tag_list stops gracefully on unknown types, never panics.
        let tags = read_tag_list(&mut slice, tag_count);

        Ok(LoginRequest {
            user_hash,
            claimed_id,
            port,
            tags,
        })
    }

    pub fn nick(&self) -> Option<&str> {
        self.tags.iter().find_map(|t| {
            if t.name == TagName::Byte(CT_NAME) {
                t.str_value()
            } else {
                None
            }
        })
    }

    /// The client's own public IPv6, from `CT_MOD_IP_V6`.
    ///
    /// The tag is 16 raw bytes in network order — never text, never an integer,
    /// never byte-swapped. Only a HASH-typed tag is accepted: taking any type
    /// would let a client with a string there be read as v6-reachable, and the
    /// presence of this tag is itself a capability signal.
    pub fn client_ipv6(&self) -> Option<std::net::Ipv6Addr> {
        self.tags.iter().find_map(|t| {
            if t.name != TagName::Byte(CT_MOD_IP_V6) {
                return None;
            }
            match &t.value {
                TagValue::Blob(b) if b.len() == 16 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(b);
                    Some(std::net::Ipv6Addr::from(a))
                }
                _ => None,
            }
        })
    }

    pub fn server_flags(&self) -> u32 {
        self.tags
            .iter()
            .find_map(|t| {
                if t.name == TagName::Byte(CT_SERVER_FLAGS) {
                    t.as_u32()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }
}

/// The 16-byte server hash sent in `OP_SERVERIDENT`.
///
/// Derived from the seckey (itself derived from `this_ip` + `tcp_port`), so it
/// is stable across restarts and differs between servers, with no new stored
/// secret. It is an identifier, not a secret: eMule reads it only to label
/// eFarm servers (a hash starting 0x2A2A2A2A, which MD5 output here cannot be
/// made to produce on purpose). The domain string keeps it unrelated to the
/// identity the HighID probe presents (`server_pseudo_user_hash`).
///
/// Computed once. The seckey only changes with the IP or port, and both need a
/// restart to take effect for obfuscation anyway, so a cached value cannot go
/// out of step with the key the rest of the server uses.
pub fn server_ident_hash(cfg: &Config) -> [u8; 16] {
    static IDENT: std::sync::OnceLock<[u8; 16]> = std::sync::OnceLock::new();
    *IDENT.get_or_init(|| server_ident_hash_for(&crate::server::udp::resolve_seckey(cfg)))
}

pub(crate) fn server_ident_hash_for(seckey: &[u8; 16]) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(b"ed2k-server-ident");
    h.update(seckey);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.finalize());
    // Never the eFarm marker, however unlikely.
    if out[..4] == [0x2A; 4] {
        out[0] = 0x2B;
    }
    out
}

/// Bytes 12–15 of `OP_IDCHANGE`: the client's address as the server sees it.
///
/// eMule reads the field at `packet+12` as `dwServerReportedIP`. On a LowID it
/// calls `SetPublicIP` with it, so a LowID client takes this value as its own
/// public address and keys UDP obfuscation, the Kad verify key and what it
/// advertises about itself on it. On a HighID it asserts the field equals the
/// client id; aMule logs a mismatch. Up to 0.9.76 this carried the SERVER's
/// `this_ip`, and every LowID client believed it lived at our address
/// (issue #17).
///
/// * HighID — the client id itself. For an ordinary login that is the address
///   the connection came from; for a client verified through the hairpin path
///   (`hairpin_lan_clients`) it is our public address, which IS that client's
///   public address, while the connection came from a LAN address that must not
///   be reported.
/// * LowID from a public IPv4 — that address.
/// * LowID from a private or loopback IPv4 — the client sits behind the same
///   NAT as the server, so its public address is ours: `this_ip`, when that is
///   set and public. This is the one case the old code happened to get right,
///   and reporting the LAN address instead would hand the client a private IP
///   as its public one. Otherwise 0.
/// * IPv6 session — its IPv4 is unknown. 0 makes eMule leave its public IP
///   unset rather than learn a wrong one.
///
/// Nothing in the HighID decision reads this field: the verdict is taken
/// before the welcome batch is built, and the identity probes compare user
/// hashes over TCP.
pub(crate) fn reported_client_ip(
    client_ip: IpAddr,
    is_high_id: bool,
    assigned_id: u32,
    this_ip: &str,
) -> u32 {
    if is_high_id {
        return assigned_id;
    }
    match client_ip {
        IpAddr::V4(v4) if !v4.is_private() && !v4.is_loopback() && !v4.is_link_local() => {
            // An address ending in .0 encodes into the LowID range; eMule
            // asserts on it and zeroes it (issue #26). Send 0 = unknown.
            Some(u32::from_le_bytes(v4.octets()))
                .filter(|&ip| ip >= crate::server::highid_probe::LOWID_CEILING)
                .unwrap_or(0)
        }
        IpAddr::V4(_) => this_ip
            .trim()
            .parse::<std::net::Ipv4Addr>()
            .ok()
            .filter(|ip| !ip.is_private() && !ip.is_loopback() && !ip.is_unspecified())
            .map(|ip| u32::from_le_bytes(ip.octets()))
            .unwrap_or(0),
        IpAddr::V6(_) => 0,
    }
}

/// Build the canonical post-login welcome batch (SPEC.md §3.1.2):
/// IDCHANGE, SERVERSTATUS, SERVERMESSAGE, SERVERIDENT, plus optional
/// extra welcome lines.
pub fn build_welcome_batch(cfg: &Config, state: &ServerState, client: &ClientHandle) -> Vec<Frame> {
    // Hot-reloadable view of the configuration. /api/config swaps `live_cfg`
    // atomically, so everything read through `live` below takes effect for the
    // NEXT client that logs in — no restart needed for the server name,
    // description, version, advertised limits or welcome messages.
    //
    // PORTS ARE DELIBERATELY NOT READ FROM HERE. `cfg.network.tcp_port` is the
    // port we are actually bound to; the live config may already carry a new
    // value that only becomes real after a restart (web.rs flags port changes as
    // restart-needed). Advertising a port nothing listens on would send every
    // client to a dead socket, so the bound port stays authoritative.
    let live = state.live_cfg.load();
    let mut frames = Vec::new();

    // 1. IDCHANGE — 20-byte payload, format required by eMule 0.49c ServerSocket.cpp:
    //   [0-3]   client_id          (LoginAnswer_Struct.clientid)
    //   [4-7]   tcp_flags          (read at offset sizeof(LoginAnswer_Struct)=4)
    //   [8-11]  filler             (eMule skips bytes 8-11)
    //   [12-15] the CLIENT's address as we see it (eMule reads packet+12 —
    //           see `reported_client_ip`; NOT our own IP, issue #17)
    //   [16-19] obfuscation_tcp_port (eMule reads packet+16 as u32)
    //
    // eMule's check: `if (size >= 20)` before reading IP+obfport — payload
    // MUST be at least 20 bytes or obfuscation port is never set.
    //
    // tcp_flags — exact eMule 0.49c SRV_TCPFLG_* bits (from server.h):
    //   0x0001 COMPRESSION    — zlib support; ALSO makes eMule send 0xFB/0xFC
    //                          client_ids in OFFERFILES (complete/partial marker)
    //   0x0008 NEWTAGS
    //   0x0010 UNICODE
    //   0x0040 RELATEDSEARCH
    //   0x0080 TYPETAGINTEGER
    //   0x0100 LARGEFILES
    //   0x0400 TCPOBFUSCATION — required (with non-zero obf port) for "Obfuscation: Yes"
    //   = 0x05DD
    {
        let reported_ip = reported_client_ip(
            client.ip,
            client.is_high_id,
            client.assigned_id,
            &live.server.this_ip,
        );
        //   0x4000 IPV6           — added only when the server actually speaks it
        let mut tcp_flags: u32 = 0x0000_05DD;
        if live.network.ipv6_publish_sources {
            // ⚠ 0x4000 server→client. The client→server capability bit is
            //   0x1000 in CT_SERVER_FLAGS — a different word in a different
            //   packet. The asymmetry is deliberate in the published spec and is
            //   the single easiest thing to get backwards here.
            //
            // Announced from `ipv6_publish_sources` rather than from
            // `ipv6_enabled`: the bit tells a client it may receive inline IPv6
            // sources, and a server that accepts IPv6 logins but publishes no v6
            // sources would be claiming something it does not do.
            tcp_flags |= SRV_TCPFLG_IPV6;
        }

        let mut payload = BytesMut::with_capacity(20);
        payload.put_u32_le(client.assigned_id); // [0-3]   client_id
        payload.put_u32_le(tcp_flags); // [4-7]   tcp_flags
                                       // [8-11] AUX PORT — the server's "standard" TCP port.
                                       //
                                       // This is NOT a filler. eMule skips these bytes (it reads the reported IP
                                       // straight from packet+12), but aMule reads them as the aux-port field and
                                       // does `cur_server->SetPort(ConnPort)` — and CServer::realport is a uint16,
                                       // so whatever we put here gets truncated to 16 bits and BECOMES the server's
                                       // port in the client's list. We used to put client_id here, so every aMule
                                       // session rewrote our port to `assigned_id & 0xFFFF`: client id 1968999842
                                       // showed up as port 36258, the next session as 34750, and so on — the
                                       // "phantom clones of our server on random ports" that only ever appeared in
                                       // aMule. The field means "if the client logged in on an auxiliary port, here
                                       // is the standard port to advertise", so send our real TCP port. aMule then
                                       // sets the port to what it already is (no-op) and eMule is unaffected.
        payload.put_u32_le(cfg.network.tcp_port as u32); // [8-11]  aux/standard port
        payload.put_u32_le(reported_ip); // [12-15] the client's own address
        payload.put_u32_le(cfg.network.tcp_port as u32); // [16-19] obfuscation_tcp_port
        frames.push(Frame::new(OP_IDCHANGE, payload.to_vec()));
    }
    // 2. SERVERSTATUS — current users, files
    {
        let mut payload = BytesMut::with_capacity(8);
        payload.put_u32_le(state.client_count() as u32);
        payload.put_u32_le(state.file_count() as u32);
        frames.push(Frame::new(OP_SERVERSTATUS, payload.to_vec()));
    }

    // 3. SERVERMESSAGE — first welcome line (or default)
    {
        let msg = live
            .welcome
            .messages
            .first()
            .cloned()
            .unwrap_or_else(|| format!("Welcome to {}", live.server.name));
        let mut payload = BytesMut::with_capacity(2 + msg.len());
        payload.put_u16_le(msg.len() as u16);
        payload.put_slice(msg.as_bytes());
        frames.push(Frame::new(OP_SERVERMESSAGE, payload.to_vec()));
    }

    // 4. SERVERIDENT — server hash + IP + port + tags
    {
        let mut payload = BytesMut::new();
        // Server hash: this server's 16-byte identity, stable and distinct per
        // server (see server_ident_hash). It used to be one fixed constant for
        // every server running this code.
        payload.put_slice(&server_ident_hash(&live));

        // Server IP: use configured this_ip if set, otherwise 0 (client uses TCP source).
        // This one IS the server's own address — unlike OP_IDCHANGE bytes 12–15.
        let server_ip: u32 = if live.server.this_ip.is_empty() {
            0
        } else {
            live.server
                .this_ip
                .parse::<std::net::Ipv4Addr>()
                .map(|ip| u32::from_le_bytes(ip.octets()))
                .unwrap_or(0)
        };
        payload.put_u32_le(server_ip);
        payload.put_u16_le(cfg.network.tcp_port);

        let (soft_files, hard_files) = match &client.offer_policy {
            Some(p) => (p.soft, p.hard),
            None => (live.limits.soft_limit_files, live.limits.hard_limit_files),
        };
        let mut tags = vec![
            Tag::byte(ST_SERVERNAME, TagValue::String(live.server.name.clone())),
            Tag::byte(ST_DESCRIPTION, TagValue::String(live.server.desc.clone())),
            // ST_VERSION as STRING "major.minor" — same format as our 0xA3 reply.
            // Some eMule builds don't display UINT32-encoded version in the server
            // list, so we use the explicit "17.15" string that eMule parses reliably.
            Tag::byte(
                ST_VERSION,
                TagValue::String(format!(
                    "{}.{}",
                    live.server.version_major, live.server.version_minor
                )),
            ),
            Tag::byte(ST_MAXUSERS, TagValue::U32(live.limits.max_clients)),
            // From the connection's OFFERFILES v1 snapshot when it has one, so
            // the two numbers it is told are the two it is held to (#19).
            Tag::byte(ST_SOFTFILES, TagValue::U32(soft_files)),
            Tag::byte(ST_HARDFILES, TagValue::U32(hard_files)),
            // ST_UDPFLAGS — eMule's SupportsObfuscationTCP() requires either this OR
            // ST_TCPFLAGS to have bit 0x400 (SRV_UDPFLG_TCPOBFUSCATION) set.
            // From eMule's server.h: SupportsObfuscationTCP() =
            //   GetObfuscationPortTCP() != 0 && ((UDPFlags & 0x400) || (TCPFlags & 0x400))
            // Single source of truth, shared with GLOBSERVSTATRES — see the
            // per-bit table on SERVER_UDP_FLAGS.
            Tag::byte(ST_UDPFLAGS, TagValue::U32(SERVER_UDP_FLAGS)),
            // ST_TCPPORTOBFUSCATION / ST_UDPPORTOBFUSCATION — eMule casts to uint16,
            // but values are stored in tags as u32 (eMule code: m_nObfuscationPortTCP = (uint16)tag->GetInt()).
            // Non-zero TCP obf port is required for SupportsObfuscationTCP() to return true.
            Tag::byte(
                ST_TCPPORTOBFUSCATION,
                TagValue::U32(cfg.network.tcp_port as u32),
            ),
            Tag::byte(
                ST_UDPPORTOBFUSCATION,
                TagValue::U32((cfg.network.tcp_port + 14) as u32),
            ),
        ];

        // ST_IPV6 — this server's own public IPv6, so a client that reached us
        // over IPv4 learns there is a v6 address to come back on.
        //
        // Appended rather than placed in the list above, because it is
        // conditional: a server with no IPv6 must send a byte-identical
        // SERVERIDENT to the one it sent before this release. An unknown tag is
        // skipped by every client, but an EMPTY or zero-filled one would be read
        // as an address.
        if live.network.ipv6_publish_sources {
            if let Ok(a) = live.network.this_ip6.trim().parse::<std::net::Ipv6Addr>() {
                if is_publishable_ipv6(a) {
                    tags.push(Tag::byte(ST_IPV6, TagValue::Hash16(a.octets())));
                }
            }

            // ST_IPV6_STATUS — our verdict on the client's own address.
            //
            // Worth sending because the client cannot work it out for itself. A
            // session connected over IPv4 that advertised CT_MOD_IP_V6 has no
            // other way to learn whether that address was accepted and whether
            // it is now being published as a v6 source; without this it would
            // have to guess, and a client that guesses "yes" wrongly stops
            // advertising its LowID as well.
            //
            // Bits are only ever set to "yes". The tag is omitted entirely when
            // there is no verdict, so a client that sees it can trust every bit
            // — an unset bit means no, never unknown.
            let mut status: u8 = 0;
            if client.ipv6.is_some() {
                status |= IPV6ST_HAVE | IPV6ST_REACHABLE;
            }
            // IPV6ST_PROBED stays unset: we accept the address on trust (from
            // the socket, or from the login tag) and never dial it back. Setting
            // it would claim a check we do not perform.
            if status != 0 {
                tags.push(Tag::byte(ST_IPV6_STATUS, TagValue::U8(status)));
            }
        }
        // OFFERFILES v1 (issue #19): all three or none, string-named so a
        // client that does not know them skips them. A legacy session (v1 off,
        // or a configuration that cannot be advertised) gets a SERVERIDENT
        // byte-identical to the one before this capability existed.
        if let Some(p) = &client.offer_policy {
            tags.extend(p.tags());
        }
        write_tag_list(&mut payload, &tags);

        frames.push(Frame::new(OP_SERVERIDENT, payload.to_vec()));
    }

    // 5. Additional welcome lines (welcome[1..N])
    for line in live.welcome.messages.iter().skip(1) {
        let mut payload = BytesMut::with_capacity(2 + line.len());
        payload.put_u16_le(line.len() as u16);
        payload.put_slice(line.as_bytes());
        frames.push(Frame::new(OP_SERVERMESSAGE, payload.to_vec()));
    }

    frames
}

/// Detect HighID/LowID via HighID probe (SPEC.md §3.2).
///
/// Probes the client's (ip, port). Public IPs are tested with an outbound
/// TCP connection; private/loopback always get LowID without probing.
pub async fn assign_client_id(
    state: &ServerState,
    // Kept for API stability; the probe timeout now comes from live_cfg so it is
    // hot-reloadable. Callers are unchanged.
    _cfg: &Config,
    peer_ip: IpAddr,
    client_port: u16,
) -> (u32, bool) {
    let (id, high, _ip) = assign_client_id_for(state, peer_ip, client_port, None, 0).await;
    (id, high)
}

/// As `assign_client_id`, but able to attempt the hairpin fallback, which needs
/// the user hash from the login in order to verify who answers the probe.
///
/// Returns the address the client should be RECORDED under as well. For every
/// ordinary login that is the address it connected from; for a verified hairpin
/// client it is the public address, because that is the one peers must be given
/// as a source. Recording the private one would undo the whole fallback: the
/// client would hold a HighID nobody could act on.
/// `ST_IPV6` — the server's own public IPv6 in `OP_SERVERIDENT`, 16 raw bytes.
///
/// Same tag id and encoding a client uses for `CT_MOD_IP_V6`; the two directions
/// share the number, unlike the capability bits.
const ST_IPV6: u8 = 0xAE;

/// `ST_IPV6_STATUS` — the server's verdict on the client's advertised IPv6.
const ST_IPV6_STATUS: u8 = 0xAB;
/// The server holds a public IPv6 for this session.
const IPV6ST_HAVE: u8 = 0x01;
/// That address is treated as reachable and the client is published as a v6
/// source.
const IPV6ST_REACHABLE: u8 = 0x02;

/// `OP_IDCHANGE` / `OP_GLOBSERVSTATRES` flag bit: this server speaks the IPv6
/// extension. See the warning at `SRVCAP_IPV6` about the direction asymmetry.
pub use crate::proto::opcodes::SRVFLG_IPV6 as SRV_TCPFLG_IPV6;

/// Is this IPv6 usable as a source address for other peers?
///
/// The same question `is_publishable_source_ip` answers for IPv4, and for the
/// same reason: an address that only means something on one link costs every
/// recipient a connection attempt and then spreads through source exchange.
/// Link-local is the one that would actually happen — a client behind a router
/// with no global prefix advertises `fe80::…` and it is useless to everyone.
pub fn is_publishable_ipv6(a: std::net::Ipv6Addr) -> bool {
    !a.is_loopback()
        && !a.is_unspecified()
        && !a.is_multicast()
        // fe80::/10 link-local
        && !(a.segments()[0] & 0xffc0 == 0xfe80)
        // fc00::/7 unique local
        && !(a.octets()[0] & 0xfe == 0xfc)
        // ::ffff:0:0/96 — an IPv4 address in disguise, never a v6 source
        && a.to_ipv4_mapped().is_none()
}

/// `CT_MOD_IP_V6` — the client's public IPv6, 16 raw bytes.
///
/// Value agreed with the two implementations that already speak this: eMuleQt
/// (`docs/protocol/ipv6-spec.md` §1.3) and eNode-go. Do not renumber.
const CT_MOD_IP_V6: u8 = 0xAE;

/// CT_SERVER_FLAGS bit meaning "this client can speak obfuscated connections".
/// eMule sets it whenever the crypt layer is enabled, which is the default.
///
/// Re-exported from the shared table rather than declared again: the private
/// copy that used to live here was correct while `opcodes::CAPABLE_SUPPORTCRYPT`
/// was not, and two constants for one wire bit is how that survives unnoticed.
pub(crate) use crate::proto::opcodes::CAPABLE_SUPPORTCRYPT as SRVCAP_SUPPORTCRYPT;

/// The HighID for a verified address, or — if the address has none (IPv6,
/// or an IPv4 ending in .0, issue #26) — a fresh LowID flagged as LowID. Never
/// a LowID-range id flagged as HighID.
fn high_or_low_id(state: &ServerState, ip: IpAddr) -> (u32, bool) {
    match crate::server::highid_probe::high_id_from_ip(ip) {
        Some(id) => (id, true),
        None => (state.allocate_low_id(), false),
    }
}

pub async fn assign_client_id_for(
    state: &ServerState,
    peer_ip: IpAddr,
    client_port: u16,
    login_user_hash: Option<&[u8; 16]>,
    client_flags: u32,
) -> (u32, bool, IpAddr) {
    use crate::server::highid_probe::{
        high_id_from_ip, probe, probe_identity, server_pseudo_user_hash,
    };

    // Hot-reloadable: the probe timeout is read per login, so tuning it via
    // /api/config takes effect immediately.
    let live = state.live_cfg.load();
    let probe_timeout = live.network.login_timeout_ms;

    // An IPv6 session is LowID on v4 by construction: the id is an IPv4 address
    // and this peer has none we know of. No probe, no HighID — its reachability
    // is published through the inline v6 source record instead.
    if peer_ip.is_ipv6() {
        return (state.allocate_low_id(), false, peer_ip);
    }

    // A public address ending in .0 has no HighID: its id would fall in the
    // LowID range (issue #26). LowID, without spending a probe on it.
    if matches!(peer_ip, IpAddr::V4(v4) if !v4.is_private() && !v4.is_loopback())
        && high_id_from_ip(peer_ip).is_none()
    {
        debug!(ip = %peer_ip, "highid: address has no HighID (ends in .0) → LowID");
        return (state.allocate_low_id(), false, peer_ip);
    }

    // admission.max_probe_jobs (issue #25): every outbound probe — this one,
    // the hairpin probe below, and the background identity checks — shares
    // one ceiling. Held until this function returns. With none free the login
    // is not delayed: it gets LowID, the conservative answer, and its next
    // login is probed again.
    let Some(_probe_permit) = state.admission.probes.try_take() else {
        state.admission.note_probe_shed();
        debug!(ip = %peer_ip, "highid: probe ceiling full → LowID");
        return (state.allocate_low_id(), false, peer_ip);
    };

    if probe(peer_ip, client_port, probe_timeout).await {
        // VERDICT, opt-in, remembered: a port that answered the hello with
        // ANOTHER client's hash belongs to someone else behind the same NAT.
        // Decided from a mark left by an earlier background check, so the
        // login never waits; the check itself runs again in the background,
        // which renews or clears the mark. See
        // `network.highid_downgrade_on_wrong_hash`.
        if live.network.highid_downgrade_on_wrong_hash {
            if let Some(uh) = login_user_hash {
                // Read the mark BEFORE starting the re-check, so this login is
                // decided by what was known when it arrived.
                let marked = state.highid_observe.is_marked(peer_ip, client_port, uh);
                spawn_highid_check(
                    state,
                    &live,
                    peer_ip,
                    client_port,
                    *uh,
                    client_flags,
                    probe_timeout,
                    true,
                );
                if marked {
                    state
                        .highid_observe
                        .downgraded
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    debug!(
                        ip = %peer_ip, port = client_port,
                        "highid: wrong-hash mark active → LowID"
                    );
                    return (state.allocate_low_id(), false, peer_ip);
                }
            }
            let (id, high) = high_or_low_id(state, peer_ip);
            return (id, high, peer_ip);
        }
        let (id, high) = high_or_low_id(state, peer_ip);
        // OBSERVE ONLY. The verdict above is already final and is returned
        // unchanged on the next line; this merely counts what the stricter,
        // Lugdunum-style check would have said. Detached, so the login does not
        // wait for it. See `network.highid_verify_observe`.
        if live.network.highid_verify_observe {
            if let Some(uh) = login_user_hash {
                spawn_highid_check(
                    state,
                    &live,
                    peer_ip,
                    client_port,
                    *uh,
                    client_flags,
                    probe_timeout,
                    false,
                );
            }
        }
        return (id, high, peer_ip);
    }

    // ─── HAIRPIN FALLBACK (opt-in) ──────────────────────────────────────
    //
    // ⚠ THE FIRST THING TO TURN OFF if HighID starts being handed out wrongly.
    //   Set network.hairpin_lan_clients = false and the server is back to the
    //   behaviour every release before this one had. Nothing else depends on it.
    //
    // Reached only when the plain probe already said LowID, so it can add
    // HighIDs but never take one away.
    //
    // The case: a client on the same network as the server reaches it through
    // the router's hairpin NAT, so the login arrives from an RFC1918 address and
    // `probe` refuses to even try. In that topology the client's public address
    // is the server's own, so that is what gets probed.
    //
    // Verified, not assumed. Where the router source-NATs hairpin traffic every
    // local client arrives from the same address, so a forward on that port may
    // belong to a different machine; the identity probe requires the peer to
    // answer with the user hash that just logged in.
    if live.network.hairpin_lan_clients && !peer_ip.is_loopback() {
        if let (Some(uh), Ok(this_ip)) = (
            login_user_hash,
            live.server.this_ip.trim().parse::<std::net::Ipv4Addr>(),
        ) {
            let private_peer = matches!(peer_ip, IpAddr::V4(v4) if v4.is_private());
            if private_peer && !this_ip.is_private() {
                let our_id = high_id_from_ip(IpAddr::V4(this_ip)).unwrap_or(0);
                // An identity of our own to present. It must not be the peer's:
                // a client handed its own user hash concludes it has connected
                // to itself and closes without answering.
                // Derived from the same seckey the obfuscated handshake uses,
                // so it is stable across restarts. Computed only on this path,
                // which a normal login never reaches.
                let ours = server_pseudo_user_hash(&crate::server::udp::resolve_seckey(&live));

                // Obfuscate when the client said at login that it can, which is
                // what Lugdunum does. A client configured to REQUIRE obfuscation
                // drops a plain connection without a word, so without this the
                // probe can never reach it.
                let supports_crypt = client_flags & SRVCAP_SUPPORTCRYPT != 0;

                let mut outcome = probe_identity(
                    IpAddr::V4(this_ip),
                    client_port,
                    uh,
                    &ours,
                    our_id,
                    live.network.tcp_port,
                    probe_timeout,
                    supports_crypt,
                )
                .await;

                // FALL BACK TO PLAIN once, and only when the obfuscated attempt
                // failed at the handshake itself. "Supports" is not "requires",
                // and a client that advertised the capability may still have it
                // switched off, or belong to a fork that answers only in the
                // clear. A retry costs one connection on a path that already
                // decided LowID; getting it wrong costs the feature entirely.
                if supports_crypt
                    && matches!(
                        outcome,
                        Err("obfuscated handshake failed")
                            | Err("peer closed during obfuscated handshake")
                            | Err("no crypt answer before timeout")
                    )
                {
                    debug!(
                        public_ip = %this_ip, port = client_port,
                        "hairpin: obfuscated probe refused, retrying in the clear"
                    );
                    outcome = probe_identity(
                        IpAddr::V4(this_ip),
                        client_port,
                        uh,
                        &ours,
                        our_id,
                        live.network.tcp_port,
                        probe_timeout,
                        false,
                    )
                    .await;
                }

                match outcome {
                    Ok(true) => {
                        info!(
                            lan_ip = %peer_ip, public_ip = %this_ip, port = client_port,
                            "hairpin: client verified behind our own NAT → HighID"
                        );
                        let (id, high) = high_or_low_id(state, IpAddr::V4(this_ip));
                        return (id, high, IpAddr::V4(this_ip));
                    }
                    Ok(false) => {
                        // A different host holds that forward. Handing out the
                        // public address here would point peers at a machine
                        // that never published the file.
                        warn!(
                            lan_ip = %peer_ip, public_ip = %this_ip, port = client_port,
                            "hairpin: port answers but with a different user hash → LowID"
                        );
                    }
                    Err(reason) => {
                        debug!(
                            lan_ip = %peer_ip, public_ip = %this_ip, port = client_port,
                            reason, "hairpin: no verified answer → LowID"
                        );
                    }
                }
            }
        }
    }

    (state.allocate_low_id(), false, peer_ip)
}

/// The identity probe as the HighID check runs it: obfuscated first when the
/// client advertised it, then once in the clear if the crypt handshake itself
/// was refused. Returns the user hash that answered.
///
/// Shared by observe and verdict mode so the two cannot drift: the
/// observe numbers are only worth something if they describe exactly what the
/// verdict does. The hairpin code keeps its own copy on purpose (see
/// `spawn_highid_observe`); if its fallback list ever changes, change this too.
async fn highid_identity_answer(
    ip: IpAddr,
    port: u16,
    user_hash: [u8; 16],
    ident: HighIdProbeIdent,
    timeout_ms: u64,
    supports_crypt: bool,
) -> Result<[u8; 16], &'static str> {
    use crate::server::highid_probe::probe_identity_hash;
    let HighIdProbeIdent {
        ours,
        our_id,
        our_port,
    } = ident;
    let outcome = probe_identity_hash(
        ip,
        port,
        &user_hash,
        &ours,
        our_id,
        our_port,
        timeout_ms,
        supports_crypt,
    )
    .await;
    if supports_crypt
        && matches!(
            outcome,
            Err("obfuscated handshake failed")
                | Err("peer closed during obfuscated handshake")
                | Err("no crypt answer before timeout")
        )
    {
        return probe_identity_hash(
            ip, port, &user_hash, &ours, our_id, our_port, timeout_ms, false,
        )
        .await;
    }
    outcome
}

/// What the server presents of itself in the identity probe's OP_HELLO.
#[derive(Clone, Copy)]
struct HighIdProbeIdent {
    ours: [u8; 16],
    our_id: u32,
    our_port: u16,
}

impl HighIdProbeIdent {
    fn from_config(live: &Config) -> Self {
        use crate::server::highid_probe::{high_id_from_ip, server_pseudo_user_hash};
        Self {
            // Never the peer's own hash — a client handed its own hash thinks
            // it has connected to itself and closes without answering. Same
            // identity the hairpin probe presents.
            ours: server_pseudo_user_hash(&crate::server::udp::resolve_seckey(live)),
            our_id: live
                .server
                .this_ip
                .trim()
                .parse::<std::net::Ipv4Addr>()
                .ok()
                .and_then(|v4| high_id_from_ip(IpAddr::V4(v4)))
                .unwrap_or(0),
            our_port: live.network.tcp_port,
        }
    }
}

/// What one identity probe found, as far as the HighID check cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HighIdCheck {
    /// The client that logged in answered (type markers aside).
    Same,
    /// Another client answered: the port is forwarded to someone else.
    Wrong,
    /// No usable answer. Proves nothing either way.
    NoAnswer,
}

/// Count one identity-probe outcome and classify it. `marking` says the caller
/// acts on a wrong hash (sets a mark), so the mismatch record says which of
/// the two modes produced it.
fn record_highid_outcome(
    obs: &crate::state::HighIdObserve,
    ip: IpAddr,
    port: u16,
    user_hash: [u8; 16],
    outcome: Result<[u8; 16], &'static str>,
    marking: bool,
) -> HighIdCheck {
    use crate::server::highid_probe::same_client_hash;
    use std::sync::atomic::Ordering::Relaxed;
    match outcome {
        Ok(answered) if same_client_hash(&answered, &user_hash) => {
            obs.verified.fetch_add(1, Relaxed);
            if answered != user_hash {
                obs.verified_marker_variant.fetch_add(1, Relaxed);
            }
            HighIdCheck::Same
        }
        Ok(answered) => {
            obs.mismatch.fetch_add(1, Relaxed);
            // INFO, not debug: rare, and each one is worth a look — it is the
            // only outcome that PROVES a HighID points peers at the wrong
            // machine.
            info!(
                %ip, port,
                login_hash = %hex::encode(user_hash),
                answered_hash = %hex::encode(answered),
                marked = marking,
                "highid check: port answers with a DIFFERENT user hash"
            );
            obs.record_mismatch(crate::state::HighIdMismatch {
                at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                ip,
                port,
                login_hash: user_hash,
                answered_hash: answered,
                marked: marking,
            });
            HighIdCheck::Wrong
        }
        Err(reason) => {
            obs.no_answer.fetch_add(1, Relaxed);
            *obs.reasons.entry(reason).or_insert(0) += 1;
            debug!(%ip, port, reason, "highid check: HighID by connect, no hello answer");
            HighIdCheck::NoAnswer
        }
    }
}

/// Apply a check result to the wrong-hash marks (verdict mode only): a wrong
/// hash sets or renews the mark, the client's own hash clears it, no answer
/// leaves it alone — silence proves nothing.
fn apply_highid_mark(
    obs: &crate::state::HighIdObserve,
    ip: IpAddr,
    port: u16,
    user_hash: [u8; 16],
    check: HighIdCheck,
    ttl: std::time::Duration,
) {
    use std::sync::atomic::Ordering::Relaxed;
    match check {
        HighIdCheck::Wrong => {
            if !obs.mark(ip, port, user_hash, ttl) {
                warn!(%ip, port, "highid: wrong-hash mark table full, mark not set");
            }
        }
        HighIdCheck::Same => {
            if obs.unmark(ip, port, &user_hash) {
                obs.marks_cleared.fetch_add(1, Relaxed);
                info!(%ip, port, "highid: port answers with the client's own hash again → mark cleared");
            }
        }
        HighIdCheck::NoAnswer => {}
    }
}

/// Background identity probe after the plain probe succeeded. Never delays
/// the login.
///
/// `marking` false: observe mode, counts only. `marking` true: verdict mode,
/// the result also sets, renews or clears the wrong-hash mark that decides
/// this client's NEXT login (`network.highid_downgrade_on_wrong_hash`).
///
/// Same probe, same obfuscation-then-plain fallback, same timeout in both
/// modes — they share `highid_identity_answer`. The hairpin code is
/// deliberately left as it is rather than shared with this: it is a verdict
/// path with its own history, and a refactor for tidiness is not worth the
/// risk of changing it.
#[allow(clippy::too_many_arguments)]
fn spawn_highid_check(
    state: &ServerState,
    live: &Config,
    ip: IpAddr,
    port: u16,
    user_hash: [u8; 16],
    client_flags: u32,
    timeout_ms: u64,
    marking: bool,
) {
    use std::sync::atomic::Ordering::Relaxed;

    let obs = std::sync::Arc::clone(&state.highid_observe);
    // Shed load rather than queue it: a reconnect storm is when this matters
    // least and costs most. A mark is left as it is when its re-check is shed.
    let permit = match std::sync::Arc::clone(&obs.permits).try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            obs.skipped_busy.fetch_add(1, Relaxed);
            return;
        }
    };
    // And the server-wide probe ceiling shared with login probes (#25).
    let Some(global_permit) = state.admission.probes.try_take() else {
        obs.skipped_busy.fetch_add(1, Relaxed);
        return;
    };
    let ident = HighIdProbeIdent::from_config(live);
    let supports_crypt = client_flags & SRVCAP_SUPPORTCRYPT != 0;
    let ttl = std::time::Duration::from_secs(live.network.highid_wrong_hash_ttl_secs.max(1));

    tokio::spawn(async move {
        let _permit = permit;
        let _global_permit = global_permit;
        let outcome =
            highid_identity_answer(ip, port, user_hash, ident, timeout_ms, supports_crypt).await;
        let check = record_highid_outcome(&obs, ip, port, user_hash, outcome, marking);
        if marking {
            apply_highid_mark(&obs, ip, port, user_hash, check, ttl);
        }
    });
}

/// Observe mode: count only. The name the observe tests use.
#[cfg(test)]
fn spawn_highid_observe(
    state: &ServerState,
    live: &Config,
    ip: IpAddr,
    port: u16,
    user_hash: [u8; 16],
    client_flags: u32,
    timeout_ms: u64,
) {
    spawn_highid_check(
        state,
        live,
        ip,
        port,
        user_hash,
        client_flags,
        timeout_ms,
        false,
    );
}

/// Process a LOGINREQUEST and register the client.
pub async fn handle_login(
    // Unused since the ID assignment moved to live_cfg, but kept so callers do
    // not have to change.
    _cfg: &Config,
    state: &ServerState,
    peer_ip: IpAddr,
    req: LoginRequest,
) -> ClientHandle {
    let client_flags = req.server_flags();
    let client_ipv6 = req.client_ipv6();
    let (assigned_id, is_high_id, source_ip) =
        assign_client_id_for(state, peer_ip, req.port, Some(&req.user_hash), client_flags).await;
    // limits.max_string_size (live): the nick is stored and shown, so it is
    // capped like any other stored string.
    let max_string = state.live_cfg.load().limits.max_string_size;
    let nick =
        crate::proto::tags::cap_string(req.nick().unwrap_or("(no name)"), max_string).to_string();
    let server_flags = client_flags;

    // Debug: log every parsed tag to diagnose field extraction
    debug!(
        tag_count = req.tags.len(),
        raw_nick = ?req.nick(),
        raw_flags = server_flags,
        "loginrequest parsed"
    );
    for (i, t) in req.tags.iter().enumerate() {
        debug!(i, name = ?t.name, value = ?t.value, "login tag");
    }

    // ─── Country lookup (for per-client field, shown in web UI) ──────────
    // IPv4 and IPv6 alike when a MaxMind DB is loaded; the CSV knows IPv4 only.
    let country = state
        .country_db
        .read()
        .await
        .lookup(peer_ip)
        .map(|(code, _)| code)
        .unwrap_or_else(|| "??".to_string());

    // ─── Client software detection ────────────────────────────────────────
    // Multi-pass detection using all available tags:
    //  CT_EMULE_VERSION (0xFB) top 8 bits: clientid → EClientSoftware enum
    //    0=eMule, 1=cDonkey/jed2k, 2=xMule, 3=aMule, 4=Shareaza, 10=mldonkey, 20=lphant
    //  CT_MOD_VERSION (0x55): mod name string (also used by mldonkey to identify itself)
    //  CT_EMULECOMPAT_OPTIONS1 (0xEF) / MISCOPTIONS: presence = eMule-protocol client
    //  Fallback: "eD2k-basic" for plain eD2k without eMule extensions

    let mut compat_id: Option<u8> = None;
    let mut mod_name_str: Option<String> = None;
    let mut has_emule_ext = false;
    let mut has_emule_ver_tag = false;
    // Client's UDP port for LowID↔LowID NAT traversal. CT_EMULE_UDPPORTS (0xf9)
    // is a u32 tag: high 16 bits = Kad UDP port, low 16 bits = client UDP port.
    // Stock eMule does NOT send this tag to servers (it only sends 4 login tags),
    // so it stays 0 for unmodified clients — only our NAT-traversal client mod
    // adds it, which is exactly how we detect mod-capable clients (see below).
    let mut udp_port: u16 = 0;

    for t in &req.tags {
        if let TagName::Byte(id) = t.name {
            match id {
                CT_EMULE_VERSION => {
                    if let Some(v) = t.as_u32() {
                        compat_id = Some((v >> 24) as u8);
                        has_emule_ver_tag = true;
                    }
                }
                CT_MOD_VERSION => {
                    mod_name_str = t.str_value().map(str::to_string);
                }
                CT_EMULE_UDPPORTS => {
                    if let Some(v) = t.as_u32() {
                        udp_port = (v & 0xFFFF) as u16;
                    }
                }
                CT_EMULE_MISCOPTIONS1 | CT_EMULE_MISCOPTIONS2 => {
                    has_emule_ext = true;
                }
                0xEF => {
                    has_emule_ext = true;
                } // CT_EMULECOMPAT_OPTIONS1
                _ => {}
            }
        }
    }

    // Check if CT_MOD_VERSION string says "mldonkey"
    let mod_is_mldonkey = mod_name_str
        .as_deref()
        .map(|s| s.to_lowercase().starts_with("mldonkey"))
        .unwrap_or(false);

    let software = if mod_is_mldonkey {
        "mldonkey".to_string()
    } else if has_emule_ver_tag {
        let cid = compat_id.unwrap_or(0);
        if cid == CLIENTID_EMULE {
            // clientid=0: eMule or one of its mods. CT_MOD_VERSION has mod name.
            mod_name_str
                .as_deref()
                .map(|s| {
                    let lower = s.to_lowercase();
                    if lower.contains("emule+") || lower.contains("emuleplus") {
                        "eMulePlus".to_string()
                    } else if lower.contains("xtreme") {
                        "eMule-Xtreme".to_string()
                    } else if lower.contains("mephisto") || lower.contains("Mephisto") {
                        "eMule-Mephisto".to_string()
                    } else {
                        format!("eMule-{}", s.split_whitespace().next().unwrap_or(s))
                    }
                })
                .unwrap_or_else(|| "eMule".to_string())
        } else {
            match cid {
                CLIENTID_CDONKEY => "cDonkey".to_string(), // also: jed2k
                CLIENTID_XMULE => "xMule".to_string(),
                CLIENTID_AMULE => "aMule".to_string(),
                CLIENTID_SHAREAZA => "Shareaza".to_string(),
                CLIENTID_MLDONKEY => "mldonkey".to_string(),
                CLIENTID_LPHANT => "lphant".to_string(),
                n => format!("compat({})", n),
            }
        }
    } else if let Some(ref mname) = mod_name_str {
        // Has CT_MOD_VERSION but no CT_EMULE_VERSION
        let lower = mname.to_lowercase();
        if lower.starts_with("mldonkey") {
            "mldonkey".to_string()
        } else if lower.contains("emule+") {
            "eMulePlus".to_string()
        } else {
            format!("eMule-{}", mname.split_whitespace().next().unwrap_or(mname))
        }
    } else if has_emule_ext {
        "eMule-old".to_string()
    } else {
        // Plain eD2k, no eMule extensions. Log tags to improve detection.
        debug!(
            ip = %peer_ip,
            tags = ?req.tags.iter()
                .map(|t| format!("{:?}={:?}", t.name, t.value))
                .collect::<Vec<_>>(),
            "unrecognized client (no eMule tags) — all tags logged"
        );
        "eD2k-basic".to_string()
    };

    // Heuristic: well-known nicks override CT_EMULE_VERSION clientid.
    // - "nolistsrvs", "Glen Carter" → mldonkey "no list servers" mode
    // - "jed2k" → Java eD2k client (often used as mldonkey alternative)
    // These cover the compat(40) / unknown clientid cases user reported.
    let nick_lower = nick.to_lowercase();
    let software = if software.starts_with("compat(") || software == "eD2k-basic" {
        if nick_lower.contains("nolistsrvs") || nick_lower.contains("mldonkey") {
            "mldonkey".to_string()
        } else if nick_lower == "jed2k" || nick_lower.contains("jed2k") {
            "jed2k".to_string()
        } else {
            software
        }
    } else {
        software
    };

    let handle = ClientHandle {
        user_hash: req.user_hash,
        assigned_id,
        // Usually the login address; the public one for a verified hairpin
        // client, since this is what gets published as a source.
        ip: source_ip,
        port: req.port,
        udp_port,
        natt_capable: udp_port != 0,
        nick: nick.clone(),
        server_flags,
        is_high_id,
        // ⚠ THE BARE CAPABILITY BIT IS NOT ACCEPTED, and the asymmetry of the
        //   two mistakes is why. Judging a client capable when it is not means
        //   sending it a source record 16 bytes longer than the one it expects,
        //   and it then reads the next record from the middle of this one and
        //   mis-parses the rest of the packet. Judging a capable client
        //   incapable costs it nothing but classic records.
        //
        //   `SRVCAP_IPV6` (0x1000) alone is too weak to carry that risk. The
        //   published spec states the bit and `CT_MOD_IP_V6` are strictly
        //   coupled — send both or neither — and warns in the same paragraph
        //   that 0x1000 is reused unofficially elsewhere and should not be
        //   treated as authoritative on its own. A client presenting the bit
        //   without the tag is therefore not the client this was written for.
        //
        //   So: the tag, or a session that actually arrived over IPv6. Both are
        //   observations rather than assertions.
        ipv6_capable: client_ipv6.is_some() || matches!(peer_ip, IpAddr::V6(_)),
        // Prefer the address the session actually arrived from over the one the
        // client claims. A socket address is observed; a tag is asserted, and a
        // client that gets its own address wrong (or lies about it) would
        // otherwise have that address handed to every peer asking for sources.
        ipv6: match peer_ip {
            IpAddr::V6(a) if is_publishable_ipv6(a) => Some(a),
            _ => client_ipv6.filter(|a| is_publishable_ipv6(*a)),
        },
        connected_at: Instant::now(),
        country: country.clone(),
        software: software.clone(),
        csam_attempts: 0,
        soft_limit_warned: false,
        offer_policy: None,
        slot: Default::default(),
        tx: None,
        last_activity_ms: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
            ClientHandle::now_ms(),
        )),
    };

    info!(
        ip = %peer_ip, nick = %nick, id = assigned_id,
        high_id = is_high_id, country = %country, software = %software,
        flags = format!("0x{:04x}", server_flags),
        "client logged in"
    );
    debug!(?req.tags, "login tags");

    handle
}

#[cfg(test)]
mod tests {
    // ⚠ NEEDED SINCE THE CAPABILITY CONSTANTS MOVED TO opcodes.rs. They used to
    //   be `const` declarations in this file, which a test could name without
    //   importing anything; they are now `use` aliases, and a glob does not
    //   carry those into a child module the way a local item is carried. The
    //   build broke on three assertions that had never had an import line.
    use super::*;
    // The alias itself. `use super::*` re-exports what login.rs names, and
    // login.rs reaches the capability bits through `opcodes::*` under their
    // real names, so the SRVCAP_ spelling exists nowhere until it is written
    // down. Without this line `cargo test` does not compile — which is how it
    // stayed broken while `cargo build` kept passing: the three uses below are
    // all inside `#[cfg(test)]`.
    use crate::proto::opcodes::CAPABLE_IPV6 as SRVCAP_IPV6;

    // ── OP_SERVERIDENT server hash ─────────────────────────────────────────
    #[test]
    fn the_server_hash_is_stable_per_seckey_and_differs_between_servers() {
        let a = server_ident_hash_for(&[1; 16]);
        assert_eq!(a, server_ident_hash_for(&[1; 16]), "stable");
        assert_ne!(a, server_ident_hash_for(&[2; 16]), "per server");
        // Not the old shared constant, not the HighID probe identity, not eFarm.
        assert_ne!(&a[..4], b"\xDE\xAD\xBE\xEF");
        assert_ne!(
            a,
            crate::server::highid_probe::server_pseudo_user_hash(&[1; 16])
        );
        assert_ne!(&a[..4], &[0x2A; 4]);
    }

    #[test]
    fn serverident_carries_the_derived_hash() {
        let mut cfg = crate::config::Config::minimal_test_config();
        cfg.server.this_ip = "85.17.116.222".to_string();
        let cfg = std::sync::Arc::new(cfg);
        let state = ServerState::new(
            std::sync::Arc::new(crate::filter::ContentFilter::new()),
            std::sync::Arc::clone(&cfg),
        );
        let client = ClientHandle {
            user_hash: [7; 16],
            assigned_id: 42,
            ip: IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)),
            port: 4662,
            udp_port: 0,
            natt_capable: false,
            nick: "t".into(),
            server_flags: 0,
            ipv6_capable: false,
            ipv6: None,
            is_high_id: false,
            connected_at: Instant::now(),
            country: "??".into(),
            software: "test".into(),
            csam_attempts: 0,
            soft_limit_warned: false,
            offer_policy: None,
            slot: Default::default(),
            tx: None,
            last_activity_ms: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };
        let frames = build_welcome_batch(&cfg, &state, &client);
        let ident = frames.iter().find(|f| f.opcode == OP_SERVERIDENT).unwrap();
        assert_eq!(&ident.payload[..16], &server_ident_hash(&cfg));
        assert_ne!(&ident.payload[..4], b"\xDE\xAD\xBE\xEF");
    }

    // ── OP_IDCHANGE bytes 12–15 (issue #17) ────────────────────────────────
    fn le(ip: [u8; 4]) -> u32 {
        u32::from_le_bytes(ip)
    }
    const OUR_IP: &str = "85.17.116.222";

    #[test]
    fn a_lowid_client_is_told_its_own_public_address_not_ours() {
        let peer = IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(
            reported_client_ip(peer, false, 5, OUR_IP),
            le([93, 184, 216, 34])
        );
    }

    #[test]
    fn a_highid_client_is_told_exactly_its_client_id() {
        // eMule asserts dwServerReportedIP == clientid for a HighID.
        let peer = IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34));
        let id = le([93, 184, 216, 34]);
        assert_eq!(reported_client_ip(peer, true, id, OUR_IP), id);
    }

    #[test]
    fn a_hairpin_highid_client_gets_the_public_id_not_its_lan_address() {
        // Verified through hairpin_lan_clients: recorded under our public IP,
        // id derived from it; the connection itself came from the LAN.
        let recorded = IpAddr::V4(OUR_IP.parse().unwrap());
        let id = le([85, 17, 116, 222]);
        assert_eq!(reported_client_ip(recorded, true, id, OUR_IP), id);
        // Even if the handle carried the LAN address, the id wins.
        let lan = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 30, 254));
        assert_eq!(reported_client_ip(lan, true, id, OUR_IP), id);
    }

    #[test]
    fn a_lowid_client_on_our_lan_is_told_our_public_address() {
        // Behind the same NAT as the server, its public address IS ours. The
        // private address must never be handed out as a public one.
        for lan in [
            std::net::Ipv4Addr::new(192, 168, 30, 254),
            std::net::Ipv4Addr::new(10, 0, 0, 7),
            std::net::Ipv4Addr::new(172, 16, 5, 5),
            std::net::Ipv4Addr::new(127, 0, 0, 1),
        ] {
            assert_eq!(
                reported_client_ip(IpAddr::V4(lan), false, 5, OUR_IP),
                le([85, 17, 116, 222]),
                "{lan}"
            );
        }
    }

    #[test]
    fn a_lan_client_gets_zero_when_our_own_address_is_unknown_or_private() {
        let lan = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 5));
        assert_eq!(reported_client_ip(lan, false, 5, ""), 0);
        assert_eq!(reported_client_ip(lan, false, 5, "192.168.1.1"), 0);
        assert_eq!(reported_client_ip(lan, false, 5, "garbage"), 0);
    }

    #[test]
    fn a_lowid_from_an_address_ending_in_zero_reports_zero_issue_26() {
        let dot0 = IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 0));
        assert_eq!(reported_client_ip(dot0, false, 5, OUR_IP), 0);
    }

    #[test]
    fn an_ipv6_session_reports_no_ipv4() {
        let v6 = IpAddr::V6("2001:db8::1".parse().unwrap());
        assert_eq!(reported_client_ip(v6, false, 5, OUR_IP), 0);
    }

    #[test]
    fn the_welcome_batch_carries_the_client_address_and_serverident_keeps_ours() {
        let mut cfg = crate::config::Config::minimal_test_config();
        cfg.server.this_ip = OUR_IP.to_string();
        let cfg = std::sync::Arc::new(cfg);
        let state = ServerState::new(
            std::sync::Arc::new(crate::filter::ContentFilter::new()),
            std::sync::Arc::clone(&cfg),
        );
        let client = ClientHandle {
            user_hash: [7; 16],
            assigned_id: 42,
            ip: IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)),
            port: 4662,
            udp_port: 0,
            natt_capable: false,
            nick: "t".into(),
            server_flags: 0,
            ipv6_capable: false,
            ipv6: None,
            is_high_id: false,
            connected_at: Instant::now(),
            country: "??".into(),
            software: "test".into(),
            csam_attempts: 0,
            soft_limit_warned: false,
            offer_policy: None,
            slot: Default::default(),
            tx: None,
            last_activity_ms: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };
        let frames = build_welcome_batch(&cfg, &state, &client);
        let idc = frames.iter().find(|f| f.opcode == OP_IDCHANGE).unwrap();
        assert_eq!(&idc.payload[12..16], &[93, 184, 216, 34]);
        let ident = frames.iter().find(|f| f.opcode == OP_SERVERIDENT).unwrap();
        assert_eq!(&ident.payload[16..20], &[85, 17, 116, 222]);
    }

    #[test]
    fn an_ipv6_peer_is_never_given_a_high_id() {
        // An eD2k client id IS a 32-bit IPv4 address, so there is no HighID an
        // IPv6-only peer could hold. The bug this guards: the probe used to run
        // for such a peer, `high_id_from_ip` returned None, the code fell
        // through to a LOW id — and returned it flagged as HighID. Source
        // replies then published the peer as directly reachable, and the
        // sentinel rule, which fires only for non-HighID sources, skipped the
        // one peer it exists for.
        use crate::server::highid_probe::high_id_from_ip;
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(high_id_from_ip(v6).is_none());
    }

    #[test]
    fn only_a_globally_usable_ipv6_is_published() {
        use std::net::Ipv6Addr;
        for bad in [
            "fe80::1",
            "fd00::1",
            "::1",
            "::",
            "ff02::1",
            "::ffff:1.2.3.4",
        ] {
            let a: Ipv6Addr = bad.parse().unwrap();
            assert!(!is_publishable_ipv6(a), "{bad}");
        }
        for good in ["2001:db8::1", "2a01:4f8::1"] {
            let a: Ipv6Addr = good.parse().unwrap();
            assert!(is_publishable_ipv6(a), "{good}");
        }
    }

    #[test]
    fn the_two_capability_bits_are_not_the_same_value() {
        // The single easiest thing to get backwards here: client->server says
        // 0x1000 in CT_SERVER_FLAGS, server->client says 0x4000 in the IDCHANGE
        // and ping flag words. Both published specs define the asymmetry.
        assert_eq!(SRVCAP_IPV6, 0x1000);
        assert_eq!(SRV_TCPFLG_IPV6, 0x4000);
        assert_ne!(SRVCAP_IPV6, SRV_TCPFLG_IPV6);
        // ...and the server bit must not collide with the flags already sent.
        assert_eq!(
            0x0000_05DD & SRV_TCPFLG_IPV6,
            0,
            "collides with existing flags"
        );
    }

    #[test]
    fn the_bare_capability_bit_does_not_make_a_client_capable() {
        // The two mistakes are not symmetric. Treating a client as capable when
        // it is not sends it a record 16 bytes longer than it expects and breaks
        // its parse of everything after; treating a capable client as incapable
        // costs it nothing but classic records. 0x1000 alone does not carry that
        // risk: the spec couples it to CT_MOD_IP_V6 ("send both or neither") and
        // warns the value is reused unofficially elsewhere.
        //
        // The evidence that made this concrete: a live server showed nine
        // sessions counted capable against three holding an address — six
        // clients presenting the bit with no tag, which the spec says should not
        // happen and which therefore means they mean something else by it.
        let with_bit_only = LoginRequest {
            user_hash: [0u8; 16],
            claimed_id: 0,
            port: 4662,
            tags: vec![Tag::byte(CT_SERVER_FLAGS, TagValue::U32(SRVCAP_IPV6))],
        };
        assert!(
            with_bit_only.client_ipv6().is_none(),
            "the bit is not an address and must not be read as one"
        );
    }

    #[test]
    fn the_status_bits_are_never_set_to_unknown() {
        // The tag is omitted when there is no verdict, so a client that sees it
        // can trust every bit: unset means no, never unknown. PROBED in
        // particular must stay clear — we accept the address on trust and never
        // dial it back, and claiming a check we do not perform would let a
        // client draw a stronger conclusion than the evidence supports.
        assert_eq!(IPV6ST_HAVE, 0x01);
        assert_eq!(IPV6ST_REACHABLE, 0x02);
        assert_eq!(IPV6ST_HAVE | IPV6ST_REACHABLE, 0x03);
        // 0x04 (PROBED) is deliberately not defined here.
        assert_eq!((IPV6ST_HAVE | IPV6ST_REACHABLE) & 0x04, 0);
    }

    #[test]
    fn one_rule_decides_whether_an_ipv6_may_be_published() {
        // Two functions answering this differently is how an address gets
        // filtered on one path and published on the other. The state-level
        // check now delegates here, so a link-local cannot be recorded by one
        // and emitted by the other.
        use crate::state::ServerState;
        use std::net::{IpAddr, Ipv6Addr};
        for a in ["fe80::1", "fd00::1", "::1", "ff02::1", "::ffff:1.2.3.4"] {
            let v6: Ipv6Addr = a.parse().unwrap();
            assert_eq!(
                is_publishable_ipv6(v6),
                ServerState::is_publishable_source_ip(IpAddr::V6(v6)),
                "{a}: the two checks disagree"
            );
            assert!(!is_publishable_ipv6(v6), "{a}");
        }
        let good: Ipv6Addr = "2a01:4f8::1".parse().unwrap();
        assert!(is_publishable_ipv6(good));
        assert!(ServerState::is_publishable_source_ip(IpAddr::V6(good)));
    }

    #[test]
    fn the_ipv6_tag_is_accepted_only_as_a_16_byte_hash() {
        // Accepting any tag type would let a client with a string in 0xAE be
        // read as v6-reachable, and the tag's presence is itself a capability
        // signal.
        let mk = |v: TagValue| LoginRequest {
            user_hash: [0u8; 16],
            claimed_id: 0,
            port: 4662,
            tags: vec![Tag::byte(CT_MOD_IP_V6, v)],
        };
        assert!(mk(TagValue::String("2001:db8::1".into()))
            .client_ipv6()
            .is_none());
        assert!(mk(TagValue::U32(1)).client_ipv6().is_none());
        assert!(mk(TagValue::Blob(vec![0u8; 4])).client_ipv6().is_none());
        let mut raw = [0u8; 16];
        raw[0] = 0x20;
        raw[1] = 0x01;
        raw[15] = 0x01;
        assert_eq!(
            mk(TagValue::Blob(raw.to_vec())).client_ipv6(),
            Some(std::net::Ipv6Addr::from(raw))
        );
    }

    /// user_hash(16) + claimed_id(4) + port(2) = the shortest legitimate login.
    fn head() -> Vec<u8> {
        let mut v = vec![0xAAu8; 16];
        v.extend_from_slice(&0u32.to_le_bytes()); // claimed id
        v.extend_from_slice(&4662u16.to_le_bytes());
        v
    }

    #[test]
    fn login_boundary_lengths_never_panic() {
        // The reported bug: 22..=25 bytes passed the `< 22` guard, took the
        // no-tags branch, then panicked slicing `&payload[26..]`. Unauthenticated
        // and reachable on a client's first message.
        for extra in 0..4usize {
            let mut p = head();
            p.extend(std::iter::repeat(0u8).take(extra));
            assert_eq!(p.len(), 22 + extra);
            let r = LoginRequest::parse(&p).expect("22..=25 bytes must parse, not panic");
            assert_eq!(r.port, 4662);
            assert!(r.tags.is_empty(), "no tag section at this length");
        }
    }

    #[test]
    fn login_too_short_is_an_error_not_a_panic() {
        for len in 0..22usize {
            let p = vec![0u8; len];
            assert!(
                LoginRequest::parse(&p).is_err(),
                "{len} bytes is below the minimum and must be rejected"
            );
        }
    }

    #[test]
    fn login_with_tags_still_parses() {
        // 26 bytes and up: the normal path stock eMule takes — ServerConnect.cpp
        // always writes a tag count, so a real client is never in the short case.
        let mut p = head();
        p.extend_from_slice(&0u32.to_le_bytes()); // tag_count = 0
        assert_eq!(p.len(), 26);
        let r = LoginRequest::parse(&p).expect("26 bytes with zero tags");
        assert!(r.tags.is_empty());
        assert_eq!(r.claimed_id, 0);
    }

    #[test]
    fn declared_tag_count_beyond_the_buffer_is_survivable() {
        // This test found a worse bug than the one it was written for:
        // read_tag_list pre-allocated from the wire-supplied count, so this
        // frame asked the allocator for ~240 GB and ABORTED THE PROCESS. Fixed
        // in proto::tags; kept here because login is the reachable path — an
        // unauthenticated peer's first message.
        let mut p = head();
        p.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let r = LoginRequest::parse(&p).expect("must not panic on a lying tag count");
        assert!(r.tags.is_empty());
    }
}

#[cfg(test)]
mod highid_observe_tests {
    //! The observation path must count, never decide. These run the real
    //! identity probe against local listeners that behave like the three kinds
    //! of port found on the network.
    use super::*;
    use std::sync::atomic::Ordering::Relaxed;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn state() -> Arc<ServerState> {
        let cfg = Arc::new(crate::config::Config::minimal_test_config());
        Arc::new(ServerState::new(
            Arc::new(crate::filter::ContentFilter::new()),
            cfg,
        ))
    }

    async fn wait_for(
        state: &ServerState,
        pred: impl Fn(&HighIdObserveView) -> bool,
    ) -> HighIdObserveView {
        for _ in 0..200 {
            let v = HighIdObserveView::of(state);
            if pred(&v) {
                return v;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        HighIdObserveView::of(state)
    }

    #[derive(Debug)]
    struct HighIdObserveView {
        verified: u64,
        mismatch: u64,
        no_answer: u64,
        skipped: u64,
    }
    impl HighIdObserveView {
        fn of(s: &ServerState) -> Self {
            let o = &s.highid_observe;
            Self {
                verified: o.verified.load(Relaxed),
                mismatch: o.mismatch.load(Relaxed),
                no_answer: o.no_answer.load(Relaxed),
                skipped: o.skipped_busy.load(Relaxed),
            }
        }
    }

    /// Accept one connection, read the hello, answer OP_HELLOANSWER carrying
    /// `hash` — what a real client behind an open port does.
    async fn answering_listener(hash: [u8; 16]) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let _ = c.read(&mut buf).await;
            let mut body = vec![0x4Cu8]; // OP_HELLOANSWER
            body.extend_from_slice(&hash);
            body.extend_from_slice(&[0u8; 4 + 2 + 4 + 4 + 2]); // id, port, 0 tags, server ip, port
            let mut frame = vec![0xE3u8];
            frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
            frame.extend_from_slice(&body);
            let _ = c.write_all(&frame).await;
        });
        port
    }

    /// Accept and close without a byte — a port that is open but has no eD2k
    /// client behind it. The case Lugdunum turns into LowID and we do not.
    async fn silent_listener() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((c, _)) = l.accept().await {
                drop(c);
            }
        });
        port
    }

    const LOCAL: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    /// What a port that accepts and immediately closes looks like to the probe.
    ///
    /// ⚠ TWO REASONS FOR ONE EVENT. If the peer closes before our HELLO lands in
    ///   its receive buffer, the kernel sends FIN and we read "peer closed without
    ///   sending a byte". If the HELLO is already sitting there unread, closing
    ///   sends RST and the read fails instead. Which one happens is a race. The
    ///   same applies on the live network — eMule rejecting our address through
    ///   its IP filter shows up under both names — so the two counts belong
    ///   together when reading the Status tab.
    const SILENT_CLOSE: [Result<bool, &str>; 2] = [
        Err("peer closed without sending a byte"),
        Err("read failed"),
    ];

    #[tokio::test]
    async fn a_public_address_ending_in_zero_gets_lowid_without_a_probe_issue_26() {
        let st = state();
        let dot0 = IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 0));
        let (id, high, _) = assign_client_id_for(&st, dot0, 4662, None, 0).await;
        assert!(!high);
        assert!(id < crate::server::highid_probe::LOWID_CEILING && id != 0);
        assert_eq!(st.admission.probes.in_use(), 0);
        assert_eq!(
            st.admission.probes.rejected(),
            0,
            "no probe slot was even asked for"
        );
    }

    #[tokio::test]
    async fn a_full_probe_ceiling_gives_lowid_without_probing() {
        // issue #25: the login does not wait for a probe slot.
        let st = state();
        let cap = st.admission.probes.cap() as usize;
        let held: Vec<_> = (0..cap)
            .map(|_| st.admission.probes.try_take().unwrap())
            .collect();
        let public = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 77));
        let t0 = std::time::Instant::now();
        let (_, high, _) = assign_client_id_for(&st, public, 4662, None, 0).await;
        assert!(!high);
        assert!(
            t0.elapsed() < std::time::Duration::from_millis(200),
            "no probe was run"
        );
        assert_eq!(st.admission.probe_shed_lowid.load(Relaxed), 1);
        // A background check is shed as well, counted as busy.
        let live = st.live_cfg.load_full();
        spawn_highid_observe(&st, &live, LOCAL, 1, [1; 16], 0, 2000);
        assert_eq!(st.highid_observe.skipped_busy.load(Relaxed), 1);
        drop(held);
        assert_eq!(st.admission.probes.in_use(), 0);
    }

    #[tokio::test]
    async fn a_port_that_answers_with_the_right_hash_is_verified() {
        let st = state();
        let live = st.live_cfg.load_full();
        let uh = [0x42u8; 16];
        let port = answering_listener(uh).await;
        spawn_highid_observe(&st, &live, LOCAL, port, uh, 0, 2000);
        let v = wait_for(&st, |v| v.verified + v.mismatch + v.no_answer > 0).await;
        assert_eq!((v.verified, v.mismatch, v.no_answer), (1, 0, 0), "{v:?}");
    }

    #[tokio::test]
    async fn a_port_answering_for_someone_else_is_a_mismatch() {
        let st = state();
        let live = st.live_cfg.load_full();
        let port = answering_listener([0x99u8; 16]).await;
        spawn_highid_observe(&st, &live, LOCAL, port, [0x42u8; 16], 0, 2000);
        let v = wait_for(&st, |v| v.verified + v.mismatch + v.no_answer > 0).await;
        assert_eq!((v.verified, v.mismatch, v.no_answer), (0, 1, 0), "{v:?}");
        // Both hashes are kept, so the case can be traced to a second client.
        let rec: Vec<_> = st
            .highid_observe
            .recent_mismatches
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect();
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0].login_hash, [0x42u8; 16]);
        assert_eq!(rec[0].answered_hash, [0x99u8; 16]);
        assert_eq!((rec[0].ip, rec[0].port), (LOCAL, port));
    }

    #[tokio::test]
    async fn the_hairpin_wrapper_still_answers_true_and_false() {
        // probe_identity is now a comparison over probe_identity_hash. The
        // hairpin VERDICT path calls it, so its results must be unchanged.
        use crate::server::highid_probe::{probe_identity, probe_identity_hash};
        let ours = [0x11u8; 16];
        let port = answering_listener([0x42u8; 16]).await;
        assert_eq!(
            probe_identity(LOCAL, port, &[0x42u8; 16], &ours, 0, 4661, 2000, false).await,
            Ok(true)
        );
        let port = answering_listener([0x99u8; 16]).await;
        assert_eq!(
            probe_identity(LOCAL, port, &[0x42u8; 16], &ours, 0, 4661, 2000, false).await,
            Ok(false)
        );
        let port = answering_listener([0x99u8; 16]).await;
        assert_eq!(
            probe_identity_hash(LOCAL, port, &[0x42u8; 16], &ours, 0, 4661, 2000, false).await,
            Ok([0x99u8; 16])
        );
        let port = silent_listener().await;
        let r = probe_identity(LOCAL, port, &[0x42u8; 16], &ours, 0, 4661, 2000, false).await;
        assert!(SILENT_CLOSE.contains(&r), "{r:?}");
    }

    fn h(hex_str: &str) -> [u8; 16] {
        let v = hex::decode(hex_str).unwrap();
        let mut a = [0u8; 16];
        a.copy_from_slice(&v);
        a
    }

    #[test]
    fn a_different_type_marker_is_the_same_client() {
        use crate::server::highid_probe::same_client_hash;
        // Real pairs from the live server: login hash with eMule's 0E/6F,
        // hello answer with MLDonkey's 4D/4C, the other 14 bytes identical.
        for (login, answered) in [
            (
                "b060873b2d0ed162b0b037c02c716f0e",
                "b060873b2d4dd162b0b037c02c714c0e",
            ),
            (
                "cd312acd250e88cdf553e432744a6f89",
                "cd312acd254d88cdf553e432744a4c89",
            ),
        ] {
            assert!(
                same_client_hash(&h(login), &h(answered)),
                "{login} vs {answered}"
            );
        }
        // Real pair of genuinely different clients (the second machine behind
        // one NAT): must stay different.
        assert!(!same_client_hash(
            &h("8746e2693c0e1e4a165d044caf576f7b"),
            &h("5ba688ae970e78131fcb5020950f6fe1")
        ));
        // One byte outside the marker positions is enough to be different.
        let a = h("b060873b2d0ed162b0b037c02c716f0e");
        for i in (0..16).filter(|i| *i != 5 && *i != 14) {
            let mut b = a;
            b[i] ^= 0x01;
            assert!(!same_client_hash(&a, &b), "byte {i} must count");
        }
    }

    #[tokio::test]
    async fn a_marker_variant_is_verified_and_counted_separately() {
        let st = state();
        let live = st.live_cfg.load_full();
        let login = h("b060873b2d0ed162b0b037c02c716f0e");
        let port = answering_listener(h("b060873b2d4dd162b0b037c02c714c0e")).await;
        spawn_highid_observe(&st, &live, LOCAL, port, login, 0, 2000);
        let v = wait_for(&st, |v| v.verified + v.mismatch + v.no_answer > 0).await;
        assert_eq!((v.verified, v.mismatch, v.no_answer), (1, 0, 0), "{v:?}");
        assert_eq!(st.highid_observe.verified_marker_variant.load(Relaxed), 1);
        assert!(st
            .highid_observe
            .recent_mismatches
            .lock()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn the_hairpin_wrapper_accepts_a_marker_variant() {
        // The verdict path: this client IS the host behind the port.
        use crate::server::highid_probe::probe_identity;
        let port = answering_listener(h("b060873b2d4dd162b0b037c02c714c0e")).await;
        assert_eq!(
            probe_identity(
                LOCAL,
                port,
                &h("b060873b2d0ed162b0b037c02c716f0e"),
                &[0x11; 16],
                0,
                4661,
                2000,
                false
            )
            .await,
            Ok(true)
        );
    }

    #[test]
    fn mismatches_are_classified_against_who_is_connected() {
        let st = ServerState::for_test();
        // register_test_client puts id N at 10.0.0.(N+1).
        st.register_test_client([0xB1; 16], 1, true, 0); // 10.0.0.2
        st.register_test_client([0xB2; 16], 2, true, 0); // 10.0.0.3
        let rec = |ip: [u8; 4], answered: [u8; 16]| crate::state::HighIdMismatch {
            at: 0,
            ip: IpAddr::V4(std::net::Ipv4Addr::from(ip)),
            port: 4662,
            login_hash: [0xA0; 16],
            answered_hash: answered,
            marked: false,
        };
        let o = &st.highid_observe;
        // Second client behind the same NAT: answered hash is logged in from
        // exactly the address we probed.
        o.record_mismatch(rec([10, 0, 0, 2], [0xB1; 16]));
        // Answered hash is logged in, but from somewhere else.
        o.record_mismatch(rec([10, 0, 0, 9], [0xB2; 16]));
        // Answered hash is not connected to us at all.
        o.record_mismatch(rec([10, 0, 0, 7], [0xCC; 16]));
        assert_eq!(o.classify_mismatches(&st.clients), (1, 1, 1, 3));
    }

    #[test]
    fn the_mismatch_buffer_is_bounded() {
        let st = ServerState::for_test();
        for i in 0..(crate::state::HighIdObserve::RECENT_MISMATCHES + 50) {
            st.highid_observe
                .record_mismatch(crate::state::HighIdMismatch {
                    at: i as u64,
                    ip: LOCAL,
                    port: 1,
                    login_hash: [0; 16],
                    answered_hash: [1; 16],
                    marked: false,
                });
        }
        let q = st.highid_observe.recent_mismatches.lock().unwrap();
        assert_eq!(q.len(), crate::state::HighIdObserve::RECENT_MISMATCHES);
        assert_eq!(
            q.back().unwrap().at,
            (crate::state::HighIdObserve::RECENT_MISMATCHES + 49) as u64
        );
    }

    #[tokio::test]
    async fn an_open_but_silent_port_is_counted_with_its_reason() {
        // The exact situation cap_probe.py measured: TCP accepted, nothing said.
        // The plain probe calls this HighID; this path must say so plainly.
        let st = state();
        let live = st.live_cfg.load_full();
        let port = silent_listener().await;
        spawn_highid_observe(&st, &live, LOCAL, port, [0x42u8; 16], 0, 2000);
        let v = wait_for(&st, |v| v.verified + v.mismatch + v.no_answer > 0).await;
        assert_eq!((v.verified, v.mismatch, v.no_answer), (0, 0, 1), "{v:?}");
        let reasons: Vec<&str> = st.highid_observe.reasons.iter().map(|e| *e.key()).collect();
        assert_eq!(reasons.len(), 1);
        assert!(SILENT_CLOSE.contains(&Err(reasons[0])), "{reasons:?}");
    }

    #[tokio::test]
    async fn a_full_cap_sheds_instead_of_queueing() {
        let st = state();
        let live = st.live_cfg.load_full();
        // Take every permit, as a reconnect storm would.
        let _held = Arc::clone(&st.highid_observe.permits)
            .acquire_many_owned(crate::state::HighIdObserve::MAX_CONCURRENT as u32)
            .await
            .unwrap();
        let port = silent_listener().await;
        spawn_highid_observe(&st, &live, LOCAL, port, [0x42u8; 16], 0, 2000);
        let v = HighIdObserveView::of(&st);
        assert_eq!(v.skipped, 1);
        assert_eq!(
            v.verified + v.mismatch + v.no_answer,
            0,
            "nothing was probed"
        );
    }

    // ─── verdict mode: network.highid_downgrade_on_wrong_hash ─────────────

    fn verdict_live(st: &ServerState) -> Arc<crate::config::Config> {
        let mut c = (*st.live_cfg.load_full()).clone();
        c.network.highid_downgrade_on_wrong_hash = true;
        Arc::new(c)
    }

    async fn settle(st: &ServerState) {
        wait_for(st, |v| v.verified + v.mismatch + v.no_answer > 0).await;
        // The mark is applied right after the counters, in the same task.
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }

    #[tokio::test]
    async fn a_wrong_hash_marks_the_login_for_next_time() {
        let st = state();
        let live = verdict_live(&st);
        let uh = h("b060873b2d0ed162b0b037c02c716f0e");
        let port = answering_listener(h("8746e2693c0e1e4a165d044caf576f7b")).await;
        assert!(!st.highid_observe.is_marked(LOCAL, port, &uh));
        spawn_highid_check(&st, &live, LOCAL, port, uh, 0, 2000, true);
        settle(&st).await;
        assert!(st.highid_observe.is_marked(LOCAL, port, &uh));
        // Only this exact login is marked: another hash, or another port, is not.
        assert!(!st.highid_observe.is_marked(LOCAL, port, &[0x42; 16]));
        assert!(!st
            .highid_observe
            .is_marked(LOCAL, port.wrapping_add(1), &uh));
        let rec = st.highid_observe.recent_mismatches.lock().unwrap();
        assert!(rec[0].marked);
    }

    #[tokio::test]
    async fn the_own_hash_again_clears_the_mark() {
        let st = state();
        let live = verdict_live(&st);
        let uh = [0x42u8; 16];
        let port = answering_listener(uh).await;
        st.highid_observe
            .mark(LOCAL, port, uh, std::time::Duration::from_secs(3600));
        spawn_highid_check(&st, &live, LOCAL, port, uh, 0, 2000, true);
        settle(&st).await;
        assert!(!st.highid_observe.is_marked(LOCAL, port, &uh));
        assert_eq!(st.highid_observe.marks_cleared.load(Relaxed), 1);
    }

    #[tokio::test]
    async fn a_marker_variant_neither_marks_nor_keeps_a_mark() {
        let st = state();
        let live = verdict_live(&st);
        let uh = h("b060873b2d0ed162b0b037c02c716f0e");
        let port = answering_listener(h("b060873b2d4dd162b0b037c02c714c0e")).await;
        st.highid_observe
            .mark(LOCAL, port, uh, std::time::Duration::from_secs(3600));
        spawn_highid_check(&st, &live, LOCAL, port, uh, 0, 2000, true);
        settle(&st).await;
        assert!(
            !st.highid_observe.is_marked(LOCAL, port, &uh),
            "same client → cleared"
        );
    }

    #[tokio::test]
    async fn silence_leaves_a_mark_as_it_is() {
        let st = state();
        let live = verdict_live(&st);
        let uh = [0x42u8; 16];
        // Silent port: the peer's IP filter, say. Never sets a mark...
        let port = silent_listener().await;
        spawn_highid_check(&st, &live, LOCAL, port, uh, 0, 2000, true);
        settle(&st).await;
        assert!(!st.highid_observe.is_marked(LOCAL, port, &uh));
        // ...and never clears one either.
        let st = state();
        let port = silent_listener().await;
        st.highid_observe
            .mark(LOCAL, port, uh, std::time::Duration::from_secs(3600));
        spawn_highid_check(&st, &live, LOCAL, port, uh, 0, 2000, true);
        settle(&st).await;
        assert!(st.highid_observe.is_marked(LOCAL, port, &uh));
        assert_eq!(st.highid_observe.marks_cleared.load(Relaxed), 0);
    }

    #[tokio::test]
    async fn observe_mode_records_but_never_marks() {
        let st = state();
        let live = st.live_cfg.load_full();
        let port = answering_listener([0x99u8; 16]).await;
        spawn_highid_observe(&st, &live, LOCAL, port, [0x42u8; 16], 0, 2000);
        settle(&st).await;
        assert_eq!(st.highid_observe.mismatch.load(Relaxed), 1);
        assert!(!st.highid_observe.is_marked(LOCAL, port, &[0x42u8; 16]));
        assert!(!st.highid_observe.recent_mismatches.lock().unwrap()[0].marked);
    }

    #[tokio::test]
    async fn a_mark_expires() {
        let st = ServerState::for_test();
        let o = &st.highid_observe;
        o.mark(LOCAL, 4662, [1; 16], std::time::Duration::from_millis(20));
        assert!(o.is_marked(LOCAL, 4662, &[1; 16]));
        assert_eq!(o.marks_active(), 1);
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        assert!(!o.is_marked(LOCAL, 4662, &[1; 16]));
        assert_eq!(o.marks_active(), 0);
        assert!(
            o.wrong_hash_marks.is_empty(),
            "expired mark removed on lookup"
        );
    }

    #[test]
    fn the_mark_table_is_bounded() {
        let st = ServerState::for_test();
        let o = &st.highid_observe;
        let ttl = std::time::Duration::from_secs(3600);
        for i in 0..crate::state::HighIdObserve::MAX_MARKS {
            let mut h = [0u8; 16];
            h[..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert!(o.mark(LOCAL, 1, h, ttl));
        }
        assert!(
            !o.mark(LOCAL, 1, [0xFF; 16], ttl),
            "full table refuses a new mark"
        );
        let mut h0 = [0u8; 16];
        h0[..8].copy_from_slice(&0u64.to_le_bytes());
        assert!(
            o.mark(LOCAL, 1, h0, ttl),
            "renewing an existing mark still works"
        );
    }
}

//! Login + welcome batch handlers (SPEC.md §3.1).

use crate::config::Config;
use crate::proto::tags::read_tag_list;
use crate::proto::{
    opcodes::*, write_tag_list, Frame, Tag, TagName, TagValue,
};
use crate::state::{ClientHandle, ServerState, UserHash};
use anyhow::{anyhow, Result};
use bytes::{BufMut, BytesMut};
use std::net::IpAddr;
use std::time::Instant;
use tracing::{debug, info};

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
            return Err(anyhow!("LOGINREQUEST payload too short ({})", payload.len()));
        }
        let mut user_hash = [0u8; 16];
        user_hash.copy_from_slice(&payload[0..16]);
        let claimed_id = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
        let port = u16::from_le_bytes([payload[20], payload[21]]);
        let tag_count = if payload.len() >= 26 {
            u32::from_le_bytes([payload[22], payload[23], payload[24], payload[25]])
        } else {
            0
        };

        let mut slice = &payload[26..];
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

/// Build the canonical post-login welcome batch (SPEC.md §3.1.2):
/// IDCHANGE, SERVERSTATUS, SERVERMESSAGE, SERVERIDENT, plus optional
/// extra welcome lines.
pub fn build_welcome_batch(
    cfg: &Config,
    state: &ServerState,
    client: &ClientHandle,
) -> Vec<Frame> {
    let mut frames = Vec::new();

    // 1. IDCHANGE — 20-byte payload, format required by eMule 0.49c ServerSocket.cpp:
    //   [0-3]   client_id          (LoginAnswer_Struct.clientid)
    //   [4-7]   tcp_flags          (read at offset sizeof(LoginAnswer_Struct)=4)
    //   [8-11]  filler             (eMule skips bytes 8-11)
    //   [12-15] server_reported_ip (eMule reads packet+12; our public IP)
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
        let server_ip: u32 = if cfg.server.this_ip.is_empty() {
            0
        } else {
            cfg.server.this_ip.parse::<std::net::Ipv4Addr>()
                .map(|ip| u32::from_le_bytes(ip.octets()))
                .unwrap_or(0)
        };
        let tcp_flags: u32 = 0x0000_05DD;

        let mut payload = BytesMut::with_capacity(20);
        payload.put_u32_le(client.assigned_id);            // [0-3]   client_id
        payload.put_u32_le(tcp_flags);                      // [4-7]   tcp_flags
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
        payload.put_u32_le(cfg.network.tcp_port as u32);   // [8-11]  aux/standard port
        payload.put_u32_le(server_ip);                      // [12-15] server_reported_ip
        payload.put_u32_le(cfg.network.tcp_port as u32);   // [16-19] obfuscation_tcp_port
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
        let msg = cfg
            .welcome
            .messages
            .first()
            .cloned()
            .unwrap_or_else(|| format!("Welcome to {}", cfg.server.name));
        let mut payload = BytesMut::with_capacity(2 + msg.len());
        payload.put_u16_le(msg.len() as u16);
        payload.put_slice(msg.as_bytes());
        frames.push(Frame::new(OP_SERVERMESSAGE, payload.to_vec()));
    }

    // 4. SERVERIDENT — server hash + IP + port + tags
    {
        let mut payload = BytesMut::new();
        // Server hash (a stable random 16-byte ID; in production this lives
        // in config.toml; for MVP we use a fixed value.)
        let server_hash: [u8; 16] = *b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE\x12\x34\x56\x78\x9A\xBC\xDE\xF0";
        payload.put_slice(&server_hash);

        // Server IP: use configured this_ip if set, otherwise 0 (client uses TCP source)
        let server_ip: u32 = if cfg.server.this_ip.is_empty() {
            0
        } else {
            cfg.server.this_ip.parse::<std::net::Ipv4Addr>()
                .map(|ip| u32::from_le_bytes(ip.octets()))
                .unwrap_or(0)
        };
        payload.put_u32_le(server_ip);
        payload.put_u16_le(cfg.network.tcp_port);

        let tags = vec![
            Tag::byte(ST_SERVERNAME,  TagValue::String(cfg.server.name.clone())),
            Tag::byte(ST_DESCRIPTION, TagValue::String(cfg.server.desc.clone())),
            // ST_VERSION as STRING "major.minor" — same format as our 0xA3 reply.
            // Some eMule builds don't display UINT32-encoded version in the server
            // list, so we use the explicit "17.15" string that eMule parses reliably.
            Tag::byte(ST_VERSION, TagValue::String(
                format!("{}.{}", cfg.server.version_major, cfg.server.version_minor)
            )),
            Tag::byte(ST_MAXUSERS,    TagValue::U32(cfg.limits.max_clients)),
            Tag::byte(ST_SOFTFILES,   TagValue::U32(cfg.limits.soft_limit_files)),
            Tag::byte(ST_HARDFILES,   TagValue::U32(cfg.limits.hard_limit_files)),
            // ST_UDPFLAGS — eMule's SupportsObfuscationTCP() requires either this OR
            // ST_TCPFLAGS to have bit 0x400 (SRV_UDPFLG_TCPOBFUSCATION) set.
            // From eMule's server.h: SupportsObfuscationTCP() =
            //   GetObfuscationPortTCP() != 0 && ((UDPFlags & 0x400) || (TCPFlags & 0x400))
            // 0x17FB = full Lugdunum 17.15 capability mask (matches GLOBSERVSTATRES udp_flags).
            Tag::byte(ST_UDPFLAGS,    TagValue::U32(0x0000_17FB)),
            // ST_TCPPORTOBFUSCATION / ST_UDPPORTOBFUSCATION — eMule casts to uint16,
            // but values are stored in tags as u32 (eMule code: m_nObfuscationPortTCP = (uint16)tag->GetInt()).
            // Non-zero TCP obf port is required for SupportsObfuscationTCP() to return true.
            Tag::byte(ST_TCPPORTOBFUSCATION, TagValue::U32(cfg.network.tcp_port as u32)),
            Tag::byte(ST_UDPPORTOBFUSCATION, TagValue::U32((cfg.network.tcp_port + 14) as u32)),
        ];
        write_tag_list(&mut payload, &tags);

        frames.push(Frame::new(OP_SERVERIDENT, payload.to_vec()));
    }

    // 5. Additional welcome lines (welcome[1..N])
    for line in cfg.welcome.messages.iter().skip(1) {
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
    cfg: &Config,
    peer_ip: IpAddr,
    client_port: u16,
) -> (u32, bool) {
    use crate::server::highid_probe::{high_id_from_ip, probe};

    let is_high = probe(peer_ip, client_port, cfg.network.login_timeout_ms).await;

    if is_high {
        let id = high_id_from_ip(peer_ip).unwrap_or_else(|| state.allocate_low_id());
        (id, true)
    } else {
        (state.allocate_low_id(), false)
    }
}

/// Process a LOGINREQUEST and register the client.
pub async fn handle_login(
    cfg: &Config,
    state: &ServerState,
    peer_ip: IpAddr,
    req: LoginRequest,
) -> ClientHandle {
    let (assigned_id, is_high_id) = assign_client_id(state, cfg, peer_ip, req.port).await;
    let nick = req.nick().unwrap_or("(no name)").to_string();
    let server_flags = req.server_flags();

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
    let country = if let IpAddr::V4(v4) = peer_ip {
        let db = state.country_db.read().await;
        db.lookup(v4).map(|(code, _)| code).unwrap_or_else(|| "??".to_string())
    } else { "??".to_string() };

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
                CT_EMULE_MISCOPTIONS1 | CT_EMULE_MISCOPTIONS2 => { has_emule_ext = true; }
                0xEF => { has_emule_ext = true; }  // CT_EMULECOMPAT_OPTIONS1
                _ => {}
            }
        }
    }

    // Check if CT_MOD_VERSION string says "mldonkey"
    let mod_is_mldonkey = mod_name_str.as_deref()
        .map(|s| s.to_lowercase().starts_with("mldonkey"))
        .unwrap_or(false);

    let software = if mod_is_mldonkey {
        "mldonkey".to_string()
    } else if has_emule_ver_tag {
        let cid = compat_id.unwrap_or(0);
        if cid == CLIENTID_EMULE {
            // clientid=0: eMule or one of its mods. CT_MOD_VERSION has mod name.
            mod_name_str.as_deref().map(|s| {
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
            }).unwrap_or_else(|| "eMule".to_string())
        } else {
            match cid {
                CLIENTID_CDONKEY   => "cDonkey".to_string(),   // also: jed2k
                CLIENTID_XMULE     => "xMule".to_string(),
                CLIENTID_AMULE     => "aMule".to_string(),
                CLIENTID_SHAREAZA  => "Shareaza".to_string(),
                CLIENTID_MLDONKEY  => "mldonkey".to_string(),
                CLIENTID_LPHANT    => "lphant".to_string(),
                n                  => format!("compat({})", n),
            }
        }
    } else if let Some(ref mname) = mod_name_str {
        // Has CT_MOD_VERSION but no CT_EMULE_VERSION
        let lower = mname.to_lowercase();
        if lower.starts_with("mldonkey") { "mldonkey".to_string() }
        else if lower.contains("emule+") { "eMulePlus".to_string() }
        else { format!("eMule-{}", mname.split_whitespace().next().unwrap_or(mname)) }
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
    } else { software };

    let handle = ClientHandle {
        user_hash: req.user_hash,
        assigned_id,
        ip: peer_ip,
        port: req.port,
        udp_port,
        natt_capable: udp_port != 0,
        nick: nick.clone(),
        server_flags,
        is_high_id,
        connected_at: Instant::now(),
        country: country.clone(),
        software: software.clone(),
        shared_files: 0,
        csam_attempts: 0,
        tx: None,
        last_activity_ms: std::sync::Arc::new(
            std::sync::atomic::AtomicU64::new(ClientHandle::now_ms()),
        ),
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

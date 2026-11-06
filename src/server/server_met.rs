//! server.met for clients and server lists, written from the peer list.
//!
//! Lugdunum wrote one every minute (`autoservlist`) from its own peers. This
//! writes one every `[server_met] interval_secs` to `[server_met] path`, from
//! the peers on the Peers tab that are verified and whose ServerKey is known,
//! minus `[server_met] exclude`, plus this server unless `include_self` is off.
//!
//! The format is the one every reader takes:
//!
//! * header `0xE0`, a u32 count, then per server `ip u32, port u16, tag
//!   count u32` and the tags (eMule `CServerList::SaveServermetToFile`);
//! * old-style tags only: type byte, u16 name length, name (one byte for an
//!   `ST_*` id, or "users" / "files"), value. The short form (type | 0x80)
//!   aMule writes is not read by servermet.php, which takes the type byte
//!   and then a u16 length every time;
//! * only string (2) and u32 (3) values: servermet.php skips nothing else
//!   correctly. Ports go in u32 tags, which eMule and aMule both accept;
//! * strings in UTF-8, with a BOM when not plain ASCII (eMule's
//!   `UTF8strOptBOM`): eMule reads a string without a BOM in the local code
//!   page, aMule as UTF-8, both strip the BOM;
//! * the tag count is exact: aMule refuses a file it cannot read to the end.
//!
//! `ST_PREFERENCE` is 0 for every server, "normal" in eMule and aMule alike
//! (`SRV_PR_NORMAL`). No server key: a key is only good for the address it
//! was handed to, which is ours, not the reader's.

use crate::state::ServerState;
use std::net::{Ipv4Addr, SocketAddrV4};

pub const ST_SERVERNAME: u8 = 0x01;
pub const ST_DESCRIPTION: u8 = 0x0B;
pub const ST_PING: u8 = 0x0C;
pub const ST_PREFERENCE: u8 = 0x0E;
pub const ST_MAXUSERS: u8 = 0x87;
pub const ST_SOFTFILES: u8 = 0x88;
pub const ST_HARDFILES: u8 = 0x89;
pub const ST_VERSION: u8 = 0x91;
pub const ST_UDPFLAGS: u8 = 0x92;
pub const ST_LOWIDUSERS: u8 = 0x94;
pub const ST_TCPPORTOBFUSCATION: u8 = 0x97;
pub const ST_UDPPORTOBFUSCATION: u8 = 0x98;

/// `SRV_PR_NORMAL` in eMule and aMule.
pub const PREFERENCE_NORMAL: u32 = 0;

/// One server as it goes into the file.
#[derive(Debug, Clone, PartialEq)]
pub struct MetEntry {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub name: Option<String>,
    pub desc: Option<String>,
    pub version: Option<String>,
    pub users: Option<u32>,
    pub files: Option<u32>,
    pub ping_ms: Option<u32>,
    pub max_users: Option<u32>,
    pub soft_files: Option<u32>,
    pub hard_files: Option<u32>,
    pub udp_flags: Option<u32>,
    pub lowid_users: Option<u32>,
    pub obf_tcp_port: Option<u16>,
    pub obf_udp_port: Option<u16>,
}

impl Default for MetEntry {
    fn default() -> Self {
        MetEntry {
            ip: Ipv4Addr::UNSPECIFIED,
            port: 0,
            name: None,
            desc: None,
            version: None,
            users: None,
            files: None,
            ping_ms: None,
            max_users: None,
            soft_files: None,
            hard_files: None,
            udp_flags: None,
            lowid_users: None,
            obf_tcp_port: None,
            obf_udp_port: None,
        }
    }
}

fn put_name(out: &mut Vec<u8>, ty: u8, name: &[u8]) {
    out.push(ty);
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(name);
}

fn put_u32(out: &mut Vec<u8>, name: &[u8], v: u32) {
    put_name(out, 3, name);
    out.extend_from_slice(&v.to_le_bytes());
}

/// Longest string written, in bytes: names and descriptions are kept to 160
/// characters already; this only bounds the u16 length field.
const MAX_STR: usize = 4096;

fn put_str(out: &mut Vec<u8>, name: &[u8], v: &str) {
    put_name(out, 2, name);
    let mut bytes: Vec<u8> = Vec::with_capacity(v.len() + 3);
    if !v.is_ascii() {
        bytes.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    }
    // Cut at a character boundary.
    let mut end = v.len().min(MAX_STR);
    while !v.is_char_boundary(end) {
        end -= 1;
    }
    bytes.extend_from_slice(&v.as_bytes()[..end]);
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&bytes);
}

fn text(s: &Option<String>) -> Option<&str> {
    s.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// The file's bytes.
pub fn build(entries: &[MetEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + entries.len() * 256);
    out.push(0xE0);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        out.extend_from_slice(&e.ip.octets());
        out.extend_from_slice(&e.port.to_le_bytes());
        let mut tags = Vec::new();
        let mut n: u32 = 0;
        if let Some(v) = text(&e.name) {
            put_str(&mut tags, &[ST_SERVERNAME], v);
            n += 1;
        }
        if let Some(v) = text(&e.desc) {
            put_str(&mut tags, &[ST_DESCRIPTION], v);
            n += 1;
        }
        put_u32(&mut tags, &[ST_PREFERENCE], PREFERENCE_NORMAL);
        n += 1;
        for (name, v) in [(&b"users"[..], e.users), (&b"files"[..], e.files)] {
            if let Some(v) = v {
                put_u32(&mut tags, name, v);
                n += 1;
            }
        }
        let ints = [
            (ST_PING, e.ping_ms),
            (ST_MAXUSERS, e.max_users),
            (ST_SOFTFILES, e.soft_files),
            (ST_HARDFILES, e.hard_files),
            (ST_UDPFLAGS, e.udp_flags),
            (ST_LOWIDUSERS, e.lowid_users),
            (ST_TCPPORTOBFUSCATION, e.obf_tcp_port.map(u32::from)),
            (ST_UDPPORTOBFUSCATION, e.obf_udp_port.map(u32::from)),
        ];
        for (id, v) in ints {
            if let Some(v) = v {
                put_u32(&mut tags, &[id], v);
                n += 1;
            }
        }
        if let Some(v) = text(&e.version) {
            put_str(&mut tags, &[ST_VERSION], v);
            n += 1;
        }
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&tags);
    }
    out
}

/// One `[server_met] exclude` entry: an address, a CIDR range, or one
/// server (`ip:port`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exclude {
    Range { net: u32, mask: u32 },
    Server(SocketAddrV4),
}

impl Exclude {
    pub fn parse(s: &str) -> Option<Exclude> {
        let s = s.trim();
        if let Ok(sa) = s.parse::<SocketAddrV4>() {
            return Some(Exclude::Server(sa));
        }
        let (ip, bits) = match s.split_once('/') {
            Some((ip, b)) => (ip, b.trim().parse::<u32>().ok().filter(|b| *b <= 32)?),
            None => (s, 32),
        };
        let ip: Ipv4Addr = ip.trim().parse().ok()?;
        let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
        Some(Exclude::Range { net: u32::from(ip) & mask, mask })
    }

    pub fn matches(&self, server: SocketAddrV4) -> bool {
        match *self {
            Exclude::Server(s) => s == server,
            Exclude::Range { net, mask } => u32::from(*server.ip()) & mask == net,
        }
    }
}

/// The entries of `[server_met] exclude` that parse, and those that do not.
pub fn parse_excludes(list: &[String]) -> (Vec<Exclude>, Vec<String>) {
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    for s in list {
        match Exclude::parse(s) {
            Some(e) => ok.push(e),
            None => bad.push(s.clone()),
        }
    }
    (ok, bad)
}

/// Where a listed peer stands for server.met.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    In,
    Excluded,
    /// Not verified, or no ServerKey yet.
    NotQualified,
}

pub fn standing(state: &ServerState, server: SocketAddrV4, excludes: &[Exclude]) -> Standing {
    let has_key = state.seed_server_keys.contains_key(&server);
    let verified = state.verified_sockets.contains_key(&server) || has_key;
    if !(verified && has_key) {
        Standing::NotQualified
    } else if excludes.iter().any(|e| e.matches(server)) {
        Standing::Excluded
    } else {
        Standing::In
    }
}

/// The servers that go into the file: this server first (when it is
/// public, `include_self` is on and it is not excluded), then the peers by
/// users, most first. `None` when no peer qualifies: an empty list would
/// replace a good file after a network hiccup.
pub async fn collect(state: &ServerState) -> Option<Vec<MetEntry>> {
    let cfg = state.live_cfg.load_full();
    let (excludes, _) = parse_excludes(&cfg.server_met.exclude);
    let list: Vec<SocketAddrV4> = state.server_list.read().await.clone();
    let mut seen = std::collections::HashSet::new();
    let mut peers: Vec<MetEntry> = Vec::new();
    for addr in list {
        if !seen.insert(addr) || standing(state, addr, &excludes) != Standing::In {
            continue;
        }
        let info = state.peer_info.get(&addr).map(|e| e.value().clone()).unwrap_or_default();
        peers.push(MetEntry {
            ip: *addr.ip(),
            port: addr.port(),
            name: info.name,
            desc: info.desc,
            version: info.version,
            users: info.users,
            files: info.files,
            ping_ms: info.ping_ms,
            max_users: info.max_users,
            soft_files: info.soft_files,
            hard_files: info.hard_files,
            udp_flags: info.udp_flags,
            lowid_users: info.lowid_users,
            obf_tcp_port: info.obf_tcp_port,
            obf_udp_port: info.obf_udp_port,
        });
    }
    if peers.is_empty() {
        return None;
    }
    peers.sort_by(|a, b| b.users.unwrap_or(0).cmp(&a.users.unwrap_or(0)));

    let mut out = Vec::with_capacity(peers.len() + 1);
    if cfg.server_met.include_self && cfg.server.public {
        if let Ok(ip) = cfg.server.this_ip.trim().parse::<Ipv4Addr>() {
            let me = SocketAddrV4::new(ip, cfg.network.tcp_port);
            if !excludes.iter().any(|e| e.matches(me)) && !seen.contains(&me) {
                out.push(MetEntry {
                    ip,
                    port: cfg.network.tcp_port,
                    name: Some(cfg.server.name.clone()),
                    desc: Some(cfg.server.desc.clone()),
                    version: Some(format!(
                        "{}.{}",
                        cfg.server.version_major, cfg.server.version_minor
                    )),
                    users: Some(state.client_count() as u32),
                    files: Some(state.file_count() as u32),
                    ping_ms: None,
                    max_users: Some(cfg.limits.max_clients),
                    soft_files: Some(cfg.limits.soft_limit_files),
                    hard_files: Some(cfg.limits.hard_limit_files),
                    udp_flags: Some(crate::server::udp::server_udp_flags(&cfg)),
                    lowid_users: Some(state.lowid_count() as u32),
                    obf_tcp_port: Some(cfg.network.tcp_port),
                    obf_udp_port: Some(cfg.network.tcp_port.wrapping_add(14)),
                });
            }
        }
    }
    out.extend(peers);
    Some(out)
}

/// Where the file goes: `path` itself, or `path/server.met` for a folder.
pub fn target(path: &str) -> std::path::PathBuf {
    let p = std::path::Path::new(path.trim());
    if p.is_dir() {
        p.join("server.met")
    } else {
        p.to_path_buf()
    }
}

/// Write `bytes` to `dest` through a temporary file in the same folder, so
/// a reader (the web server, a client mid-download) never sees half a file.
pub fn write_atomic(dest: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = dest.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(std::path::Path::new("."));
    let name = dest.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "server.met".into());
    let tmp = dir.join(format!(".{name}.tmp"));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader in the shape of servermet.php: type byte, u16 name length,
    /// then only types 2 and 3. Returns (ip, port, tags) per server and
    /// fails on anything else, as the script would misread it.
    fn php_read(b: &[u8]) -> Vec<(Ipv4Addr, u16, Vec<(Vec<u8>, Result<Vec<u8>, u32>)>)> {
        let mut i = 0;
        assert!(b[0] == 0xE0 || b[0] == 0x0E);
        i += 1;
        let n = u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        i += 4;
        let mut out = Vec::new();
        for _ in 0..n {
            let ip = Ipv4Addr::new(b[i], b[i + 1], b[i + 2], b[i + 3]);
            let port = u16::from_le_bytes([b[i + 4], b[i + 5]]);
            let tc = u32::from_le_bytes(b[i + 6..i + 10].try_into().unwrap());
            i += 10;
            let mut tags = Vec::new();
            for _ in 0..tc {
                let ty = b[i];
                assert!(ty == 2 || ty == 3, "type {ty:#x}");
                let ln = u16::from_le_bytes([b[i + 1], b[i + 2]]) as usize;
                let name = b[i + 3..i + 3 + ln].to_vec();
                i += 3 + ln;
                if ty == 2 {
                    let sl = u16::from_le_bytes([b[i], b[i + 1]]) as usize;
                    tags.push((name, Ok(b[i + 2..i + 2 + sl].to_vec())));
                    i += 2 + sl;
                } else {
                    tags.push((name, Err(u32::from_le_bytes(b[i..i + 4].try_into().unwrap()))));
                    i += 4;
                }
            }
            out.push((ip, port, tags));
        }
        assert_eq!(i, b.len(), "trailing bytes: aMule refuses the file");
        out
    }

    #[test]
    fn the_file_reads_back_the_way_servermet_php_and_amule_read_it() {
        let e = MetEntry {
            ip: Ipv4Addr::new(85, 17, 116, 222),
            port: 6082,
            name: Some("ed2k-rust".into()),
            desc: Some("Сервер".into()),
            version: Some("18.1".into()),
            users: Some(17079),
            files: Some(7_653_140),
            max_users: Some(75000),
            obf_tcp_port: Some(6082),
            obf_udp_port: Some(6096),
            ..Default::default()
        };
        let bare = MetEntry { ip: Ipv4Addr::new(10, 0, 0, 1), port: 4661, ..Default::default() };
        let b = build(&[e, bare]);
        assert_eq!(b[0], 0xE0);
        let r = php_read(&b);
        assert_eq!(r.len(), 2);
        let (ip, port, tags) = &r[0];
        assert_eq!((*ip, *port), (Ipv4Addr::new(85, 17, 116, 222), 6082));
        let get = |n: &[u8]| tags.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
        assert_eq!(get(&[ST_SERVERNAME]), Some(Ok(b"ed2k-rust".to_vec())));
        // A non-ASCII string carries the UTF-8 BOM.
        let d = get(&[ST_DESCRIPTION]).unwrap().unwrap();
        assert_eq!(&d[..3], &[0xEF, 0xBB, 0xBF]);
        assert_eq!(std::str::from_utf8(&d[3..]).unwrap(), "Сервер");
        assert_eq!(get(b"users"), Some(Err(17079)));
        assert_eq!(get(b"files"), Some(Err(7_653_140)));
        assert_eq!(get(&[ST_MAXUSERS]), Some(Err(75000)));
        assert_eq!(get(&[ST_PREFERENCE]), Some(Err(PREFERENCE_NORMAL)));
        assert_eq!(get(&[ST_VERSION]), Some(Ok(b"18.1".to_vec())));
        assert_eq!(get(&[ST_UDPPORTOBFUSCATION]), Some(Err(6096)));
        // A server with nothing known still gets its priority, and only that.
        assert_eq!(r[1].2.len(), 1);
        assert_eq!(r[1].2[0].0, vec![ST_PREFERENCE]);
    }

    #[test]
    fn excludes_take_an_address_a_range_or_one_server() {
        let a = SocketAddrV4::new(Ipv4Addr::new(91, 208, 162, 182), 4232);
        let b = SocketAddrV4::new(Ipv4Addr::new(91, 208, 162, 55), 4235);
        let ex = |s: &str| Exclude::parse(s).unwrap();
        assert!(ex("91.208.162.182").matches(a) && !ex("91.208.162.182").matches(b));
        assert!(ex("91.208.162.0/24").matches(a) && ex("91.208.162.0/24").matches(b));
        assert!(ex("91.208.162.182:4232").matches(a));
        assert!(!ex("91.208.162.182:4661").matches(a));
        assert!(ex("0.0.0.0/0").matches(b));
        let (ok, bad) = parse_excludes(&["1.2.3.4".into(), "nonsense".into(), "1.2.3.0/33".into()]);
        assert_eq!((ok.len(), bad.len()), (1, 2));
    }
}

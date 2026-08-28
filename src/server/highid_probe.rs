//! HighID/LowID detection probe (SPEC.md §3.2).
//!
//! The server opens an outbound TCP connection to (client_ip, client_port).
//! If successful → HighID (client is reachable, assigned_id = IPv4 as u32).
//! If timeout/refused → LowID (client is behind NAT, assigned_id from pool).
//!
//! The server sends OP_HELLO (eD2k client-to-client opcode 0x01 with prefix
//! 0x10) during the test, then closes. The client ignores it but the TCP
//! handshake itself proves reachability.
//!
//! This is the standard eD2k callback reachability check (server connects back
//! to the client to learn whether it has an open port); it is NOT a backdoor.
//!
//! Config: `network.login_timeout_ms` (default 2000ms).
//! On busy servers this runs concurrently per connection — no global lock.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

/// eD2k client-to-client opcodes used by the identity probe.
const OP_HELLO: u8 = 0x01;
const OP_HELLOANSWER: u8 = 0x4C;
const PROTO_EDONKEY: u8 = 0xE3;
/// eMule's extended protocol. A client answering an incoming HELLO sends its
/// OP_EMULEINFO in one of these BEFORE the eDonkey HELLOANSWER, so the first
/// frame on the wire is routinely not the one we are waiting for.
const PROTO_EMULE: u8 = 0xC5;

/// Hello tag ids. A real client always sends at least these three, and at least
/// one fork crashes without the first — see `build_hello`.
const CT_NAME: u8 = 0x01;
const CT_PORT: u8 = 0x0F;
const CT_VERSION: u8 = 0x11;
/// eDonkey protocol version announced in CT_VERSION, as every eMule sends it.
const EDONKEY_VERSION: u32 = 60;
/// Name we introduce ourselves under. Deliberately not impersonating a client:
/// an operator reading their log should be able to tell what connected to them.
const PROBE_NAME: &str = "ed2k-server-probe";
/// Zlib-compressed payload. Not something we have to decompress: we skip frames
/// we do not want by their declared length, and the length is in the clear.
const PROTO_PACKED: u8 = 0xD4;

/// eD2k client-to-client obfuscation, initiator side.
///
/// Matches what Lugdunum does in `SendHello` when the client advertised crypt
/// support, so a client configured to require obfuscation is reachable by our
/// probe as well.
///
/// ```text
/// on the wire:  [semi-random byte][keypart u32, CLEAR][RC4: magic|method|padlen|pad][RC4: payload…]
/// send key:     RC4( MD5( peer user hash ‖ 34  ‖ keypart ) ), first 1024 bytes discarded
/// recv key:     RC4( MD5( peer user hash ‖ 203 ‖ keypart ) ), same
/// ```
///
/// The keys are derived from the PEER's user hash, which is the one thing only
/// the two of us are supposed to know — so the obfuscation doubles as a second,
/// weaker identity check on top of the hash comparison we already do.
struct ClientCrypt {
    send: crate::proto::obfuscation::Rc4,
    recv: crate::proto::obfuscation::Rc4,
}

impl ClientCrypt {
    /// Build the keys and the opening bytes.
    ///
    /// Returns the handshake to send; the caller writes it before anything else
    /// and encrypts everything afterwards with `send`.
    fn start(peer_user_hash: &[u8; 16]) -> (Self, Vec<u8>) {
        use crate::proto::obfuscation::{
            Rc4, FORBIDDEN_MARKERS, MAGIC_SYNC, MAGIC_VALUE_REQUESTER, MAGIC_VALUE_SERVER,
        };
        use md5::{Digest, Md5};

        // Zero is excluded: Lugdunum loops until the keypart is non-zero, and a
        // zero keypart makes both keys depend on the peer hash alone, so every
        // connection to the same client would use one keystream.
        let mut keypart: u32 = {
            let b = crate::proto::obfuscation::random_bytes(4);
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        };
        while keypart == 0 {
            let b = crate::proto::obfuscation::random_bytes(4);
            keypart = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        }

        let derive = |magic: u8| -> Rc4 {
            let mut h = Md5::new();
            h.update(peer_user_hash);
            h.update([magic]);
            h.update(keypart.to_le_bytes());
            Rc4::new(&h.finalize(), true)
        };
        let mut send = derive(MAGIC_VALUE_REQUESTER);
        let recv = derive(MAGIC_VALUE_SERVER);

        // The first byte stays in the clear and must not look like a protocol
        // marker, or the peer reads the stream as a plain eD2k frame.
        let mut marker: u8 = crate::proto::obfuscation::random_bytes(1)[0];
        while FORBIDDEN_MARKERS.contains(&marker) {
            marker = crate::proto::obfuscation::random_bytes(1)[0];
        }

        let mut out = Vec::with_capacity(11);
        out.push(marker);
        out.extend_from_slice(&keypart.to_le_bytes());

        // Encrypted from here on. No padding: the length byte is honoured by
        // every implementation and zero keeps the exchange one packet shorter.
        let mut body = Vec::with_capacity(6);
        body.extend_from_slice(&MAGIC_SYNC.to_le_bytes());
        body.push(0); // encryption method: RC4
        body.push(0); // padding length
        send.apply(&mut body);
        out.extend_from_slice(&body);

        (Self { send, recv }, out)
    }
}

/// Probe the client's advertised (ip, port).
/// Returns true if the client is routable (HighID).
pub async fn probe(ip: IpAddr, port: u16, timeout_ms: u64) -> bool {
    // Private / loopback / link-local are always LowID — no point probing.
    if !is_routable(ip) {
        // NOT the final verdict when the hairpin fallback is enabled: that path
        // runs afterwards and probes a different address. Worded carefully —
        // "→ LowID" here sent a bug reporter looking for a second code path that
        // does not exist, because two lines appeared for one login.
        debug!(ip = %ip, "private IP → skipping plain probe (hairpin fallback may still run)");
        return false;
    }

    let addr = SocketAddr::new(ip, port);
    match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(addr),
    )
    .await
    {
        Ok(Ok(_stream)) => {
            // Connected — HighID. Stream is immediately dropped; the client
            // will see a brief incoming connection which it handles gracefully.
            debug!(addr = %addr, "HighID probe succeeded → HighID");
            true
        }
        Ok(Err(e)) => {
            debug!(addr = %addr, error = %e, "HighID probe refused → LowID");
            false
        }
        Err(_) => {
            debug!(addr = %addr, "HighID probe timeout → LowID");
            false
        }
    }
}

/// Probe that also proves WHO answered.
///
/// The plain `probe` above only proves that something accepts connections on
/// that port. For a public client that is enough, because the address it
/// connected FROM and the address we probe are the same by construction — the
/// port belongs to the same host or the packets would not have arrived.
///
/// That guarantee disappears the moment the probed address is not the address
/// the client connected from, which is exactly what the hairpin path does. On
/// a network where the router source-NATs hairpin traffic, every local client
/// reaches the server from the router's own address, so they are
/// indistinguishable, and a port-forward for that port may well lead to a
/// DIFFERENT machine. Without an identity check the server would hand the
/// public address out as a source for the wrong host, and external peers would
/// download from a machine that never published the file.
///
/// So: send a client-to-client HELLO and read the peer's HELLOANSWER, whose
/// first field is its user hash. If it matches the hash that logged in, the
/// host behind the forwarded port is the client we are talking to.
///
/// Returns `Ok(true)` on a verified match, `Ok(false)` on a mismatch, and
/// `Err(reason)` when the exchange could not be completed at all — the caller
/// decides how to treat "no answer", which is not the same as "wrong host".
pub async fn probe_identity(
    ip: IpAddr,
    port: u16,
    expected_user_hash: &[u8; 16],
    our_user_hash: &[u8; 16],
    our_id: u32,
    our_port: u16,
    timeout_ms: u64,
    obfuscate: bool,
) -> Result<bool, &'static str> {
    let addr = SocketAddr::new(ip, port);
    let deadline = Duration::from_millis(timeout_ms);
    // Every stage is timed and logged. The first round of diagnosing this path
    // was spent arguing about whether a socket was opened at all, because the
    // only thing the log carried was a one-word reason. Cheap: this runs once
    // per login on one opt-in path.
    let started = std::time::Instant::now();

    let mut stream = match tokio::time::timeout(deadline, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!(
                %addr, elapsed_us = started.elapsed().as_micros(), error = %e,
                "probe_identity: connect failed"
            );
            return Err("connect refused");
        }
        Err(_) => {
            debug!(
                %addr, elapsed_us = started.elapsed().as_micros(),
                "probe_identity: connect timed out"
            );
            return Err("connect timeout");
        }
    };

    // WHO answered, and from where we reached them. On a hairpin path these two
    // lines settle the question a packet capture cannot: if the peer address is
    // the public one but the client machine sees no SYN, then something between
    // us and the client accepted the connection — the router's own stack on the
    // WAN interface, typically, rather than the port forward.
    debug!(
        %addr,
        local = ?stream.local_addr().ok(),
        peer = ?stream.peer_addr().ok(),
        connect_us = started.elapsed().as_micros(),
        "probe_identity: connected"
    );

    // ⚠ OUR hash, never the peer's. Sending the peer its own user hash makes it
    //   conclude it has connected to itself and drop the connection without a
    //   word — which is exactly what the first version of this probe did.
    //   Diagnosed from a router's connection table: three packets out, two back,
    //   and ZERO payload bytes in the reply. The client had accepted the TCP
    //   connection, read the hello and hung up.
    debug_assert_ne!(our_user_hash, expected_user_hash);
    // Obfuscated handshake first, when the client asked for one at login.
    let mut crypt = if obfuscate {
        let (state, opening) = ClientCrypt::start(expected_user_hash);
        match tokio::time::timeout(deadline, stream.write_all(&opening)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                debug!(%addr, error = %e, "probe_identity: crypt handshake write failed");
                return Err("write failed");
            }
            Err(_) => return Err("write timeout"),
        }
        debug!(%addr, "probe_identity: sent obfuscated handshake");
        Some(state)
    } else {
        None
    };

    let mut hello = build_hello(our_user_hash, our_id, our_port);
    if let Some(c) = crypt.as_mut() {
        c.send.apply(&mut hello);
    }
    match tokio::time::timeout(deadline, stream.write_all(&hello)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            debug!(%addr, error = %e, "probe_identity: write failed");
            return Err("write failed");
        }
        Err(_) => return Err("write timeout"),
    }

    // The peer answers the handshake before anything else, with its own magic
    // value under ITS send key — which is our recv key. Getting this right also
    // proves the peer knows its own user hash, since the key is derived from it.
    if let Some(c) = crypt.as_mut() {
        use crate::proto::obfuscation::MAGIC_SYNC;
        let mut head = [0u8; 6];
        match tokio::time::timeout(deadline, stream.read_exact(&mut head)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                debug!(%addr, error = %e, "probe_identity: no crypt handshake answer");
                return Err("peer closed during obfuscated handshake");
            }
            Err(_) => return Err("no crypt answer before timeout"),
        }
        c.recv.apply(&mut head);
        let sync = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
        if sync != MAGIC_SYNC {
            // Either the peer is not speaking obfuscation, or it derived a
            // different key — which happens when it does not have the user hash
            // we think it has.
            debug!(
                %addr, got = format_args!("0x{sync:08X}"),
                "probe_identity: obfuscated handshake rejected"
            );
            return Err("obfuscated handshake failed");
        }
        if head[4] != 0 {
            return Err("peer chose an encryption method we do not implement");
        }
        // Masked to four bits, as Lugdunum does: the field is a byte but no
        // implementation sends more than 15 bytes of padding here.
        let pad = (head[5] & 0x0F) as usize;
        if pad > 0 {
            let mut sink = vec![0u8; pad];
            match tokio::time::timeout(deadline, stream.read_exact(&mut sink)).await {
                Ok(Ok(_)) => {}
                _ => return Err("truncated obfuscated padding"),
            }
            c.recv.apply(&mut sink);
        }
        debug!(%addr, pad, "probe_identity: obfuscated handshake accepted");
    }

    // READ FRAMES UNTIL THE RIGHT ONE, rather than assuming the first is it.
    //
    // This is what the first version got wrong. A stock eMule answering an
    // incoming HELLO sends TWO frames back to back: its own OP_EMULEINFO in an
    // extended-protocol frame (0xC5), and only then the eDonkey HELLOANSWER
    // (0xE3) we came for. Reading six bytes and judging the protocol byte
    // rejected a perfectly good answer as "not an eD2k answer" — 175 bytes had
    // arrived, of which the first 68 were the extended frame and the remaining
    // 107 were exactly what we wanted.
    //
    // Frames we do not want are skipped by their DECLARED LENGTH, which is in
    // the clear in every eD2k protocol variant, including the compressed one.
    // Nothing has to be decompressed to walk past it.
    const MAX_FRAMES: usize = 8;
    const MAX_SKIP: usize = 64 * 1024;
    let mut skipped_bytes = 0usize;

    for _ in 0..MAX_FRAMES {
        // proto(1) + length(4) + opcode(1)
        let mut head = [0u8; 6];
        let mut got = 0usize;
        while got < head.len() {
            match tokio::time::timeout(deadline, stream.read(&mut head[got..])).await {
                Ok(Ok(0)) => {
                    debug!(
                        %addr, bytes_read = got, hello_bytes = hello.len(),
                        skipped_bytes, elapsed_us = started.elapsed().as_micros(),
                        first = ?&head[..got],
                        "probe_identity: peer closed"
                    );
                    return Err(if got == 0 && skipped_bytes == 0 {
                        "peer closed without sending a byte"
                    } else {
                        "peer closed mid-answer"
                    });
                }
                Ok(Ok(n)) => {
                    if let Some(c) = crypt.as_mut() {
                        c.recv.apply(&mut head[got..got + n]);
                    }
                    got += n;
                }
                Ok(Err(e)) => {
                    debug!(%addr, bytes_read = got, error = %e, "probe_identity: read failed");
                    return Err("read failed");
                }
                Err(_) => {
                    debug!(
                        %addr, bytes_read = got, skipped_bytes,
                        elapsed_us = started.elapsed().as_micros(),
                        "probe_identity: no answer before timeout"
                    );
                    return Err("no answer before timeout");
                }
            }
        }

        let proto = head[0];
        let len = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
        let opcode = head[5];
        debug!(
            %addr, proto = format_args!("0x{proto:02X}"), len,
            opcode = format_args!("0x{opcode:02X}"),
            elapsed_us = started.elapsed().as_micros(),
            "probe_identity: frame"
        );
        if len == 0 || len > MAX_SKIP {
            return Err("implausible frame length");
        }

        // The hash sits at the start of the frame body for both hello opcodes;
        // OP_HELLO carries one extra leading byte (the hash size).
        let hash_at = match (proto, opcode) {
            (PROTO_EDONKEY, OP_HELLOANSWER) => Some(0usize),
            (PROTO_EDONKEY, OP_HELLO) => Some(1usize),
            (PROTO_EDONKEY, _) | (PROTO_EMULE, _) | (PROTO_PACKED, _) => None,
            _ => return Err("not an eD2k answer"),
        };

        // `len` counts the opcode, which is already consumed.
        let remaining = len - 1;

        match hash_at {
            Some(skip) => {
                if remaining < skip + 16 {
                    return Err("answer too short");
                }
                let mut buf = vec![0u8; skip + 16];
                match tokio::time::timeout(deadline, stream.read_exact(&mut buf)).await {
                    Ok(Ok(_)) => {}
                    _ => return Err("truncated answer"),
                }
                if let Some(c) = crypt.as_mut() {
                    c.recv.apply(&mut buf);
                }
                return Ok(&buf[skip..] == expected_user_hash.as_slice());
            }
            None => {
                skipped_bytes += remaining;
                if skipped_bytes > MAX_SKIP {
                    return Err("too much preamble before an answer");
                }
                let mut sink = vec![0u8; remaining];
                match tokio::time::timeout(deadline, stream.read_exact(&mut sink)).await {
                    Ok(Ok(_)) => {}
                    _ => return Err("truncated while skipping a frame"),
                }
                if let Some(c) = crypt.as_mut() {
                    // The keystream is continuous: a frame we do not want still
                    // has to be pushed through it, or everything after it
                    // decrypts to noise.
                    c.recv.apply(&mut sink);
                }
            }
        }
    }

    Err("no hello answer within the first frames")
}

/// Client-to-client OP_HELLO.
///
/// Layout after the opcode: one byte giving the hash size (always 0x10), the
/// 16-byte user hash, our client id, our TCP port, then a tag count. Zero tags
/// is accepted by every client we care about here — the answer is what matters,
/// and no client conditions its answer on our tag list.
///
/// `user_hash` is OURS. See the note at the call site: a client that receives
/// its own hash treats the connection as a loop back to itself and closes it.
fn build_hello(user_hash: &[u8; 16], our_id: u32, our_port: u16) -> Vec<u8> {
    let mut tags = Vec::new();
    let mut tag_count = 0u32;

    // ⚠ THE TAGS ARE NOT DECORATION. A hello with `tag count = 0` is legal, and
    //   stock eMule answers it, but at least one widely used fork DIES on it:
    //
    //     CShield::CheckClient()          eMuleAI 1.6, Shield.cpp:502
    //       client->GetUserName() != client->m_pszUsernameShield
    //       client->m_pszUsernameShield  = client->GetUserName();
    //
    //   `GetUserName()` returns the raw `TCHAR*`, which stays NULL when no
    //   CT_NAME arrived, and both lines then hand a null pointer to CString.
    //   The access violation propagates out of the hello handler, the fork logs
    //   "caused an exception, disconnecting client" with no reason, and the
    //   socket is closed with our bytes still unread — which reaches us as a
    //   reset with zero bytes read. It cost several rounds of diagnosis to find,
    //   because nothing in any of its logs named a cause.
    //
    //   A real client always sends these three, which is why nobody had hit it.
    //   Sending them is a few bytes and makes the probe indistinguishable from
    //   an ordinary peer, so there is no reason not to.
    push_string_tag(&mut tags, CT_NAME, PROBE_NAME);
    tag_count += 1;
    push_int_tag(&mut tags, CT_VERSION, EDONKEY_VERSION);
    tag_count += 1;
    push_int_tag(&mut tags, CT_PORT, our_port as u32);
    tag_count += 1;

    let mut body = Vec::with_capacity(32 + tags.len());
    body.push(0x10); // hash size
    body.extend_from_slice(user_hash);
    body.extend_from_slice(&our_id.to_le_bytes());
    body.extend_from_slice(&our_port.to_le_bytes());
    body.extend_from_slice(&tag_count.to_le_bytes());
    body.extend_from_slice(&tags);
    body.extend_from_slice(&0u32.to_le_bytes()); // server ip
    body.extend_from_slice(&0u16.to_le_bytes()); // server port

    let mut frame = Vec::with_capacity(body.len() + 6);
    frame.push(PROTO_EDONKEY);
    frame.extend_from_slice(&((body.len() + 1) as u32).to_le_bytes());
    frame.push(OP_HELLO);
    frame.extend_from_slice(&body);
    frame
}

/// Special-tag form: the type byte carries 0x80 and the name is a single byte.
/// That is what clients send in a hello, and what their parsers expect.
fn push_string_tag(out: &mut Vec<u8>, id: u8, value: &str) {
    out.push(0x02 | 0x80); // string
    out.push(id);
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn push_int_tag(out: &mut Vec<u8>, id: u8, value: u32) {
    out.push(0x03 | 0x80); // u32
    out.push(id);
    out.extend_from_slice(&value.to_le_bytes());
}

/// A stable pseudo user hash identifying this server in a client-to-client
/// handshake.
///
/// The server is not an eD2k client and has no user hash of its own, but the
/// probe has to present one, and it must differ from the peer's — see
/// `probe_identity`. Derived from the seckey so it is stable across restarts
/// (a client that saw us yesterday sees the same identity today) and unique per
/// server, without inventing a new stored secret.
///
/// The two marker bytes are the eD2k convention for "this is an eMule-family
/// client". Setting them is not required, but a hash without them makes some
/// clients classify the peer as an old eDonkey hybrid and take a different code
/// path — needless variation in something we only use to ask one question.
pub fn server_pseudo_user_hash(seckey: &[u8; 16]) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(b"ed2k-server-probe-identity");
    h.update(seckey);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.finalize());
    out[5] = 0x0E;
    out[14] = 0x6F;
    out
}

/// Compute the HighID from an IPv4 address.
/// eD2k uses the raw u32 (big-endian octets interpreted as little-endian u32).
pub fn high_id_from_ip(ip: IpAddr) -> Option<u32> {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Stored as u32 LE: octets in natural order
            Some(u32::from_le_bytes(octets))
        }
        _ => None,
    }
}

fn is_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_loopback()
                && !v4.is_private()
                && !v4.is_link_local()
                && !v4.is_unspecified()
                && !v4.is_broadcast()
        }
        IpAddr::V6(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn private_ips_not_routable() {
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(172, 23, 20, 152))));
        assert!(!is_routable(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn public_ip_routable() {
        assert!(is_routable(IpAddr::V4(Ipv4Addr::new(65, 109, 199, 83))));
        assert!(is_routable(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn our_identity_is_stable_and_never_the_peers() {
        // The bug this guards: sending the peer its own user hash made it treat
        // the connection as a loop back to itself and hang up without replying.
        // Confirmed on a router's connection table — reply payload was zero
        // bytes.
        let a = server_pseudo_user_hash(&[7u8; 16]);
        let b = server_pseudo_user_hash(&[7u8; 16]);
        assert_eq!(a, b, "must be stable across restarts");
        assert_ne!(a, server_pseudo_user_hash(&[8u8; 16]), "must differ per server");
        assert_ne!(a, [7u8; 16]);
        assert_eq!(a[5], 0x0E, "eMule-family marker byte");
        assert_eq!(a[14], 0x6F, "eMule-family marker byte");
    }

    #[test]
    fn the_obfuscated_opening_has_the_shape_lugdunum_sends() {
        // Layout, initiator side:
        //   [1] semi-random marker, in the clear
        //   [4] key part, in the clear
        //   [6] RC4( magic 0x835E6FC4 | method 0 | padding length 0 )
        let peer = [0x5Au8; 16];
        let (_state, opening) = ClientCrypt::start(&peer);
        assert_eq!(opening.len(), 11, "1 + 4 + 6");
        assert!(
            !crate::proto::obfuscation::FORBIDDEN_MARKERS.contains(&opening[0]),
            "the clear marker must not look like a protocol byte"
        );
        let keypart = u32::from_le_bytes([opening[1], opening[2], opening[3], opening[4]]);
        assert_ne!(keypart, 0, "a zero key part makes every stream identical");
        // The encrypted part must not read as the magic value in the clear.
        let plain_magic = crate::proto::obfuscation::MAGIC_SYNC.to_le_bytes();
        assert_ne!(&opening[5..9], &plain_magic[..], "body must be encrypted");
    }

    #[test]
    fn the_peer_can_decrypt_what_we_send() {
        // Derive the peer's side of the exchange by hand and check it recovers
        // the magic value — this is exactly the check Lugdunum performs, and it
        // is what proves our key derivation matches the protocol rather than
        // merely being self-consistent.
        use crate::proto::obfuscation::{Rc4, MAGIC_SYNC, MAGIC_VALUE_REQUESTER};
        use md5::{Digest, Md5};

        let peer = [0xA3u8; 16];
        let (_state, opening) = ClientCrypt::start(&peer);
        let keypart = u32::from_le_bytes([opening[1], opening[2], opening[3], opening[4]]);

        let mut h = Md5::new();
        h.update(peer);
        h.update([MAGIC_VALUE_REQUESTER]);
        h.update(keypart.to_le_bytes());
        let mut peer_view = Rc4::new(&h.finalize(), true);

        let mut body = opening[5..].to_vec();
        peer_view.apply(&mut body);
        assert_eq!(
            u32::from_le_bytes([body[0], body[1], body[2], body[3]]),
            MAGIC_SYNC,
            "the peer must recover the magic value"
        );
        assert_eq!(body[4], 0, "encryption method RC4");
        assert_eq!(body[5] & 0x0F, 0, "no padding");
    }

    #[test]
    fn two_handshakes_never_share_a_keystream() {
        // The clock-only seed produced identical streams for calls landing in
        // the same nanosecond bucket, which is what happens when several logins
        // arrive at once.
        let peer = [0x11u8; 16];
        let (_a, one) = ClientCrypt::start(&peer);
        let (_b, two) = ClientCrypt::start(&peer);
        assert_ne!(one[1..5], two[1..5], "key parts must differ");
    }

    #[test]
    fn the_extended_protocol_frame_is_the_one_that_arrives_first() {
        // Measured on a live client: 175 bytes came back in one read, made of an
        // extended-protocol frame (0xC5, OP_EMULEINFO, 63-byte body = 68 bytes on
        // the wire) followed by the eDonkey HELLOANSWER (107 bytes). Judging the
        // protocol byte of the FIRST frame threw the answer away.
        let emule_info_len = 0x3fusize;
        assert_eq!(1 + 4 + emule_info_len, 68);
        assert_eq!(175 - 68, 107);
        // The reader must treat 0xC5 and 0xD4 as frames to walk past, not as a
        // reason to give up.
        assert_ne!(PROTO_EMULE, PROTO_EDONKEY);
        assert_ne!(PROTO_PACKED, PROTO_EDONKEY);
    }

    #[test]
    fn hello_frame_is_well_formed() {
        let uh = [0xABu8; 16];
        let f = build_hello(&uh, 0x01020304, 4661);
        assert_eq!(f[0], PROTO_EDONKEY);
        let len = u32::from_le_bytes([f[1], f[2], f[3], f[4]]) as usize;
        // Length covers the opcode and everything after it.
        assert_eq!(len, f.len() - 5);
        assert_eq!(f[5], OP_HELLO);
        assert_eq!(f[6], 0x10, "hash size byte");
        assert_eq!(&f[7..23], &uh, "user hash follows the size byte");
        assert_eq!(u32::from_le_bytes([f[23], f[24], f[25], f[26]]), 0x01020304);
        assert_eq!(u16::from_le_bytes([f[27], f[28]]), 4661);
        assert_eq!(
            u32::from_le_bytes([f[29], f[30], f[31], f[32]]),
            3,
            "tag count"
        );
        // ...and the frame still ends with the server address fields.
        assert_eq!(&f[f.len() - 6..], &[0u8; 6], "server ip and port");
    }

    #[test]
    fn the_hello_carries_the_tags_a_real_client_sends() {
        // Not cosmetic: a hello with no tags leaves the receiver's username
        // pointer NULL, and at least one fork dereferences it. See build_hello.
        let f = build_hello(&[0u8; 16], 0, 4662);
        let mut at = 33; // after hash size, hash, id, port, tag count
        let mut seen = Vec::new();
        for _ in 0..3 {
            let ttype = f[at];
            assert_eq!(ttype & 0x80, 0x80, "hello tags use the single-byte name form");
            let id = f[at + 1];
            seen.push(id);
            at += 2;
            match ttype & 0x7F {
                0x02 => {
                    let n = u16::from_le_bytes([f[at], f[at + 1]]) as usize;
                    at += 2 + n;
                }
                0x03 => at += 4,
                other => panic!("unexpected tag type 0x{other:02X}"),
            }
        }
        assert_eq!(seen, vec![CT_NAME, CT_VERSION, CT_PORT]);
        // Everything consumed except the trailing server address fields.
        assert_eq!(at, f.len() - 6);
    }

    #[test]
    fn high_id_encoding() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let id = high_id_from_ip(ip).unwrap();
        // LE bytes of [1,2,3,4] = 0x04030201
        assert_eq!(id, 0x04030201);
    }
}

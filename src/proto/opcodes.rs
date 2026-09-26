//! eD2k protocol opcodes.
//!
//! Reference: SPEC.md §2.3, derived from aMule
//! `src/include/protocol/ed2k/Client2Server/TCP.h`.

#![allow(dead_code)]

// Protocol markers (first byte of every frame, see SPEC.md §2.1)
pub const PROTO_EDONKEY: u8 = 0xE3;
pub const PROTO_PACKED: u8 = 0xD4; // zlib-compressed payload
pub const PROTO_EMULE: u8 = 0xC5; // eMule extended (client-to-client only)

// Client → Server (TCP)
pub const OP_LOGINREQUEST: u8 = 0x01;
pub const OP_GETSERVERLIST: u8 = 0x14;
pub const OP_OFFERFILES: u8 = 0x15;
pub const OP_SEARCHREQUEST: u8 = 0x16;
pub const OP_DISCONNECT: u8 = 0x18;
pub const OP_GETSOURCES: u8 = 0x19;
pub const OP_SEARCH_USER: u8 = 0x1A;
pub const OP_CALLBACKREQUEST: u8 = 0x1C;
pub const OP_QUERY_MORE_RESULT: u8 = 0x21;
pub const OP_GETSOURCES_OBFU: u8 = 0x23;

// ── LowID↔LowID NAT-traversal (custom server extension, §3.12) ──────────────
// These are an ed2k-server extension, NOT part of stock eD2k. A modified client
// uses them to ask the server to coordinate a UDP hole punch with another LowID
// client. The server only exchanges small address packets — it never relays
// file data. Opcodes chosen in the 0x60 range to avoid any stock eD2k collision.
//
// Client→server: requester asks to reach another LowID by its server ID, and
// includes its OWN UDP port (the client knows it; the server would otherwise
// have to parse it out of the login tags, which not all clients send reliably).
//   payload: target_id(4) + requester_udp_port(2)
pub const OP_LOWID_HOLEPUNCH_REQUEST: u8 = 0x60;
// Server→both clients: each side is told the other's address so they can punch.
//   payload: peer_ip(4 LE) + peer_tcp_port(2 LE) + peer_udp_port(2 LE)
//          + peer_user_hash(16) + role(1)   role: 0 = you initiate, 1 = you wait
pub const OP_LOWID_HOLEPUNCH_INFO: u8 = 0x61;
// Server→requester: the request could not be coordinated.
//   payload: target_id(4) + reason(1)
//   reason: 1 = target not connected, 2 = target is HighID (no punch needed),
//           3 = requester not logged in / invalid
pub const OP_LOWID_HOLEPUNCH_FAIL: u8 = 0x62;

// Server → Client (TCP)
pub const OP_REJECT: u8 = 0x05;
pub const OP_SERVERLIST: u8 = 0x32;
pub const OP_SEARCHRESULT: u8 = 0x33;
pub const OP_SERVERSTATUS: u8 = 0x34;
pub const OP_CALLBACKREQUESTED: u8 = 0x35;
pub const OP_CALLBACK_FAIL: u8 = 0x36;
pub const OP_SERVERMESSAGE: u8 = 0x38;
pub const OP_IDCHANGE: u8 = 0x40;
pub const OP_SERVERIDENT: u8 = 0x41;
pub const OP_FOUNDSOURCES: u8 = 0x42;
pub const OP_FOUNDSOURCES_OBFU: u8 = 0x44;

// Tag IDs - File (FT_*) - SPEC.md §A.1
pub const FT_FILENAME: u8 = 0x01;
pub const FT_FILESIZE: u8 = 0x02;
pub const FT_FILETYPE: u8 = 0x03;
pub const FT_FILEFORMAT: u8 = 0x04;
pub const FT_SOURCES: u8 = 0x15;
pub const FT_COMPLETE_SOURCES: u8 = 0x30;
pub const FT_FILESIZE_HI: u8 = 0x3A; // high 32 bits for >4GiB files
pub const FT_FILERATING: u8 = 0xF7;

// Tag IDs - Client/login (CT_*)
pub const CT_NAME: u8 = 0x01;
pub const CT_PORT: u8 = 0x0F;
pub const CT_VERSION: u8 = 0x11;
pub const CT_SERVER_FLAGS: u8 = 0x20;
pub const CT_EMULE_VERSION: u8 = 0xFB; // encodes clientid (top 8 bits) + version
pub const CT_MOD_VERSION: u8 = 0x55; // string: mod name ("lc-mod", "Plus", …)
pub const CT_EMULE_MISCOPTIONS1: u8 = 0xF4;
/// CT_EMULE_UDPPORTS (0xf9): u32 tag, high 16 bits = Kad UDP port, low 16 bits
/// = client UDP port. eMule sends it in client↔client hello; our NAT-traversal
/// client mod also sends it in the server login so the server learns the
/// client's UDP port for LowID↔LowID hole punching. Stock clients omit it.
pub const CT_EMULE_UDPPORTS: u8 = 0xF9;
pub const CT_EMULE_MISCOPTIONS2: u8 = 0xF2;
// CT_EMULE_VERSION clientid constants (top 8 bits >> 24)
// EClientSoftware enum values from eMule 0.49c ClientStateDefs.h.
// These are the values placed in the TOP 8 bits of CT_EMULE_VERSION.
pub const CLIENTID_EMULE: u8 = 0;
pub const CLIENTID_CDONKEY: u8 = 1;
pub const CLIENTID_XMULE: u8 = 2;
pub const CLIENTID_AMULE: u8 = 3;
pub const CLIENTID_SHAREAZA: u8 = 4;
pub const CLIENTID_MLDONKEY: u8 = 10;
pub const CLIENTID_LPHANT: u8 = 20;

// Tag IDs - Server (ST_*) - SPEC.md §A.2
pub const ST_SERVERNAME: u8 = 0x01;
pub const ST_DESCRIPTION: u8 = 0x0B;
pub const ST_DYNIP: u8 = 0x85;
pub const ST_MAXUSERS: u8 = 0x87;
pub const ST_SOFTFILES: u8 = 0x88;
pub const ST_HARDFILES: u8 = 0x89;
pub const ST_VERSION: u8 = 0x91;
pub const ST_UDPFLAGS: u8 = 0x92;
pub const ST_AUXPORTSLIST: u8 = 0x93;
pub const ST_LOWIDUSERS: u8 = 0x94;
pub const ST_TCPPORTOBFUSCATION: u8 = 0x97;
pub const ST_UDPPORTOBFUSCATION: u8 = 0x98;

// Client capability flags in CT_SERVER_FLAGS.
//
// ⚠ VALUES TAKEN FROM CLIENTS, NOT FROM THE SPEC DOCUMENT. Two of these were
//   wrong until 0.9.76 — LARGEFILES was 0x0020 and SUPPORTCRYPT was 0x0800 —
//   and the second was the dangerous one: 0x0800 is REQUIRECRYPT on every real
//   client, so anyone reaching for the shared constant would have been testing
//   "requires obfuscation" while the name said "supports" it. LARGEFILES at
//   0x0020 tested a bit no client sets at all.
//
//   Nothing was broken, because the only bit the server reads had a private,
//   correct copy in server/login.rs. That duplicate was the smell: a shared
//   table nobody trusted enough to use.
//
// Verified against srchybrid/Opcodes.h in eMule 0.72a (SRVCAP_*), and reported
// as matching eMule 0.70b, eMuleAI and aMule's src/include/tags/ClientTags.h.
pub const CAPABLE_ZLIB: u32 = 0x0001;
pub const CAPABLE_IP_IN_LOGIN: u32 = 0x0002;
pub const CAPABLE_AUXPORT: u32 = 0x0004;
pub const CAPABLE_NEWTAGS: u32 = 0x0008;
pub const CAPABLE_UNICODE: u32 = 0x0010;
pub const CAPABLE_LARGEFILES: u32 = 0x0100;
/// The client can speak obfuscated connections.
pub const CAPABLE_SUPPORTCRYPT: u32 = 0x0200;
/// The client would prefer them.
pub const CAPABLE_REQUESTCRYPT: u32 = 0x0400;
/// The client accepts nothing else — a plain connection to it will be dropped.
pub const CAPABLE_REQUIRECRYPT: u32 = 0x0800;
/// The client speaks the IPv6 source extension.
///
/// ⚠ The two directions use DIFFERENT values. This one is client→server in
///   CT_SERVER_FLAGS; server→client is 0x4000 in the OP_IDCHANGE and ping flag
///   words (`login::SRV_TCPFLG_IPV6`). Both published specs define the
///   asymmetry deliberately.
pub const CAPABLE_IPV6: u32 = 0x1000;

// Server flags advertised in IDCHANGE
pub const SRVFLG_ZLIB: u32 = 0x0001;
pub const SRVFLG_IP_IN_LOGIN: u32 = 0x0002;
pub const SRVFLG_AUXPORT: u32 = 0x0004;
pub const SRVFLG_NEWTAGS: u32 = 0x0008;
pub const SRVFLG_UNICODE: u32 = 0x0010;
pub const SRVFLG_LARGEFILES: u32 = 0x0100;
/// Server supports obfuscated (RC4) connections — makes eMule show "Obfuscation: Yes"
pub const SRVFLG_SUPPORTCRYPT: u32 = 0x0800;
/// Server UDP capability mask advertised in ST_UDPFLAGS and GLOBSERVSTATRES.
///
/// 0x073B. Was 0x17FB, copied wholesale from Lugdunum 17.15 as seen in captures;
/// bit 0x1000 is dropped because nothing on the network knows what it means —
/// not eMule's `Server.h`, not aMule's `Client2Server/UDP.h`, not mldonkey's
/// `donkeyProtoServer.ml`, which is the most permissive parser of the three.
/// A bit no client can interpret promises nothing and can only mislead a reader
/// of our own traffic.
///
/// What each remaining bit claims, and why it is earned:
///
/// | bit | name | evidence |
/// |---|---|---|
/// | 0x0001 | EXT_GETSOURCES | 0x9A answered with 0x9B carrying id+port per source |
/// | 0x0002 | EXT_GETFILES | 0x92 and 0x90 both handled (0x92 added in 0.9.71) |
/// | 0x0008 | NEWTAGS | all 987 tags in a 245-result capture use the 0x80 form |
/// | 0x0010 | UNICODE | non-ASCII filenames decode as valid UTF-8 in replies |
/// | 0x0020 | EXT_GETSOURCES2 | 0x94 records walked correctly (fixed in 0.9.71) |
/// | 0x0040 | RELATEDSEARCH | NOT implemented — kept pending a decision |
/// | 0x0080 | TYPETAGINTEGER | FT_FILETYPE emitted as an integer in both result paths |
/// | 0x0100 | LARGEFILES | FT_FILESIZE_HI emitted; 17 GiB file observed correct |
/// | 0x0200 | UDPOBFUSCATION | the large majority of our UDP output is obfuscated |
/// | 0x0400 | TCPOBFUSCATION | handshake verified by capture against eMule/aMule |
///
/// 0x0040 RELATEDSEARCH is advertised and not implemented, deliberately. It is a
/// real Lugdunum feature: `Is_related_search` (eserver decompile) recognises a
/// search term literally beginning "related:", parses up to 32 `count:hash`
/// pairs out of it, and rewrites the node to type 0x4F — so it is an ordinary
/// search whose text has a special shape, not a separate opcode. Building it
/// here is tractable (the user→files index already exists) but its value at this
/// index size is unproven, and it would expose which publisher holds what.
/// Documented rather than silently wrong; clearing the bit is one edit.
///
/// Note 0x0004 has never been set. Whoever assembled the original mask left it
/// out, and no client defines it either.
pub const SERVER_UDP_FLAGS: u32 = 0x0000_073B;

/// Server prefers obfuscated connections
pub const SRVFLG_REQUESTCRYPT: u32 = 0x1000;

/// Server speaks the IPv6 source extension.
///
/// ⚠ Server→client, in the `OP_IDCHANGE` and `OP_GLOBSERVSTATRES` flag words.
///   The client→server bit for the same capability is `CAPABLE_IPV6` (0x1000),
///   a different value in a different packet. Both published specs define that
///   asymmetry deliberately, and it is the single easiest thing here to get
///   backwards.
pub const SRVFLG_IPV6: u32 = 0x0000_4000;

// OFFERFILES self-source markers - SPEC.md §3.3
pub const SELF_COMPLETE_ID: u32 = 0xFBFB_FBFB;
pub const SELF_COMPLETE_PORT: u16 = 0xFBFB;
pub const SELF_INCOMPLETE_ID: u32 = 0xFCFC_FCFC;
pub const SELF_INCOMPLETE_PORT: u16 = 0xFCFC;

/// Returns a human-readable name for a Client→Server opcode (for logging).
pub fn opcode_name_c2s(op: u8) -> &'static str {
    match op {
        OP_LOGINREQUEST => "LOGINREQUEST",
        OP_GETSERVERLIST => "GETSERVERLIST",
        OP_OFFERFILES => "OFFERFILES",
        OP_SEARCHREQUEST => "SEARCHREQUEST",
        OP_DISCONNECT => "DISCONNECT",
        OP_GETSOURCES => "GETSOURCES",
        OP_SEARCH_USER => "SEARCH_USER",
        OP_CALLBACKREQUEST => "CALLBACKREQUEST",
        OP_QUERY_MORE_RESULT => "QUERY_MORE_RESULT",
        OP_GETSOURCES_OBFU => "GETSOURCES_OBFU",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod capability_tests {
    use super::*;

    #[test]
    fn the_capability_bits_match_what_clients_actually_send() {
        // Read from srchybrid/Opcodes.h in eMule 0.72a. Two of these were wrong
        // for a long time and nothing caught it, because the only bit the
        // server reads had a private copy elsewhere — so the shared table was
        // never exercised.
        assert_eq!(CAPABLE_ZLIB, 0x0001);
        assert_eq!(CAPABLE_IP_IN_LOGIN, 0x0002);
        assert_eq!(CAPABLE_AUXPORT, 0x0004);
        assert_eq!(CAPABLE_NEWTAGS, 0x0008);
        assert_eq!(CAPABLE_UNICODE, 0x0010);
        assert_eq!(CAPABLE_LARGEFILES, 0x0100);
        assert_eq!(CAPABLE_SUPPORTCRYPT, 0x0200);
        assert_eq!(CAPABLE_REQUESTCRYPT, 0x0400);
        assert_eq!(CAPABLE_REQUIRECRYPT, 0x0800);
        assert_eq!(CAPABLE_IPV6, 0x1000);
    }

    #[test]
    fn the_three_crypt_bits_are_distinct_and_ordered() {
        // The old value of SUPPORTCRYPT was 0x0800, which is REQUIRECRYPT. A
        // reader taking the shared constant would have tested "requires
        // obfuscation" while the name promised "supports" it — the opposite
        // conclusion for a client that merely permits it.
        assert_ne!(CAPABLE_SUPPORTCRYPT, CAPABLE_REQUIRECRYPT);
        assert!(CAPABLE_SUPPORTCRYPT < CAPABLE_REQUESTCRYPT);
        assert!(CAPABLE_REQUESTCRYPT < CAPABLE_REQUIRECRYPT);
    }

    #[test]
    fn the_two_directions_of_the_ipv6_bit_stay_different() {
        // The asymmetry is deliberate in both published specs and is the single
        // easiest thing in this file to get backwards. Client->server is
        // 0x1000 in CT_SERVER_FLAGS; server->client is 0x4000 in the IDCHANGE
        // and ping flag words.
        assert_eq!(CAPABLE_IPV6, 0x1000);
        assert_eq!(SRVFLG_IPV6, 0x4000);
        assert_ne!(CAPABLE_IPV6, SRVFLG_IPV6);
        // ...and the server bit must not collide with what IDCHANGE already
        // carries.
        assert_eq!(0x0000_05DD & SRVFLG_IPV6, 0);
    }

    #[test]
    fn no_two_capability_bits_collide() {
        let all = [
            CAPABLE_ZLIB,
            CAPABLE_IP_IN_LOGIN,
            CAPABLE_AUXPORT,
            CAPABLE_NEWTAGS,
            CAPABLE_UNICODE,
            CAPABLE_LARGEFILES,
            CAPABLE_SUPPORTCRYPT,
            CAPABLE_REQUESTCRYPT,
            CAPABLE_REQUIRECRYPT,
            CAPABLE_IPV6,
        ];
        let mut seen = 0u32;
        for bit in all {
            assert_eq!(bit.count_ones(), 1, "0x{bit:04X} is not a single bit");
            assert_eq!(seen & bit, 0, "0x{bit:04X} collides with an earlier flag");
            seen |= bit;
        }
    }
}

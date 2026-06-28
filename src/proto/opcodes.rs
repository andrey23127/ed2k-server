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
pub const CT_EMULE_VERSION: u8 = 0xFB;  // encodes clientid (top 8 bits) + version
pub const CT_MOD_VERSION: u8   = 0x55;  // string: mod name ("lc-mod", "Plus", …)
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
pub const CLIENTID_EMULE:    u8 = 0;
pub const CLIENTID_CDONKEY:  u8 = 1;
pub const CLIENTID_XMULE:    u8 = 2;
pub const CLIENTID_AMULE:    u8 = 3;
pub const CLIENTID_SHAREAZA: u8 = 4;
pub const CLIENTID_MLDONKEY: u8 = 10;
pub const CLIENTID_LPHANT:   u8 = 20;

// Tag IDs - Server (ST_*) - SPEC.md §A.2
pub const ST_SERVERNAME: u8 = 0x01;
pub const ST_DESCRIPTION: u8 = 0x0B;
pub const ST_DYNIP: u8 = 0x85;
pub const ST_MAXUSERS: u8 = 0x87;
pub const ST_SOFTFILES: u8 = 0x88;
pub const ST_HARDFILES: u8 = 0x89;
pub const ST_VERSION: u8 = 0x91;
pub const ST_UDPFLAGS: u8                = 0x92;
pub const ST_AUXPORTSLIST: u8 = 0x93;
pub const ST_LOWIDUSERS: u8              = 0x94;
pub const ST_TCPPORTOBFUSCATION: u8      = 0x97;
pub const ST_UDPPORTOBFUSCATION: u8      = 0x98;

// Client capability flags in CT_SERVER_FLAGS - SPEC.md §3.1.3
pub const CAPABLE_ZLIB: u32 = 0x0001;
pub const CAPABLE_IP_IN_LOGIN: u32 = 0x0002;
pub const CAPABLE_AUXPORT: u32 = 0x0004;
pub const CAPABLE_NEWTAGS: u32 = 0x0008;
pub const CAPABLE_UNICODE: u32 = 0x0010;
pub const CAPABLE_LARGEFILES: u32 = 0x0020;
pub const CAPABLE_SUPPORTCRYPT: u32 = 0x0800;

// Server flags advertised in IDCHANGE
pub const SRVFLG_ZLIB: u32 = 0x0001;
pub const SRVFLG_IP_IN_LOGIN: u32 = 0x0002;
pub const SRVFLG_AUXPORT: u32 = 0x0004;
pub const SRVFLG_NEWTAGS: u32 = 0x0008;
pub const SRVFLG_UNICODE: u32 = 0x0010;
pub const SRVFLG_LARGEFILES: u32 = 0x0100;
/// Server supports obfuscated (RC4) connections — makes eMule show "Obfuscation: Yes"
pub const SRVFLG_SUPPORTCRYPT: u32 = 0x0800;
/// Server prefers obfuscated connections
pub const SRVFLG_REQUESTCRYPT: u32 = 0x1000;

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

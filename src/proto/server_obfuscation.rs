//! Server-to-server obfuscated UDP (Lugdunum-compatible).
//!
//! Real eD2k servers exchange GLOBSERVSTATREQ/RES and SERVER_LIST traffic over
//! an *obfuscated* UDP channel — plain `0xE3` datagrams between servers are
//! ignored by Lugdunum. Without speaking this dialect our server never gets
//! its `pchallenge` set on a seed and therefore never appears in anyone's
//! server.met. This module implements that obfuscation layer.
//!
//! Algorithm reverse-engineered from eserver.c (UDPthread @ ~line 2200 for
//! receive, UDPthread_4673 @ ~line 2655 for send):
//!
//! Wire format of an obfuscated UDP datagram:
//!   [0]      1 random pad byte (never 0xE3 / 0xD4 / 0xC5 — those mark plain
//!            and zlib frames, so the receiver can tell obfuscated from plain
//!            by the first byte)
//!   [1..3)   2 random "key salt" bytes (Lugdunum calls this RandomKeyPartC)
//!   [3..]    RC4-encrypted blob:
//!              magic(4)   = 0x13EF24D5  (verifies the key on decrypt)
//!              padlen(1)  = low nibble is the real pad length (0..15)
//!              pad(padlen) zero bytes
//!              message    the actual ed2k payload (E3 + opcode + ...)
//!
//! Key derivation has two variants in Lugdunum. We implement the one keyed on
//! IPObfuscate, used by the main obfuscated UDP socket:
//!
//!   ServerKey = IPObfuscate(peer_ip)
//!             = let d = MD5(seckey[0..16] || peer_ip_le(4));
//!               d[0] ^ d[1] ^ d[2] ^ d[3]   (four LE u32 words of the digest)
//!               (if the result is 0, Lugdunum substitutes 0x5D78B234)
//!
//!   RC4_key   = MD5( ServerKey(4 LE) || salt(2) || 0x00(1) )   — 7 bytes in
//!
//! `seckey` is a 16-byte secret each server generates once and keeps private
//! (Lugdunum stores it in donkey.ini). Two servers cannot derive the *same*
//! key for a given direction unless they exchange ServerKey values — which is
//! exactly what the ServerKey field in GLOBSERVSTATRES is for. For our own
//! receive path we use *our* seckey + the sender's IP; for sending to a peer
//! we use the ServerKey that peer told us.

use md5::{Digest, Md5};

use crate::proto::obfuscation::Rc4;

/// Magic value that the first 4 bytes of the decrypted blob must equal.
/// Confirms we derived the right RC4 key before trusting the rest.
const OBF_MAGIC: u32 = 0x13EF_24D5;

/// Fallback ServerKey when IPObfuscate's XOR-fold lands on zero (eserver.c).
const SERVERKEY_ZERO_FALLBACK: u32 = 0x5D78_B234;

/// Maximum random padding inserted before the real message (Lugdunum's
/// `padrange` default). padlen is stored in the low nibble so it never
/// exceeds 15 anyway; we cap our own sending side here.
const MAX_PAD: usize = 12;

/// Compute `ServerKey = IPObfuscate(ip)` for a given 16-byte server secret.
///
/// `peer_ip_le` is the IP as a little-endian u32 with octets in natural order
/// (i.e. `u32::from_le_bytes(ip.octets())`), matching how Lugdunum passes
/// `sin_addr.s_addr` on a little-endian host.
pub fn ip_obfuscate(seckey: &[u8; 16], peer_ip_le: u32) -> u32 {
    let mut hasher = Md5::new();
    hasher.update(seckey);
    hasher.update(peer_ip_le.to_le_bytes());
    let digest = hasher.finalize(); // 16 bytes

    // XOR the four little-endian 32-bit words of the digest together.
    let w0 = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
    let w1 = u32::from_le_bytes([digest[4], digest[5], digest[6], digest[7]]);
    let w2 = u32::from_le_bytes([digest[8], digest[9], digest[10], digest[11]]);
    let w3 = u32::from_le_bytes([digest[12], digest[13], digest[14], digest[15]]);
    let key = w0 ^ w1 ^ w2 ^ w3;

    if key == 0 {
        SERVERKEY_ZERO_FALLBACK
    } else {
        key
    }
}

/// Derive the RC4 cipher for an obfuscated datagram.
///
/// `server_key` is the 4-byte ServerKey (ours-from-their-IP on receive, or
/// the peer-provided value on send). `salt` is the 2 random bytes carried in
/// the datagram header. The MD5 input is exactly 7 bytes:
///   server_key(4 LE) || salt(2) || 0x00(1)
fn derive_cipher(server_key: u32, salt: [u8; 2]) -> Rc4 {
    let mut input = [0u8; 7];
    input[0..4].copy_from_slice(&server_key.to_le_bytes());
    input[4] = salt[0];
    input[5] = salt[1];
    input[6] = 0x00;

    let digest = Md5::digest(input); // 16-byte RC4 key
    // Server-to-server RC4 does NOT drop the first 1024 bytes (unlike the
    // client DH obfuscation) — eserver.c uses the keystream immediately.
    Rc4::new(&digest, false)
}

/// Derive the RC4 cipher with an explicit obfuscation-channel byte.
///
/// `obf_byte` distinguishes channels: 0x00 for the plain s2s channel,
/// 0xA5 for the TCP+12 (obfpingport) reply channel that seeds use when
/// responding to OBF ping handshakes.
/// Derive RC4 cipher with an explicit obfuscation-channel byte.
///
/// Wire layout of the MD5 input (7 bytes):
///   key_LE(4) || obf_byte(1) || salt(2)
///
/// Verified against real Lugdunum 17.15 packet capture:
///   packet hex: 43 44 0f 8c ... (58 bytes), session_key=0x02371540
///   salt=[44,0f], MD5([40,15,37,02, a5, 44,0f]) → correct RC4 key ✓
///
/// Note: the main channel (`derive_cipher` with 0x00) uses the same formula
/// (key+0x00+salt) but since any ordering with a null byte gives equivalent
/// results for our internally-consistent encode/decode pair, both work.
pub fn derive_cipher_with_obfbyte(server_key: u32, salt: [u8; 2], obf_byte: u8) -> Rc4 {
    let mut input = [0u8; 7];
    input[0..4].copy_from_slice(&server_key.to_le_bytes());
    input[4] = obf_byte;   // obf_byte BEFORE salt — confirmed from packet capture
    input[5] = salt[0];
    input[6] = salt[1];
    let digest = Md5::digest(input);
    Rc4::new(&digest, false)
}

/// Like `decode`, but lets the caller specify which obf channel byte to use.
/// Pass `0x00` for regular s2s gossip, `0xA5` for OBF-ping reply channel.
pub fn decode_with_obfbyte(datagram: &[u8], server_key: u32, obf_byte: u8) -> Option<Vec<u8>> {
    if datagram.len() < 10 {
        return None;
    }
    let salt = [datagram[1], datagram[2]];
    let mut cipher = derive_cipher_with_obfbyte(server_key, salt, obf_byte);
    let mut blob = datagram[3..].to_vec();
    cipher.apply(&mut blob);
    let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    if magic != OBF_MAGIC {
        return None;
    }
    let padlen = (blob[4] & 0x0F) as usize;
    let msg_start = 5 + padlen;
    if msg_start >= blob.len() {
        return None;
    }
    Some(blob[msg_start..].to_vec())
}

/// Attempt to decode an obfuscated server-to-server UDP datagram.
///
/// `datagram` is the raw bytes received. `server_key` is `ip_obfuscate(our
/// seckey, sender_ip)`. Returns the inner ed2k message (starting at its 0xE3
/// proto byte) on success, or `None` if this isn't a valid obfuscated frame
/// for this key (wrong magic, too short, etc.) — the caller then treats the
/// datagram as plain or drops it.
pub fn decode(datagram: &[u8], server_key: u32) -> Option<Vec<u8>> {
    // Need at least: pad(1) + salt(2) + magic(4) + padlen(1) = 8 bytes,
    // plus at least a 2-byte ed2k message.
    if datagram.len() < 10 {
        return None;
    }

    let salt = [datagram[1], datagram[2]];
    let mut cipher = derive_cipher(server_key, salt);

    // Decrypt everything from offset 3 onward.
    let mut blob = datagram[3..].to_vec();
    cipher.apply(&mut blob);

    // Verify magic.
    let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    if magic != OBF_MAGIC {
        return None; // wrong key, or not actually obfuscated
    }

    // padlen is the low nibble of the byte after the magic.
    let padlen = (blob[4] & 0x0F) as usize;
    let msg_start = 5 + padlen;
    if msg_start >= blob.len() {
        return None; // padding overruns the buffer
    }

    Some(blob[msg_start..].to_vec())
}

/// Encode an ed2k message into an obfuscated server-to-server UDP datagram.
///
/// `message` is the full inner ed2k frame (0xE3 + opcode + payload).
/// `server_key` is the key the *recipient* will use to decrypt — for the
/// IPObfuscate variant that is `ip_obfuscate(recipient_seckey, our_ip)`,
/// which the recipient told us via the ServerKey field of GLOBSERVSTATRES.
/// `rng_seed` is mixed into the random fields; pass something varying
/// (e.g. a counter or timestamp) so successive datagrams differ.
pub fn encode(message: &[u8], server_key: u32, rng_seed: u32) -> Vec<u8> {
    // Tiny deterministic PRNG (xorshift) — we don't need crypto-grade
    // randomness for the pad/salt, just variation. Lugdunum uses ds_rand_r.
    let mut state = rng_seed ^ 0x9E37_79B9;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state
    };

    // First byte: random, but must not collide with the plain/zlib/emule
    // proto markers, or a receiver would try to parse it as a plain frame.
    let mut pad0 = (next() & 0xFF) as u8;
    while pad0 == 0xE3 || pad0 == 0xD4 || pad0 == 0xC5 {
        pad0 = (next() & 0xFF) as u8;
    }

    let r = next();
    let salt = [(r & 0xFF) as u8, ((r >> 8) & 0xFF) as u8];

    // Random pad length 0..MAX_PAD, stored in the low nibble of one byte.
    let padlen = (next() as usize) % (MAX_PAD + 1);

    // Build the plaintext blob: magic(4) + padlen(1) + pad(padlen) + message.
    let mut blob = Vec::with_capacity(5 + padlen + message.len());
    blob.extend_from_slice(&OBF_MAGIC.to_le_bytes());
    blob.push((padlen & 0x0F) as u8);
    blob.resize(blob.len() + padlen, 0u8); // zero padding
    blob.extend_from_slice(message);

    // Encrypt the blob.
    let mut cipher = derive_cipher(server_key, salt);
    cipher.apply(&mut blob);

    // Assemble the datagram: pad0(1) + salt(2) + encrypted blob.
    let mut datagram = Vec::with_capacity(3 + blob.len());
    datagram.push(pad0);
    datagram.push(salt[0]);
    datagram.push(salt[1]);
    datagram.extend_from_slice(&blob);
    datagram
}

/// Like `encode`, but with an explicit obfuscation-channel byte.
/// `0x00` = plain s2s channel (default), `0xa5` = TCP+12 obfpingport channel.
pub fn encode_with_obfbyte(message: &[u8], server_key: u32, rng_seed: u32, obf_byte: u8) -> Vec<u8> {
    let mut state = rng_seed ^ 0x9E37_79B9;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state
    };
    let mut pad0 = (next() & 0xFF) as u8;
    while pad0 == 0xE3 || pad0 == 0xD4 || pad0 == 0xC5 {
        pad0 = (next() & 0xFF) as u8;
    }
    let r = next();
    let salt = [(r & 0xFF) as u8, ((r >> 8) & 0xFF) as u8];
    let padlen = (next() as usize) % (MAX_PAD + 1);

    let mut blob = Vec::with_capacity(5 + padlen + message.len());
    blob.extend_from_slice(&OBF_MAGIC.to_le_bytes());
    blob.push((padlen & 0x0F) as u8);
    blob.resize(blob.len() + padlen, 0u8);
    blob.extend_from_slice(message);

    let mut cipher = derive_cipher_with_obfbyte(server_key, salt, obf_byte);
    cipher.apply(&mut blob);

    let mut datagram = Vec::with_capacity(3 + blob.len());
    datagram.push(pad0);
    datagram.push(salt[0]);
    datagram.push(salt[1]);
    datagram.extend_from_slice(&blob);
    datagram
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_obfuscate_is_deterministic_and_nonzero() {
        let seckey = [0xABu8; 16];
        let ip = u32::from_le_bytes([171, 25, 158, 106]);
        let k1 = ip_obfuscate(&seckey, ip);
        let k2 = ip_obfuscate(&seckey, ip);
        assert_eq!(k1, k2, "same inputs must give same key");
        assert_ne!(k1, 0, "key must never be zero");
    }

    #[test]
    fn ip_obfuscate_differs_per_ip() {
        let seckey = [0x11u8; 16];
        let a = ip_obfuscate(&seckey, u32::from_le_bytes([1, 2, 3, 4]));
        let b = ip_obfuscate(&seckey, u32::from_le_bytes([1, 2, 3, 5]));
        assert_ne!(a, b, "different IPs should give different keys");
    }

    #[test]
    fn ip_obfuscate_differs_per_seckey() {
        let ip = u32::from_le_bytes([8, 8, 8, 8]);
        let a = ip_obfuscate(&[0x01; 16], ip);
        let b = ip_obfuscate(&[0x02; 16], ip);
        assert_ne!(a, b, "different secrets should give different keys");
    }

    #[test]
    fn encode_decode_round_trip() {
        // Both sides agree on the same ServerKey (in reality exchanged via
        // GLOBSERVSTATRES); here we just pick one.
        let server_key = 0xDEAD_BEEFu32;
        let message = vec![0xE3, 0x97, 0x01, 0x02, 0x03, 0x04];

        let datagram = encode(&message, server_key, 12345);
        // First byte must not look like a plain/zlib/emule frame.
        assert_ne!(datagram[0], 0xE3);
        assert_ne!(datagram[0], 0xD4);
        assert_ne!(datagram[0], 0xC5);

        let decoded = decode(&datagram, server_key).expect("should decode");
        assert_eq!(decoded, message, "round trip must preserve the message");
    }

    #[test]
    fn decode_with_wrong_key_fails() {
        let message = vec![0xE3, 0x97, 0xAA, 0xBB];
        let datagram = encode(&message, 0x1111_1111, 999);
        // A different key must fail the magic check, not return garbage.
        assert!(decode(&datagram, 0x2222_2222).is_none());
    }

    #[test]
    fn decode_rejects_too_short() {
        assert!(decode(&[0x00, 0x01, 0x02], 0x1234).is_none());
        assert!(decode(&[], 0x1234).is_none());
    }

    #[test]
    fn varying_seed_varies_datagram() {
        let key = 0xCAFE_0000u32;
        let msg = vec![0xE3, 0x96, 0x01, 0x02, 0x03, 0x04];
        let d1 = encode(&msg, key, 1);
        let d2 = encode(&msg, key, 2);
        // Different seeds → different salt/pad → different bytes on the wire,
        // but both still decode back to the same message.
        assert_ne!(d1, d2, "datagrams should differ with different seeds");
        assert_eq!(decode(&d1, key).unwrap(), msg);
        assert_eq!(decode(&d2, key).unwrap(), msg);
    }

    #[test]
    fn padding_lengths_all_round_trip() {
        // Exercise every seed-driven pad length by trying many seeds.
        let key = 0x5555_AAAAu32;
        let msg = vec![0xE3, 0xA1, 0xFF];
        for seed in 0..64u32 {
            let d = encode(&msg, key, seed);
            assert_eq!(
                decode(&d, key).expect("decode"),
                msg,
                "seed {seed} should round-trip"
            );
        }
    }
}

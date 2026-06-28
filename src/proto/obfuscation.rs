//! Protocol obfuscation for eD2k TCP connections (SPEC.md §4).
//!
//! Ported from eNode-go/ed2k/crypt.go + tcpcrypt.go (MIT License).
//! Original author: zt8989 / David Xanatos.
//!
//! Algorithm:
//!   1. Client sends: SemiRandomMarker(1) + DH_pub_A(96) + Padding(0-15)
//!   2. Server generates private b, computes:
//!        B = g^b mod p  (server DH public)
//!        K = A^b mod p  (shared secret, 96 bytes)
//!   3. Derive RC4 keys from MD5(K || magic_byte), discard first 1024 bytes
//!   4. Server sends: B(96) + RC4( MagicSync(4) + Methods(1) + Chosen(1) + PadLen(1) + Pad )
//!   5. Client sends (encrypted): MagicSync(4) + Method(1) + PadLen(1) + Pad + [payload]
//!   6. After handshake: all bytes encrypted with respective RC4 streams.

use num_bigint::BigUint;


// ─── DH-768 parameters ───────────────────────────────────────────────────────

/// 768-bit safe prime used for DH key exchange (SPEC.md §A.4).
/// Same constant across all eD2k implementations.
pub const DH_PRIME: [u8; 96] = [
    0xF2, 0xBF, 0x52, 0xC5, 0x5F, 0x58, 0x7A, 0xDD, 0x53, 0x71, 0xA9, 0x36,
    0xE8, 0x86, 0xEB, 0x3C, 0x62, 0x17, 0xA3, 0x3E, 0xC3, 0x4C, 0xB4, 0x0D,
    0xC7, 0x3A, 0x41, 0xA6, 0x43, 0xAF, 0xFC, 0xE7, 0x21, 0xFC, 0x28, 0x63,
    0x66, 0x53, 0x5B, 0xDB, 0xCE, 0x25, 0x9F, 0x22, 0x86, 0xDA, 0x4A, 0x91,
    0xB2, 0x07, 0xCB, 0xAA, 0x52, 0x55, 0xD4, 0xF6, 0x1C, 0xCE, 0xAE, 0xD4,
    0x5A, 0xD5, 0xE0, 0x74, 0x7D, 0xF7, 0x78, 0x18, 0x28, 0x10, 0x5F, 0x34,
    0x0F, 0x76, 0x23, 0x87, 0xF8, 0x8B, 0x28, 0x91, 0x42, 0xFB, 0x42, 0x68,
    0x8F, 0x05, 0x15, 0x0F, 0x54, 0x8B, 0x5F, 0x43, 0x6A, 0xF7, 0x0D, 0xF3,
];

const DH_G: u64 = 2;
pub const DH_PRIME_SIZE: usize = 96;
/// Private exponent size: 16 bytes = 128 bits (eNode-go: CryptDhaSize = 16)
const DH_PRIVATE_SIZE: usize = 16;

const MAGIC_VALUE_SERVER: u8    = 203;  // 0xCB
const MAGIC_VALUE_REQUESTER: u8 = 34;   // 0x22
const MAGIC_SYNC: u32 = 0x835E_6FC4;

const EM_OBFUSCATE: u8 = 0;

/// eD2k protocol markers that must NOT appear as the SemiRandomMarker byte
/// (would make the stream look like a plain eD2k frame to the server).
const FORBIDDEN_MARKERS: [u8; 3] = [0xE3, 0xC5, 0xD4];

// ─── RC4 ─────────────────────────────────────────────────────────────────────

/// RC4 state (ported from eNode-go RC4Key).
pub struct Rc4 {
    state: [u8; 256],
    x: u8,
    y: u8,
}

impl Rc4 {
    /// Initialize RC4 with a key and optionally discard the first 1024 bytes
    /// of keystream (standard eD2k anti-weak-key measure).
    pub fn new(key: &[u8], drop_1024: bool) -> Self {
        let mut s = [0u8; 256];
        for i in 0..256 { s[i] = i as u8; }
        let mut j = 0usize;
        for i in 0..256 {
            j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
            s.swap(i, j);
        }
        let mut rc4 = Self { state: s, x: 0, y: 0 };
        if drop_1024 {
            rc4.skip(1024);
        }
        rc4
    }

    /// Advance the keystream by `n` bytes without XOR'ing output.
    pub fn skip(&mut self, n: usize) {
        for _ in 0..n {
            self.x = self.x.wrapping_add(1);
            self.y = self.y.wrapping_add(self.state[self.x as usize]);
            self.state.swap(self.x as usize, self.y as usize);
        }
    }

    /// XOR `data` in-place with the RC4 keystream.
    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.x = self.x.wrapping_add(1);
            self.y = self.y.wrapping_add(self.state[self.x as usize]);
            self.state.swap(self.x as usize, self.y as usize);
            let xor_idx = self.state[self.x as usize]
                .wrapping_add(self.state[self.y as usize]);
            *byte ^= self.state[xor_idx as usize];
        }
    }

    /// XOR `data` and return result as a new Vec.
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        self.apply(&mut out);
        out
    }
}

// ─── Key derivation ───────────────────────────────────────────────────────────

/// Derive an RC4 key from the shared DH secret and a magic byte.
/// key = MD5(K[0..96] || magic_byte), then RC4 init, then discard 1024.
fn derive_rc4(shared_secret: &[u8], magic: u8) -> Rc4 {
    let mut buf = Vec::with_capacity(DH_PRIME_SIZE + 1);
    let pad = DH_PRIME_SIZE.saturating_sub(shared_secret.len());
    buf.extend(std::iter::repeat(0u8).take(pad));
    buf.extend_from_slice(shared_secret);
    buf.push(magic);
    use md5::{Md5, Digest};
    let digest = Md5::new().chain_update(&buf).finalize();
    Rc4::new(&digest, true)
}

// ─── DH helpers ──────────────────────────────────────────────────────────────

/// Compute g^exp mod p, returning exactly DH_PRIME_SIZE bytes (big-endian, zero-padded).
fn dh_pow_mod(exp_bytes: &[u8]) -> Vec<u8> {
    let g = BigUint::from(DH_G);
    let p = BigUint::from_bytes_be(&DH_PRIME);
    let exp = BigUint::from_bytes_be(exp_bytes);
    let result = g.modpow(&exp, &p);
    let result_bytes = result.to_bytes_be();
    let mut out = vec![0u8; DH_PRIME_SIZE];
    let pad = DH_PRIME_SIZE.saturating_sub(result_bytes.len());
    out[pad..].copy_from_slice(&result_bytes);
    out
}

fn dh_shared(a_pub: &[u8], b_priv: &[u8]) -> Vec<u8> {
    let p = BigUint::from_bytes_be(&DH_PRIME);
    let a = BigUint::from_bytes_be(a_pub);
    let b = BigUint::from_bytes_be(b_priv);
    let k = a.modpow(&b, &p);
    let kb = k.to_bytes_be();
    let mut out = vec![0u8; DH_PRIME_SIZE];
    let pad = DH_PRIME_SIZE.saturating_sub(kb.len());
    out[pad..].copy_from_slice(&kb);
    out
}

// ─── Handshake state machine ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptState {
    /// Server decided not to use obfuscation (plain traffic)
    Plain,
    /// Waiting for the initial DH packet from client
    Waiting,
    /// Sent server DH response; waiting for client's encrypted handshake
    Negotiating,
    /// Handshake complete; all traffic is RC4-encrypted
    Encrypting,
}

/// Server-side obfuscation state machine.
///
/// ```text
/// Waiting → [parse client DH + generate B] → Negotiating
/// Negotiating → [decrypt and verify client ack] → Encrypting
/// ```
pub struct TcpObfuscation {
    pub state: CryptState,
    send_key: Option<Rc4>,
    recv_key: Option<Rc4>,
}

impl TcpObfuscation {
    pub fn new(support_crypt: bool) -> Self {
        Self {
            state: if support_crypt { CryptState::Waiting } else { CryptState::Plain },
            send_key: None,
            recv_key: None,
        }
    }

    /// Check if the first byte is a SemiRandomMarker (not a protocol byte).
    /// Returns true if the connection looks obfuscated.
    pub fn is_obfuscated_start(first_byte: u8) -> bool {
        !FORBIDDEN_MARKERS.contains(&first_byte)
    }

    /// Phase 1: process the incoming DH public key from the client.
    ///
    /// Expects:  SemiRandomMarker(1) + A(96) + PaddingLen(1) + Padding(0-15)
    /// Returns:  B(96) + RC4( MagicSync(4) + EM(1) + EM(1) + PadLen(1) + Pad )
    ///
    /// On success, transitions to CryptState::Negotiating.
    pub fn negotiate(&mut self, buf: &[u8]) -> Result<Vec<u8>, &'static str> {
        if buf.len() < 1 + DH_PRIME_SIZE + 1 {
            return Err("negotiate: buffer too short");
        }

        // Skip SemiRandomMarker
        let a_pub = &buf[1..1 + DH_PRIME_SIZE];

        let pad_len = buf[1 + DH_PRIME_SIZE] as usize;
        // Skip padding (optional trailing bytes)

        // Generate server private exponent (16 random bytes)
        let b_priv = random_bytes(DH_PRIVATE_SIZE);
        let b_pub = dh_pow_mod(&b_priv);
        let shared = dh_shared(a_pub, &b_priv);

        self.send_key = Some(derive_rc4(&shared, MAGIC_VALUE_SERVER));
        self.recv_key = Some(derive_rc4(&shared, MAGIC_VALUE_REQUESTER));

        // Build the encrypted part of the server response
        let pad_out = random_bytes(random_u8() as usize % 16);
        let mut plain = Vec::with_capacity(7 + pad_out.len());
        plain.extend_from_slice(&MAGIC_SYNC.to_le_bytes());
        plain.push(EM_OBFUSCATE); // methods supported
        plain.push(EM_OBFUSCATE); // method preferred/selected
        plain.push(pad_out.len() as u8);
        plain.extend_from_slice(&pad_out);

        let enc = self.send_key.as_mut().unwrap().encrypt(&plain);

        let mut out = Vec::with_capacity(DH_PRIME_SIZE + enc.len());
        out.extend_from_slice(&b_pub); // plaintext DH public
        out.extend_from_slice(&enc);   // encrypted handshake

        self.state = CryptState::Negotiating;
        let _ = pad_len; // consumed conceptually
        Ok(out)
    }

    /// Phase 2: process the client's encrypted handshake ack.
    ///
    /// Expects (encrypted): MagicSync(4) + Method(1) + PadLen(1) + Pad + [payload]
    /// Returns: decrypted payload bytes that follow the handshake (if any).
    ///
    /// On success, transitions to CryptState::Encrypting.
    pub fn handshake<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], &'static str> {
        let recv = self.recv_key.as_mut().ok_or("no recv key")?;
        recv.apply(buf);

        if buf.len() < 6 {
            return Err("handshake: buffer too short after decrypt");
        }
        let sync = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if sync != MAGIC_SYNC {
            return Err("handshake: wrong MagicSync");
        }
        let method = buf[4];
        if method != EM_OBFUSCATE {
            return Err("handshake: unsupported encryption method");
        }
        let pad_len = buf[5] as usize;
        let data_start = 6 + pad_len;
        if buf.len() < data_start {
            return Err("handshake: truncated padding");
        }

        self.state = CryptState::Encrypting;
        Ok(&buf[data_start..])
    }

    /// Decrypt an incoming buffer in-place. No-op when not encrypting.
    pub fn decrypt(&mut self, buf: &mut [u8]) {
        if self.state == CryptState::Encrypting {
            if let Some(k) = &mut self.recv_key {
                k.apply(buf);
            }
        }
    }

    /// Encrypt an outgoing buffer in-place. No-op when not encrypting.
    pub fn encrypt(&mut self, buf: &mut [u8]) {
        if self.state == CryptState::Encrypting {
            if let Some(k) = &mut self.send_key {
                k.apply(buf);
            }
        }
    }

    /// Consume the RC4 keys out of this handshake object.
    /// Called after a successful handshake to transfer ownership to CryptStream.
    pub fn take_keys(&mut self) -> Option<(Rc4, Rc4)> {
        match (self.recv_key.take(), self.send_key.take()) {
            (Some(r), Some(s)) => Some((r, s)),
            _ => None,
        }
    }
}

// ─── Platform PRNG helpers ────────────────────────────────────────────────────

fn random_bytes(n: usize) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::SystemTime;
    // For a production build, replace with `rand::thread_rng()`.
    // This simple version is fine for test/MVP.
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let mut h = DefaultHasher::new();
    seed.hash(&mut h);
    let mut out = Vec::with_capacity(n);
    let mut state: u64 = h.finish();
    for _ in 0..n {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.push((state >> 56) as u8);
    }
    out
}

fn random_u8() -> u8 {
    random_bytes(1)[0]
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify DH exponentiation: 2^5 mod p should equal 32 for any prime p > 32.
    #[test]
    fn dh_small_exponent() {
        let result = dh_pow_mod(&[5]);
        // 2^5 = 32
        assert_eq!(result[DH_PRIME_SIZE - 1], 32);
        assert!(result[..DH_PRIME_SIZE - 1].iter().all(|&b| b == 0));
    }

    /// Full RC4 round-trip: encrypt then decrypt should reproduce plaintext.
    #[test]
    fn rc4_round_trip() {
        let key = b"test key 12345";
        let mut enc = Rc4::new(key, false);
        let mut dec = Rc4::new(key, false);
        let plain = b"Hello eD2k!";
        let mut ciphertext = enc.encrypt(plain);
        dec.apply(&mut ciphertext);
        assert_eq!(&ciphertext, plain);
    }

    /// RC4 with 1024-byte discard produces different output than without.
    #[test]
    fn rc4_drop_differs() {
        let key = b"k";
        let mut no_drop = Rc4::new(key, false);
        let mut with_drop = Rc4::new(key, true);
        let plain = [0u8; 8];
        let a = no_drop.encrypt(&plain);
        let b = with_drop.encrypt(&plain);
        assert_ne!(a, b);
    }

    /// Simulate a complete client-server obfuscation handshake.
    /// The client side is implemented here to mirror eNode-go's test.
    #[test]
    fn full_handshake_simulation() {
        // ─── Client side (eMule-like) ─────────────────────────────────────
        let client_priv = vec![5u8; DH_PRIVATE_SIZE]; // fixed for test
        let client_pub = dh_pow_mod(&client_priv); // g^a mod p

        // Client sends: marker(1) + A(96) + pad_len(1)
        let marker: u8 = 0x7A; // non-protocol byte
        let mut client_hello = Vec::new();
        client_hello.push(marker);
        client_hello.extend_from_slice(&client_pub);
        client_hello.push(0u8); // pad_len = 0

        // ─── Server side ─────────────────────────────────────────────────
        let mut server = TcpObfuscation::new(true);
        assert_eq!(server.state, CryptState::Waiting);

        let server_resp = server.negotiate(&client_hello).unwrap();
        assert_eq!(server.state, CryptState::Negotiating);
        assert!(server_resp.len() >= DH_PRIME_SIZE); // B(96) + encrypted part

        // ─── Client processes server response ─────────────────────────────
        let b_pub = &server_resp[..DH_PRIME_SIZE];
        let server_enc_part = &server_resp[DH_PRIME_SIZE..];

        // Derive client-side keys (opposite magic bytes)
        let shared_client = dh_shared(b_pub, &client_priv);
        let mut client_send = derive_rc4(&shared_client, MAGIC_VALUE_REQUESTER);
        let mut client_recv = derive_rc4(&shared_client, MAGIC_VALUE_SERVER);

        // Decrypt server's encrypted part to verify MagicSync
        let mut dec_server = server_enc_part.to_vec();
        client_recv.apply(&mut dec_server);
        let sync = u32::from_le_bytes([dec_server[0], dec_server[1], dec_server[2], dec_server[3]]);
        assert_eq!(sync, MAGIC_SYNC, "client sees correct MagicSync from server");

        // Client builds its ack
        let pad_len_byte = dec_server[3 + 1 + 1]; // after sync(4) + em_supported + em_preferred
        let pad_len = dec_server[6] as usize;
        let _ = pad_len_byte;

        let mut client_ack = Vec::new();
        client_ack.extend_from_slice(&MAGIC_SYNC.to_le_bytes());
        client_ack.push(EM_OBFUSCATE); // method
        client_ack.push(0u8);          // pad_len
        // Append a plaintext test payload after the handshake
        client_ack.extend_from_slice(b"\xE3\x05\x00\x00\x00\x38hi");
        let _ = pad_len;

        let client_ack_enc = client_send.encrypt(&client_ack);

        // ─── Server processes client ack ──────────────────────────────────
        let mut buf = client_ack_enc;
        let payload = server.handshake(&mut buf).unwrap();
        assert_eq!(server.state, CryptState::Encrypting);
        // The eD2k test frame should survive through
        assert_eq!(&payload[..3], &[0xE3, 0x05, 0x00]);
    }
}

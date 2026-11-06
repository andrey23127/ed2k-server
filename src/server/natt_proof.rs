//! The NAT-T token's proof (issue #40).
//!
//! A `0x9F` that comes with the session's token is believed from any
//! address, which is what a client behind a carrier NAT or a per-flow VPN
//! needs. 0.9.87 took the token itself (`<user hash 16><token 16>`); sent
//! plain, that showed it to anyone on the path, who could then point the
//! session's punches elsewhere for the rest of the login. So the client
//! proves the token instead (it learns it may from `ST_NATT_PROOF` in
//! `OP_SERVERIDENT`), and the token form counts for nothing more than the
//! user hash:
//!
//! ```text
//! <user hash 16><counter u32 LE><mac 16>          36 bytes
//! mac = HMAC-SHA256(key = token, user hash ‖ counter LE)[..16]
//! ```
//!
//! The counter starts at 1 each login and grows with every `0x9F`; one not
//! higher than the last accepted is a replay. The token itself never leaves
//! the TCP session, so the datagram needs no obfuscation. Told apart from the
//! token form by its length.

use sha2::{Digest, Sha256};

/// The value of `ST_NATT_PROOF`.
pub const VERSION: u32 = 1;

/// Payload length of the proof form of `0x9F`.
pub const LEN: usize = 36;

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::new().chain_update(ipad).chain_update(msg).finalize();
    Sha256::new().chain_update(opad).chain_update(inner).finalize().into()
}

/// The mac for `counter` of the session with `user_hash` and `token`.
pub fn mac(token: &[u8; 16], user_hash: &[u8; 16], counter: u32) -> [u8; 16] {
    let mut msg = [0u8; 20];
    msg[..16].copy_from_slice(user_hash);
    msg[16..].copy_from_slice(&counter.to_le_bytes());
    let full = hmac_sha256(token, &msg);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// How a proof-form payload checks out against the session's token and the
/// last counter accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Good, with the counter to remember.
    Ok(u32),
    /// The mac is right but the counter is not higher than the last one.
    Replay,
    /// Wrong mac, or no token for the session.
    Bad,
}

pub fn check(payload: &[u8], token: Option<&[u8; 16]>, last: u32) -> Verdict {
    if payload.len() != LEN {
        return Verdict::Bad;
    }
    let Some(token) = token else {
        return Verdict::Bad;
    };
    let mut uh = [0u8; 16];
    uh.copy_from_slice(&payload[..16]);
    let counter = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let want = mac(token, &uh, counter);
    // Constant time: the difference of every byte, folded.
    let diff = want.iter().zip(&payload[20..36]).fold(0u8, |d, (a, b)| d | (a ^ b));
    if diff != 0 {
        Verdict::Bad
    } else if counter <= last {
        Verdict::Replay
    } else {
        Verdict::Ok(counter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_2() {
        let got = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(got),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// The vector posted in issue #40 for client authors.
    #[test]
    fn the_published_test_vector_holds() {
        let token: [u8; 16] = core::array::from_fn(|i| i as u8);
        let uh: [u8; 16] = core::array::from_fn(|i| 16 + i as u8);
        assert_eq!(hex::encode(mac(&token, &uh, 1)), "57f631c901f652e692307db3ea25be83");
    }

    #[test]
    fn a_proof_is_good_once_and_only_with_the_token() {
        let token = [7u8; 16];
        let uh = [1u8; 16];
        let mut p = uh.to_vec();
        p.extend_from_slice(&5u32.to_le_bytes());
        p.extend_from_slice(&mac(&token, &uh, 5));
        assert_eq!(check(&p, Some(&token), 4), Verdict::Ok(5));
        assert_eq!(check(&p, Some(&token), 5), Verdict::Replay);
        assert_eq!(check(&p, Some(&[8u8; 16]), 0), Verdict::Bad);
        assert_eq!(check(&p, None, 0), Verdict::Bad);
        let mut q = p.clone();
        q[16] = 6; // counter changed, mac not
        assert_eq!(check(&q, Some(&token), 0), Verdict::Bad);
    }
}

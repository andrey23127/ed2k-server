//! Password login for the admin panel.
//!
//! Off unless `admin.password_hash` is set: the panel then works exactly as
//! before, on loopback, reached through an SSH tunnel. With a hash set, every
//! page and API call needs a session, whatever address the request comes from,
//! so a reverse proxy on the same host cannot become a way around it.
//!
//! # Password hash
//!
//! `pbkdf2-sha256$<iterations>$<salt hex>$<hash hex>`, PBKDF2-HMAC-SHA256 with a
//! random 16-byte salt and a 32-byte output. `ed2k-server --hash-password`
//! prints one. Not the unsalted MD5 that the aMule web interface keeps in
//! amule.conf: if config.toml leaks, an MD5 of a typical password falls to a
//! GPU in minutes; a salted hash with 600 000 iterations costs that attacker
//! about a million times as much per guess.
//!
//! # Sessions
//!
//! A login sets a cookie holding 32 random bytes: `HttpOnly` (scripts cannot
//! read it) and `SameSite=Strict` (the browser does not send it with requests
//! that other sites start). Sessions live in memory, so a restart logs
//! everybody out, and expire after [`SESSION_TTL`].
//!
//! # Guessing
//!
//! At most [`MAX_FAILURES`] wrong passwords per address per [`FAILURE_WINDOW`];
//! after that the address gets 429 until the window has passed. Hash checks run
//! one at a time off the async runtime, so a flood of login attempts costs one
//! core at most and never stalls the eD2k side.
//!
//! # What this does not do
//!
//! Without `admin.tls` the panel speaks plain HTTP: on anything but loopback
//! the password (once, at login) and the session cookie (on every request)
//! cross the network unencrypted. The server logs a warning when bound that
//! way. See [`crate::admin_tls`].

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// Iterations for a new hash (OWASP's figure for PBKDF2-HMAC-SHA256).
pub const DEFAULT_ITERATIONS: u32 = 600_000;
/// Fewest iterations a configured hash may use.
pub const MIN_ITERATIONS: u32 = 100_000;
/// How long a session lasts after login.
pub const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
/// Most sessions kept at once; past it the oldest goes.
pub const MAX_SESSIONS: usize = 64;
/// Wrong passwords allowed per address per window.
pub const MAX_FAILURES: u32 = 5;
pub const FAILURE_WINDOW: Duration = Duration::from_secs(10 * 60);
/// Addresses tracked for failures; past it the oldest record goes.
const MAX_TRACKED_ADDRESSES: usize = 4096;
/// Name of the session cookie.
pub const COOKIE: &str = "ed2k_admin";

// ── PBKDF2-HMAC-SHA256 ──────────────────────────────────────────────────────

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
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
    let mut inner = Sha256::new();
    inner.update(ipad);
    for p in parts {
        inner.update(p);
    }
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

/// PBKDF2-HMAC-SHA256, one 32-byte block (all this module needs).
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut u = hmac_sha256(password, &[salt, &1u32.to_be_bytes()]);
    let mut out = u;
    for _ in 1..iterations {
        u = hmac_sha256(password, &[&u]);
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    out
}

/// Bytes from the operating system's random source.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("the operating system has no random source");
    b
}

/// A parsed `pbkdf2-sha256$iter$salt$hash` string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordHash {
    iterations: u32,
    salt: Vec<u8>,
    hash: [u8; 32],
}

impl PasswordHash {
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.trim().split('$').collect();
        let [scheme, iter, salt, hash] = parts.as_slice() else {
            return Err("expected pbkdf2-sha256$<iterations>$<salt hex>$<hash hex>; \
                        generate one with `ed2k-server --hash-password`"
                .into());
        };
        if *scheme != "pbkdf2-sha256" {
            return Err(format!("unknown scheme \"{scheme}\", expected pbkdf2-sha256"));
        }
        let iterations: u32 = iter
            .parse()
            .map_err(|_| format!("iterations \"{iter}\" is not a number"))?;
        if iterations < MIN_ITERATIONS {
            return Err(format!(
                "{iterations} iterations is below the minimum of {MIN_ITERATIONS}"
            ));
        }
        let salt = hex::decode(salt).map_err(|_| "salt is not hex".to_string())?;
        if salt.len() < 8 {
            return Err("salt is shorter than 8 bytes".into());
        }
        let hash: [u8; 32] = hex::decode(hash)
            .ok()
            .and_then(|h| h.try_into().ok())
            .ok_or("hash is not 32 bytes of hex")?;
        Ok(PasswordHash { iterations, salt, hash })
    }

    /// Hash a new password with a fresh salt.
    pub fn new(password: &str, iterations: u32) -> Self {
        let salt = random_bytes::<16>().to_vec();
        let hash = pbkdf2_sha256(password.as_bytes(), &salt, iterations);
        PasswordHash { iterations, salt, hash }
    }

    pub fn verify(&self, password: &str) -> bool {
        let got = pbkdf2_sha256(password.as_bytes(), &self.salt, self.iterations);
        constant_time_eq(&got, &self.hash)
    }
}

impl std::fmt::Display for PasswordHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pbkdf2-sha256${}${}${}",
            self.iterations,
            hex::encode(&self.salt),
            hex::encode(self.hash)
        )
    }
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ── Sessions and failure accounting ─────────────────────────────────────────

/// Outcome of a login attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum Login {
    /// The new session token, to put in the cookie.
    Ok(String),
    Wrong,
    /// Too many wrong passwords from this address (or, for remote addresses,
    /// from everywhere at once); retry after the duration.
    Locked(Duration),
    /// Too many password checks already queued; retry in a moment.
    Busy,
}

/// Wrong passwords from all remote addresses together, per window, before
/// remote logins stop for the rest of the window. Loopback (an SSH tunnel)
/// is never held by it, so the operator always has a way in.
pub const MAX_GLOBAL_FAILURES: u32 = 50;
/// Password checks allowed to wait for the hash at once (loopback exempt).
const MAX_QUEUED_CHECKS: usize = 4;

/// The unit failures are counted per: the address for IPv4, the /64 for IPv6
/// (one host usually holds a whole /64, so per-address counting would let it
/// guess without limit).
fn failure_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) if v6.to_ipv4_mapped().is_none() => {
            let s = v6.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        IpAddr::V6(v6) => IpAddr::V4(v6.to_ipv4_mapped().unwrap()),
        v4 => v4,
    }
}

pub struct Auth {
    hash: PasswordHash,
    sessions: Mutex<HashMap<String, Instant>>,
    failures: Mutex<Failures>,
    /// One hash check at a time: each costs a few hundred milliseconds of CPU.
    check: tokio::sync::Mutex<()>,
    queued: std::sync::atomic::AtomicUsize,
}

#[derive(Default)]
struct Failures {
    per_key: HashMap<IpAddr, (u32, Instant)>,
    /// Remote failures in the current global window.
    global: (u32, Option<Instant>),
}

impl Auth {
    pub fn new(hash: PasswordHash) -> Self {
        Auth {
            hash,
            sessions: Mutex::new(HashMap::new()),
            failures: Mutex::new(Failures::default()),
            check: tokio::sync::Mutex::new(()),
            queued: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Is this cookie value a live session?
    pub fn session_valid(&self, token: &str, now: Instant) -> bool {
        let mut s = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        s.retain(|_, exp| *exp > now);
        // Compare against every live token in constant time, so the lookup
        // does not leak how much of a guessed token was right.
        let mut ok = false;
        for t in s.keys() {
            ok |= constant_time_eq(t.as_bytes(), token.as_bytes());
        }
        ok
    }

    pub fn logout(&self, token: &str) {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(token);
    }

    fn locked_for(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        let f = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let mut wait = None;
        if let Some((n, start)) = f.per_key.get(&failure_key(ip)) {
            let end = *start + FAILURE_WINDOW;
            if *n >= MAX_FAILURES && end > now {
                wait = Some(end - now);
            }
        }
        if !ip.is_loopback() {
            if let (n, Some(start)) = f.global {
                let end = start + FAILURE_WINDOW;
                if n >= MAX_GLOBAL_FAILURES && end > now {
                    wait = Some(wait.map_or(end - now, |w: Duration| w.max(end - now)));
                }
            }
        }
        wait
    }

    fn note_failure(&self, ip: IpAddr, now: Instant) {
        let mut f = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        f.per_key.retain(|_, (_, start)| *start + FAILURE_WINDOW > now);
        let key = failure_key(ip);
        if f.per_key.len() >= MAX_TRACKED_ADDRESSES && !f.per_key.contains_key(&key) {
            if let Some(oldest) = f.per_key.iter().min_by_key(|(_, (_, s))| *s).map(|(k, _)| *k) {
                f.per_key.remove(&oldest);
            }
        }
        f.per_key.entry(key).or_insert((0, now)).0 += 1;
        if !ip.is_loopback() {
            match f.global.1 {
                Some(start) if start + FAILURE_WINDOW > now => f.global.0 += 1,
                _ => f.global = (1, Some(now)),
            }
        }
    }

    fn new_session(&self, now: Instant) -> String {
        let token = hex::encode(random_bytes::<32>());
        let mut s = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        s.retain(|_, exp| *exp > now);
        while s.len() >= MAX_SESSIONS {
            let oldest = s.iter().min_by_key(|(_, e)| **e).map(|(k, _)| k.clone());
            match oldest {
                Some(k) => s.remove(&k),
                None => break,
            };
        }
        s.insert(token.clone(), now + SESSION_TTL);
        token
    }

    /// Check a password from `ip`. The hash runs on a blocking thread, one at
    /// a time; at most a few remote checks wait for it.
    pub async fn login(self: &std::sync::Arc<Self>, ip: IpAddr, password: String) -> Login {
        use std::sync::atomic::Ordering::SeqCst;
        if let Some(wait) = self.locked_for(ip, Instant::now()) {
            return Login::Locked(wait);
        }
        struct Queued<'a>(&'a std::sync::atomic::AtomicUsize);
        impl Drop for Queued<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let before = self.queued.fetch_add(1, SeqCst);
        let _q = Queued(&self.queued);
        if before >= MAX_QUEUED_CHECKS && !ip.is_loopback() {
            return Login::Busy;
        }
        let _one = self.check.lock().await;
        // Re-check: other attempts may have locked this address meanwhile.
        if let Some(wait) = self.locked_for(ip, Instant::now()) {
            return Login::Locked(wait);
        }
        let me = std::sync::Arc::clone(self);
        let ok = tokio::task::spawn_blocking(move || me.hash.verify(&password))
            .await
            .unwrap_or(false);
        let now = Instant::now();
        if ok {
            self.failures
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .per_key
                .remove(&failure_key(ip));
            Login::Ok(self.new_session(now))
        } else {
            self.note_failure(ip, now);
            Login::Wrong
        }
    }
}

/// The cookie's name. Over HTTPS it carries the `__Host-` prefix, which makes
/// the browser accept it only when `Secure`, for this host only and for `/`:
/// nothing on another subdomain or path can set or shadow it.
pub fn cookie_name(secure: bool) -> &'static str {
    if secure {
        "__Host-ed2k_admin"
    } else {
        COOKIE
    }
}

/// The session token from a `Cookie` header, if there is one.
pub fn cookie_token<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|c| {
        let (k, v) = c.trim().split_once('=')?;
        (k == name).then_some(v)
    })
}

/// The `password` field of an `application/x-www-form-urlencoded` body.
pub fn form_password(body: &str) -> Option<String> {
    body.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == "password").then(|| percent_decode(v))
    })
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let hi = (b[i + 1] as char).to_digit(16);
                let lo = (b[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_matches_rfc7914_vector() {
        // RFC 7914 §11: P="passwd", S="salt", c=1 (first 32 bytes of dkLen=64).
        let got = pbkdf2_sha256(b"passwd", b"salt", 1);
        assert_eq!(
            hex::encode(got),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
    }

    #[test]
    fn pbkdf2_matches_a_multi_iteration_vector() {
        // Python: hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 4096).hex()
        let got = pbkdf2_sha256(b"password", b"salt", 4096);
        assert_eq!(
            hex::encode(got),
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
        );
    }

    #[test]
    fn hash_round_trips_and_verifies() {
        let h = PasswordHash::new("correct horse", MIN_ITERATIONS);
        let text = h.to_string();
        let back = PasswordHash::parse(&text).unwrap();
        assert_eq!(back, h);
        assert!(back.verify("correct horse"));
        assert!(!back.verify("correct horse "));
        // A fresh salt every time.
        assert_ne!(PasswordHash::new("x", MIN_ITERATIONS).to_string(),
                   PasswordHash::new("x", MIN_ITERATIONS).to_string());
    }

    #[test]
    fn bad_hash_strings_are_refused() {
        let good = PasswordHash::new("x", MIN_ITERATIONS).to_string();
        assert!(PasswordHash::parse(&good).is_ok());
        for bad in [
            "",
            "plaintext",
            "md5$abc",
            "pbkdf2-sha256$1000$00112233445566778899aabbccddeeff$00",
            &good.replacen("pbkdf2-sha256", "pbkdf2-sha1", 1),
            &good.replacen(&format!("${MIN_ITERATIONS}$"), "$99999$", 1),
        ] {
            assert!(PasswordHash::parse(bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn wrong_passwords_lock_the_address_not_others() {
        let auth = std::sync::Arc::new(Auth::new(PasswordHash::new("pw", MIN_ITERATIONS)));
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        for _ in 0..MAX_FAILURES {
            assert_eq!(auth.login(a, "nope".into()).await, Login::Wrong);
        }
        assert!(matches!(auth.login(a, "pw".into()).await, Login::Locked(_)), "even the right one");
        let Login::Ok(tok) = auth.login(b, "pw".into()).await else { panic!("b must log in") };
        assert!(auth.session_valid(&tok, Instant::now()));
        assert!(!auth.session_valid("deadbeef", Instant::now()));
        assert!(!auth.session_valid(&tok, Instant::now() + SESSION_TTL + Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn ipv6_failures_count_per_64_and_loopback_escapes_the_global_lock() {
        let auth = std::sync::Arc::new(Auth::new(PasswordHash::new("pw", MIN_ITERATIONS)));
        // Five addresses in one /64 share a counter.
        for i in 1..=MAX_FAILURES {
            let ip: IpAddr = format!("2001:db8:1:2::{i}").parse().unwrap();
            assert_eq!(auth.login(ip, "nope".into()).await, Login::Wrong);
        }
        let same64: IpAddr = "2001:db8:1:2::ffff".parse().unwrap();
        assert!(matches!(auth.login(same64, "pw".into()).await, Login::Locked(_)));
        let other64: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert!(matches!(auth.login(other64, "pw".into()).await, Login::Ok(_)));

        // Many remote addresses together trip the global lock...
        let auth = std::sync::Arc::new(Auth::new(PasswordHash::new("pw", MIN_ITERATIONS)));
        {
            let mut f = auth.failures.lock().unwrap();
            f.global = (MAX_GLOBAL_FAILURES, Some(Instant::now()));
        }
        let remote: IpAddr = "198.51.100.9".parse().unwrap();
        assert!(matches!(auth.login(remote, "pw".into()).await, Login::Locked(_)));
        // ...but never the SSH tunnel.
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(matches!(auth.login(lo, "pw".into()).await, Login::Ok(_)));
    }

    #[test]
    fn cookie_and_form_parsing() {
        assert_eq!(cookie_token("a=1; ed2k_admin=abc; b=2", COOKIE), Some("abc"));
        assert_eq!(cookie_token("xed2k_admin=abc", COOKIE), None);
        assert_eq!(
            cookie_token("ed2k_admin=x; __Host-ed2k_admin=y", cookie_name(true)),
            Some("y")
        );
        assert_eq!(form_password("user=x&password=p%40ss+w%2Bd"), Some("p@ss w+d".into()));
        assert_eq!(form_password("password=%zz%"), Some("%zz%".into()));
        assert_eq!(form_password("other=1"), None);
    }
}

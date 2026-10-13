//! HTTPS for the admin panel (`admin.tls`).
//!
//! Three modes:
//!
//! * `"off"` (default): plain HTTP, as before.
//! * `"self-signed"`: the server makes its own certificate on first start and
//!   keeps it in `admin.tls_cert` / `admin.tls_key` (default: next to the
//!   config file). The browser warns once; compare the SHA-256 fingerprint it
//!   shows with the one this server logs at startup before accepting.
//!   With `admin.tls_ca_cert` / `admin.tls_ca_key` set, the certificate is
//!   signed by that CA instead (`ed2k-server --make-admin-ca DIR` makes one).
//!   Import the CA certificate on your PC once and every server signed by it
//!   opens without a warning.
//! * `"files"`: certificate and key from `admin.tls_cert` / `admin.tls_key`,
//!   e.g. from Let's Encrypt. Re-read when either file changes.
//!
//! A server-made certificate lasts [`LEAF_DAYS`] days and is replaced
//! [`RENEW_DAYS`] days before it ends, at startup or by the periodic check,
//! without a restart. A self-signed certificate changes its fingerprint when it
//! is replaced (the browser warns once more); one signed by the CA does not
//! need a new exception. It is also replaced when the addresses it must cover
//! change (`server.this_ip`, `admin.bind`, `admin.tls_names`) or when the CA
//! changes.
//!
//! No certificate parser is needed to decide any of that: when the server
//! makes a certificate it writes what it put in next to it (`<cert>.json`).

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use arc_swap::ArcSwap;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints,
    SanType, SerialNumber, PKCS_ECDSA_P256_SHA256,
};
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use tokio_rustls::rustls;

use crate::config::AdminConfig;

/// Lifetime of a certificate the server makes, counted from now; with the day
/// of backdating it spans 397 days, inside the limit browsers apply to
/// publicly trusted certificates, so one signed by an imported CA is accepted
/// everywhere.
pub const LEAF_DAYS: i64 = 396;
/// Replace a server-made certificate this long before it ends.
pub const RENEW_DAYS: i64 = 30;
/// Lifetime of a CA made by `--make-admin-ca`.
pub const CA_DAYS: i64 = 3650;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Off,
    SelfSigned,
    Files,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim() {
            "" | "off" => Ok(Mode::Off),
            "self-signed" => Ok(Mode::SelfSigned),
            "files" => Ok(Mode::Files),
            other => Err(format!(
                "admin.tls = \"{other}\": expected \"off\", \"self-signed\" or \"files\""
            )),
        }
    }
}

/// `AA:BB:...` SHA-256 of a DER certificate, as browsers show it.
pub fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random_serial() -> SerialNumber {
    let mut b = crate::admin_auth::random_bytes::<16>();
    b[0] &= 0x7f; // positive
    b[0] |= 0x01; // and never shorter than 16 bytes
    SerialNumber::from_slice(&b)
}

fn validity(params: &mut CertificateParams, days: i64) {
    let now = time::OffsetDateTime::now_utc();
    // A day of slack for clocks that run behind.
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(days);
}

/// Write `data` to `path` through a new temporary file with `mode`.
///
/// The temporary file is always freshly created (`O_EXCL`, random name), so a
/// file left over from a crash, or a planted symlink, can never receive the
/// private key with its own looser permissions.
fn write_atomic(path: &Path, data: &str, mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".tmp-{}", hex::encode(crate::admin_auth::random_bytes::<6>())));
    let tmp = PathBuf::from(name);
    let res = (|| -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(data.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// A file readable only by the owner (private keys).
fn write_private(path: &Path, data: &str) -> Result<()> {
    write_atomic(path, data, 0o600)
}

fn write_public(path: &Path, data: &str) -> Result<()> {
    write_atomic(path, data, 0o644)
}

// ── The CA ───────────────────────────────────────────────────────────────────

/// The CA's name, derived from its public key. Reproducible from the key alone,
/// which is what lets the server sign with a CA it only has the key file of:
/// the issuer name and key identifier it writes are exactly those of the CA
/// certificate the operator imported.
fn ca_name(key: &KeyPair) -> String {
    let id = hex::encode(&Sha256::digest(key.public_key_raw())[..4]);
    format!("ed2k-server admin CA {id}")
}

fn ca_params(key: KeyPair) -> CertificateParams {
    let mut p = CertificateParams::default();
    p.alg = &PKCS_ECDSA_P256_SHA256;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, ca_name(&key));
    dn.push(DnType::OrganizationName, "ed2k-server");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.key_pair = Some(key);
    p
}

/// What a CA may sign for, besides loopback: the operator's server addresses,
/// networks (CIDR) and DNS names.
fn ca_subtrees(names: &[String]) -> Result<Vec<GeneralSubtree>> {
    let mut v = vec![
        GeneralSubtree::IpAddress(CidrSubnet::from_str("127.0.0.0/8").unwrap()),
        GeneralSubtree::IpAddress(CidrSubnet::from_str("::1/128").unwrap()),
        GeneralSubtree::DnsName("localhost".into()),
    ];
    for n in names {
        let n = n.trim();
        if n.is_empty() {
            continue;
        }
        if let Ok(ip) = n.parse::<IpAddr>() {
            let bits = if ip.is_ipv4() { 32 } else { 128 };
            v.push(GeneralSubtree::IpAddress(CidrSubnet::from_addr_prefix(ip, bits)));
        } else if n.contains('/') {
            let c = CidrSubnet::from_str(n)
                .map_err(|_| anyhow::anyhow!("\"{n}\" is not a valid network (CIDR)"))?;
            v.push(GeneralSubtree::IpAddress(c));
        } else {
            v.push(GeneralSubtree::DnsName(n.to_ascii_lowercase()));
        }
    }
    Ok(v)
}

/// Does `name` fall inside what the CA was limited to? Used to refuse at
/// startup, with an explanation, a certificate a browser would reject.
fn permitted(ca_names: &[String], name: &str) -> bool {
    let builtin = ["127.0.0.0/8", "::1/128", "localhost"];
    let ip = name.parse::<IpAddr>().ok();
    builtin.iter().map(|s| s.to_string()).chain(ca_names.iter().cloned()).any(|c| {
        let c = c.trim().to_ascii_lowercase();
        match (ip, c.parse::<IpAddr>().ok(), c.split_once('/')) {
            (Some(a), Some(b), _) => a == b,
            (Some(a), None, Some((net, bits))) => {
                let (Ok(net), Ok(bits)) = (net.parse::<IpAddr>(), bits.parse::<u32>()) else {
                    return false;
                };
                match (a, net) {
                    (IpAddr::V4(a), IpAddr::V4(n)) if bits <= 32 => {
                        let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                        u32::from(a) & mask == u32::from(n) & mask
                    }
                    (IpAddr::V6(a), IpAddr::V6(n)) if bits <= 128 => {
                        let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                        u128::from(a) & mask == u128::from(n) & mask
                    }
                    _ => false,
                }
            }
            (None, None, None) => name == c || name.ends_with(&format!(".{c}")),
            _ => false,
        }
    })
}

fn ca_sidecar(cert: &Path) -> PathBuf {
    sidecar(cert)
}

/// `ed2k-server --make-admin-ca DIR --admin-ca-names LIST`: a new CA in
/// `DIR/admin-ca-cert.pem` and `DIR/admin-ca-key.pem`. Refuses to overwrite
/// either.
///
/// The CA is name-constrained to `names` (server addresses, networks, DNS
/// names) and loopback. A CA imported as a trusted root is otherwise trusted
/// for every site, and its key sits on the servers: whoever took one over
/// could then impersonate any HTTPS site to the operator's PC. Constrained,
/// it can only vouch for the operator's own servers.
pub fn make_ca(dir: &Path, names: &[String]) -> Result<(PathBuf, PathBuf, String)> {
    let names: Vec<String> = names
        .iter()
        .map(|n| n.trim().to_ascii_lowercase())
        .filter(|n| !n.is_empty())
        .collect();
    if names.is_empty() {
        bail!(
            "--admin-ca-names is required: the server addresses, networks (CIDR) or DNS \
             names this CA may sign for, comma-separated (loopback is always included)"
        );
    }
    let subtrees = ca_subtrees(&names)?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let cert_path = dir.join("admin-ca-cert.pem");
    let key_path = dir.join("admin-ca-key.pem");
    for p in [&cert_path, &key_path] {
        if p.exists() {
            bail!("{} already exists; not overwriting a CA", p.display());
        }
    }
    let key = KeyPair::generate(&PKCS_ECDSA_P256_SHA256)?;
    let mut p = ca_params(key);
    p.serial_number = Some(random_serial());
    p.name_constraints = Some(NameConstraints {
        permitted_subtrees: subtrees,
        excluded_subtrees: Vec::new(),
    });
    validity(&mut p, CA_DAYS);
    let ca = Certificate::from_params(p)?;
    // Serialize once: ECDSA signatures are randomised, so every call returns
    // different bytes, and the fingerprint must be that of the file.
    let der = ca.serialize_der()?;
    write_private(&key_path, &ca.serialize_private_key_pem())?;
    write_public(&cert_path, &pem_encode("CERTIFICATE", &der))?;
    write_public(&ca_sidecar(&cert_path), &serde_json::to_string_pretty(&names)?)?;
    Ok((cert_path, key_path, fingerprint(&der)))
}

/// A signer rebuilt from the CA key, checked against the CA certificate.
struct Ca {
    signer: Certificate,
    cert_der: Vec<u8>,
    fingerprint: String,
    /// What the CA is limited to (from its sidecar), if known.
    names: Option<Vec<String>>,
}

fn load_ca(cert_path: &Path, key_path: &Path) -> Result<Ca> {
    let key_pem = std::fs::read_to_string(key_path)
        .with_context(|| format!("reading {}", key_path.display()))?;
    let key = KeyPair::from_pem(&key_pem).context("admin.tls_ca_key is not a usable key")?;
    let cert_der = CertificateDer::from_pem_file(cert_path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e:?}", cert_path.display()))?
        .to_vec();
    // The certificate must be the one made for this key: its name is derived
    // from the key, and its public key appears in it verbatim.
    let name = ca_name(&key);
    let contains = |needle: &[u8]| cert_der.windows(needle.len()).any(|w| w == needle);
    if !contains(name.as_bytes()) || !contains(key.public_key_raw()) {
        bail!(
            "{} and {} are not a pair made by --make-admin-ca",
            cert_path.display(),
            key_path.display()
        );
    }
    let fp = fingerprint(&cert_der);
    let signer = Certificate::from_params(ca_params(key))?;
    let names = std::fs::read_to_string(ca_sidecar(cert_path))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    Ok(Ca { signer, cert_der, fingerprint: fp, names })
}

// ── The server certificate ──────────────────────────────────────────────────

/// What a server-made certificate was made with, kept next to it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Made {
    names: Vec<String>,
    /// "self" or the CA certificate's fingerprint.
    issuer: String,
    not_after: i64,
}

fn sidecar(cert: &Path) -> PathBuf {
    let mut s = cert.as_os_str().to_owned();
    s.push(".json");
    PathBuf::from(s)
}

/// The names the certificate must cover: the bind address (or, on a wildcard
/// bind, the server's public address), loopback for the SSH tunnel, and
/// `admin.tls_names`.
pub fn wanted_names(admin: &AdminConfig, public_ip: &str) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    let bind = admin.bind_addr();
    if !bind.is_unspecified() && !bind.is_loopback() {
        v.push(bind.to_string());
    }
    if bind.is_unspecified() {
        if let Ok(ip) = public_ip.trim().parse::<IpAddr>() {
            v.push(ip.to_string());
        }
    }
    v.push("127.0.0.1".into());
    v.push("::1".into());
    v.push("localhost".into());
    for n in &admin.tls_names {
        let n = n.trim().to_ascii_lowercase();
        if !n.is_empty() {
            v.push(n);
        }
    }
    let mut seen = std::collections::HashSet::new();
    v.retain(|n| seen.insert(n.clone()));
    v
}

fn make_leaf(names: &[String], ca: Option<&Ca>) -> Result<(String, String, Made)> {
    let mut p = CertificateParams::default();
    p.alg = &PKCS_ECDSA_P256_SHA256;
    let mut dn = DistinguishedName::new();
    // A fresh name each time: Firefox refuses a second certificate with the
    // issuer and serial of one it has already seen, and a self-signed
    // certificate is its own issuer.
    let id = hex::encode(crate::admin_auth::random_bytes::<4>());
    dn.push(DnType::CommonName, format!("ed2k-server admin {id}"));
    dn.push(DnType::OrganizationName, "ed2k-server");
    p.distinguished_name = dn;
    p.serial_number = Some(random_serial());
    p.subject_alt_names = names
        .iter()
        .map(|n| match n.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(n.clone()),
        })
        .collect();
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.use_authority_key_identifier_extension = ca.is_some();
    p.key_pair = Some(KeyPair::generate(&PKCS_ECDSA_P256_SHA256)?);
    validity(&mut p, LEAF_DAYS);
    let not_after = p.not_after.unix_timestamp();
    let cert = Certificate::from_params(p)?;
    let pem = match ca {
        Some(ca) => cert.serialize_pem_with_signer(&ca.signer)?,
        None => cert.serialize_pem()?,
    };
    let made = Made {
        names: names.to_vec(),
        issuer: ca.map(|c| c.fingerprint.clone()).unwrap_or_else(|| "self".into()),
        not_after,
    };
    Ok((pem, cert.serialize_private_key_pem(), made))
}

/// Paths in effect: the configured ones, or `admin-cert.pem` / `admin-key.pem`
/// next to the config file.
pub fn cert_paths(admin: &AdminConfig, config_path: &Path) -> (PathBuf, PathBuf) {
    let dir = config_path.parent().unwrap_or(Path::new("."));
    let pick = |s: &str, default: &str| {
        if s.trim().is_empty() {
            dir.join(default)
        } else {
            PathBuf::from(s.trim())
        }
    };
    (pick(&admin.tls_cert, "admin-cert.pem"), pick(&admin.tls_key, "admin-key.pem"))
}

/// Make or keep the server's certificate. Returns whether a new one was made.
fn ensure_server_made(
    cert: &Path,
    key: &Path,
    names: &[String],
    ca: Option<&Ca>,
) -> Result<bool> {
    if let Some(allowed) = ca.and_then(|c| c.names.as_ref()) {
        let outside: Vec<&String> = names.iter().filter(|n| !permitted(allowed, n)).collect();
        if !outside.is_empty() {
            bail!(
                "the admin CA may sign only for {allowed:?} (and loopback), but this \
                 server's certificate must also cover {outside:?}. Make a CA that \
                 includes them (--admin-ca-names), or change admin.bind / tls_names."
            );
        }
    }
    let issuer = ca.map(|c| c.fingerprint.clone()).unwrap_or_else(|| "self".into());
    let current: Option<Made> = std::fs::read_to_string(sidecar(cert))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    let fresh = current.as_ref().is_some_and(|m| {
        m.names == names
            && m.issuer == issuer
            && m.not_after - now_unix() > RENEW_DAYS * 86_400
            && cert.exists()
            && key.exists()
    });
    if fresh {
        return Ok(false);
    }
    let (cert_pem, key_pem, made) = make_leaf(names, ca)?;
    if let Some(dir) = cert.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    // Key first: a crash between the two leaves a stale certificate with a new
    // key, which fails loudly at load and is remade on the next start, rather
    // than the reverse.
    write_private(key, &key_pem)?;
    let mut chain = cert_pem;
    if let Some(ca) = ca {
        // Send the CA along: harmless to a client that already trusts it, and
        // lets one that does not show the whole chain.
        chain.push_str(&pem_encode("CERTIFICATE", &ca.cert_der));
    }
    write_public(cert, &chain)?;
    write_public(&sidecar(cert), &serde_json::to_string_pretty(&made)?)?;
    Ok(true)
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let p = pem::Pem::new(label, der.to_vec());
    pem::encode(&p)
}

// ── Serving ──────────────────────────────────────────────────────────────────

/// The certificate rustls hands out; swapped in place on renewal.
#[derive(Debug)]
struct Resolver(ArcSwap<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for Resolver {
    fn resolve(
        &self,
        _hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.load_full())
    }
}

fn load_certified(cert: &Path, key: &Path) -> Result<(rustls::sign::CertifiedKey, String)> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| anyhow::anyhow!("reading {}: {e:?}", cert.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("reading {}: {e:?}", cert.display()))?;
    let Some(leaf) = chain.first() else {
        bail!("{} holds no certificate", cert.display());
    };
    let fp = fingerprint(leaf);
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| anyhow::anyhow!("reading {}: {e:?}", key.display()))?;
    let signing = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| anyhow::anyhow!("unsupported private key: {e}"))?;
    Ok((rustls::sign::CertifiedKey::new(chain, signing), fp))
}

/// Everything the HTTPS listener needs, plus what the periodic check uses.
pub struct AdminTls {
    pub acceptor: tokio_rustls::TlsAcceptor,
    resolver: Arc<Resolver>,
    fingerprint: ArcSwap<String>,
    mode: Mode,
    cert: PathBuf,
    key: PathBuf,
    names: Vec<String>,
    ca_paths: Option<(PathBuf, PathBuf)>,
    /// mtimes of the files last loaded (files mode).
    stamp: std::sync::Mutex<(Option<SystemTime>, Option<SystemTime>)>,
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

impl AdminTls {
    /// Set up HTTPS, or `None` for `admin.tls = "off"`.
    pub fn setup(
        admin: &AdminConfig,
        config_path: &Path,
        public_ip: &str,
    ) -> Result<Option<Arc<AdminTls>>> {
        let mode = Mode::parse(&admin.tls).map_err(anyhow::Error::msg)?;
        if mode == Mode::Off {
            return Ok(None);
        }
        let (cert, key) = cert_paths(admin, config_path);
        let names = wanted_names(admin, public_ip);
        let ca_paths = (!admin.tls_ca_cert.trim().is_empty()).then(|| {
            (
                PathBuf::from(admin.tls_ca_cert.trim()),
                PathBuf::from(admin.tls_ca_key.trim()),
            )
        });
        if mode == Mode::SelfSigned {
            let ca = match &ca_paths {
                Some((c, k)) => Some(load_ca(c, k)?),
                None => None,
            };
            ensure_server_made(&cert, &key, &names, ca.as_ref())?;
        }
        let (ck, fp) = load_certified(&cert, &key)?;
        let resolver = Arc::new(Resolver(ArcSwap::from_pointee(ck)));
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        Ok(Some(Arc::new(AdminTls {
            acceptor,
            resolver,
            fingerprint: ArcSwap::from_pointee(fp),
            mode,
            stamp: std::sync::Mutex::new((mtime(&cert), mtime(&key))),
            cert,
            key,
            names,
            ca_paths,
        })))
    }

    pub fn fingerprint(&self) -> String {
        self.fingerprint.load().as_ref().clone()
    }

    pub fn cert_path(&self) -> &Path {
        &self.cert
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Renew a server-made certificate when due, or pick up changed files.
    /// Returns the new fingerprint when the certificate changed.
    pub fn refresh(&self) -> Result<Option<String>> {
        let changed = match self.mode {
            Mode::Off => false,
            Mode::SelfSigned => {
                let ca = match &self.ca_paths {
                    Some((c, k)) => Some(load_ca(c, k)?),
                    None => None,
                };
                ensure_server_made(&self.cert, &self.key, &self.names, ca.as_ref())?
            }
            Mode::Files => {
                let now = (mtime(&self.cert), mtime(&self.key));
                *self.stamp.lock().unwrap_or_else(|e| e.into_inner()) != now
            }
        };
        if !changed {
            return Ok(None);
        }
        // Remember the files as loaded only once they load: a half-written
        // pair (certbot mid-renewal) is retried on the next check instead of
        // being skipped until the files change again.
        let stamp = (mtime(&self.cert), mtime(&self.key));
        let (ck, fp) = load_certified(&self.cert, &self.key)?;
        *self.stamp.lock().unwrap_or_else(|e| e.into_inner()) = stamp;
        self.resolver.0.store(Arc::new(ck));
        self.fingerprint.store(Arc::new(fp.clone()));
        Ok(Some(fp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin(tls: &str) -> AdminConfig {
        AdminConfig {
            enabled: true,
            tls: tls.into(),
            ..AdminConfig::default()
        }
    }

    #[test]
    fn modes_parse() {
        assert_eq!(Mode::parse(""), Ok(Mode::Off));
        assert_eq!(Mode::parse("off"), Ok(Mode::Off));
        assert_eq!(Mode::parse("self-signed"), Ok(Mode::SelfSigned));
        assert_eq!(Mode::parse("files"), Ok(Mode::Files));
        assert!(Mode::parse("on").is_err());
    }

    #[test]
    fn names_cover_bind_or_public_address_and_loopback() {
        let mut a = admin("self-signed");
        a.bind = "0.0.0.0".into();
        a.tls_names = vec!["Admin.Example.org".into(), "10.8.0.1".into()];
        let n = wanted_names(&a, "203.0.113.7");
        assert_eq!(
            n,
            ["203.0.113.7", "127.0.0.1", "::1", "localhost", "admin.example.org", "10.8.0.1"]
        );
        a.bind = "10.8.0.1".into();
        let n = wanted_names(&a, "203.0.113.7");
        assert_eq!(n, ["10.8.0.1", "127.0.0.1", "::1", "localhost", "admin.example.org"]);
    }

    #[test]
    fn self_signed_is_made_once_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        let a = admin("self-signed");
        let t = AdminTls::setup(&a, &cfg, "203.0.113.7").unwrap().unwrap();
        let fp = t.fingerprint();
        assert_eq!(fp.len(), 32 * 3 - 1);
        let key = dir.path().join("admin-key.pem");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
        // A second start keeps it; a refresh with nothing due changes nothing.
        let t2 = AdminTls::setup(&a, &cfg, "203.0.113.7").unwrap().unwrap();
        assert_eq!(t2.fingerprint(), fp);
        assert_eq!(t2.refresh().unwrap(), None);
        // A new address to cover makes a new one.
        let mut b = a.clone();
        b.tls_names = vec!["10.8.0.1".into()];
        let t3 = AdminTls::setup(&b, &cfg, "203.0.113.7").unwrap().unwrap();
        assert_ne!(t3.fingerprint(), fp);
    }

    #[test]
    fn renewal_is_due_shortly_before_the_end() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        let a = admin("self-signed");
        let t = AdminTls::setup(&a, &cfg, "").unwrap().unwrap();
        let fp = t.fingerprint();
        // Pretend it ends in 29 days.
        let side = sidecar(t.cert_path());
        let mut m: Made = serde_json::from_str(&std::fs::read_to_string(&side).unwrap()).unwrap();
        m.not_after = now_unix() + 29 * 86_400;
        std::fs::write(&side, serde_json::to_string(&m).unwrap()).unwrap();
        let new = t.refresh().unwrap().expect("renewed");
        assert_ne!(new, fp);
        assert_eq!(t.fingerprint(), new);
    }

    #[test]
    fn ca_signs_and_mismatched_pairs_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (ca_cert, ca_key, ca_fp) = make_ca(&dir.path().join("ca"), &["203.0.113.0/24".to_string()]).unwrap();
        assert!(make_ca(&dir.path().join("ca"), &["203.0.113.0/24".to_string()]).is_err(), "never overwrites");
        let cfg = dir.path().join("config.toml");
        let mut a = admin("self-signed");
        a.bind = "0.0.0.0".into(); // so the public address is covered
        a.tls_ca_cert = ca_cert.display().to_string();
        a.tls_ca_key = ca_key.display().to_string();
        let t = AdminTls::setup(&a, &cfg, "203.0.113.7").unwrap().unwrap();
        let pem = std::fs::read_to_string(t.cert_path()).unwrap();
        assert_eq!(pem.matches("BEGIN CERTIFICATE").count(), 2, "leaf + CA");
        let side: Made =
            serde_json::from_str(&std::fs::read_to_string(sidecar(t.cert_path())).unwrap())
                .unwrap();
        assert_eq!(side.issuer, ca_fp);

        // The leaf verifies against the CA as a browser would.
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(t.cert_path())
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from_pem_file(&ca_cert).unwrap()).unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let name = rustls_pki_types::ServerName::try_from("203.0.113.7").unwrap();
        use rustls::client::danger::ServerCertVerifier;
        verifier
            .verify_server_cert(&chain[0], &[], &name, &[], rustls_pki_types::UnixTime::now())
            .expect("leaf signed by the CA, covering the address");
        let other = rustls_pki_types::ServerName::try_from("198.51.100.1").unwrap();
        assert!(verifier
            .verify_server_cert(&chain[0], &[], &other, &[], rustls_pki_types::UnixTime::now())
            .is_err());

        // A CA limited to other addresses refuses to sign for this one.
        let (c3, k3, _) =
            make_ca(&dir.path().join("ca3"), &["198.51.100.1".to_string()]).unwrap();
        let mut narrow = a.clone();
        narrow.tls_ca_cert = c3.display().to_string();
        narrow.tls_ca_key = k3.display().to_string();
        narrow.tls_cert = dir.path().join("n-cert.pem").display().to_string();
        narrow.tls_key = dir.path().join("n-key.pem").display().to_string();
        let err = AdminTls::setup(&narrow, &cfg, "203.0.113.7").err().expect("refused");
        assert!(err.to_string().contains("203.0.113.7"), "{err}");
        assert!(make_ca(&dir.path().join("ca4"), &[]).is_err(), "names required");

        // A CA certificate paired with another CA's key is refused.
        let (_, other_key, _) = make_ca(&dir.path().join("ca2"), &["203.0.113.7".to_string()]).unwrap();
        a.tls_ca_key = other_key.display().to_string();
        assert!(AdminTls::setup(&a, &cfg, "203.0.113.7").is_err());
    }

    #[test]
    fn permitted_names() {
        let ca = vec!["203.0.113.0/24".to_string(), "example.org".to_string(),
                      "2001:db8::/32".to_string(), "198.51.100.1".to_string()];
        for ok in ["203.0.113.7", "127.0.0.1", "::1", "localhost", "admin.example.org",
                   "example.org", "2001:db8:1::5", "198.51.100.1"] {
            assert!(permitted(&ca, ok), "{ok}");
        }
        for no in ["203.0.114.1", "198.51.100.2", "badexample.org", "2001:db9::1", "10.0.0.1"] {
            assert!(!permitted(&ca, no), "{no}");
        }
    }

    #[test]
    fn files_mode_reloads_changed_files() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        // Make a pair with self-signed mode, then serve it as "files".
        let made = AdminTls::setup(&admin("self-signed"), &cfg, "").unwrap().unwrap();
        let mut f = admin("files");
        f.tls_cert = made.cert_path().display().to_string();
        f.tls_key = dir.path().join("admin-key.pem").display().to_string();
        let t = AdminTls::setup(&f, &cfg, "").unwrap().unwrap();
        assert_eq!(t.fingerprint(), made.fingerprint());
        assert_eq!(t.refresh().unwrap(), None);
        // Replace the files (as certbot would) and refresh.
        std::fs::remove_file(sidecar(made.cert_path())).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let fresh = AdminTls::setup(&admin("self-signed"), &cfg, "").unwrap().unwrap();
        assert_ne!(fresh.fingerprint(), made.fingerprint());
        assert_eq!(t.refresh().unwrap(), Some(fresh.fingerprint()));
    }
}

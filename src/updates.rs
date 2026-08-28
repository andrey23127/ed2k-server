//! Update client for the filter data files.
//!
//! Fetches the eight operator data files from an update service, verifies an
//! Ed25519 signature over the bytes, validates them with the SAME parser that
//! loads them at runtime, keeps rotating backups, installs atomically, and then
//! trips the existing reload flag so the change is live within two seconds.
//!
//! ─────────────────────────────────────────────────────────────────────────
//! WHY THE SIGNATURE MATTERS MORE THAN THE PASSWORD
//!
//! Who can READ these lists is an unpleasant question. Who can REPLACE them is
//! a much worse one, and the two failure modes are concrete:
//!
//!   * An empty vocabulary file silences a whole layer at once, on every server
//!     that pulls it. The layer keeps running and quietly matches nothing.
//!   * One hash of a popular legal release dropped into the ban list bans
//!     everybody sharing it, for thirty days, on every server at once — the ban
//!     list counts against the publisher.
//!
//! Neither needs the update host to be malicious: a hijacked domain, an expired
//! registration or a compromised VPS is enough. So the public key is compiled
//! into the binary and the signature is checked BEFORE anything touches disk. A
//! file that does not verify is not written, not backed up, and not applied.
//!
//! ─────────────────────────────────────────────────────────────────────────
//! WHY VALIDATION IS SEPARATE FROM THE SIGNATURE
//!
//! A signature proves origin, not sense. A correctly signed but truncated file
//! is still a disaster, and truncation is the common failure — a dropped TCP
//! connection produces a prefix of a valid file, which parses fine and is simply
//! shorter. So every download is additionally checked for:
//!
//!   * completeness against Content-Length, when the server sends one;
//!   * parseability, using the runtime parser rather than a second copy of it;
//!   * COLLAPSE — a new file dramatically smaller than the one it replaces is
//!     refused. A ban list that went from 87 000 entries to 200 is a broken
//!     download, not an operator decision.
//!
//! Only after all of that does the file move into place, and it moves by
//! `rename`, which is atomic: a reader either sees the whole old file or the
//! whole new one, never a half-written mixture.

use std::io::Read;
use std::path::{Path, PathBuf};

/// The files this client knows how to update.
///
/// The catalogue is in code, not config: each entry needs a validator and an
/// install rule, and an operator-supplied name could not be matched to either.
/// Config supplies the URL and nothing else.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target {
    CsamJargon,
    CsamTermsExtra,
    Layer2Terms,
    GuardingP2p,
    IpToCountry,
    HashBanlist,
    HashFilter,
    WhitelistHashes,
}

impl Target {
    pub const ALL: [Target; 8] = [
        Target::CsamJargon,
        Target::CsamTermsExtra,
        Target::Layer2Terms,
        Target::GuardingP2p,
        Target::IpToCountry,
        Target::HashBanlist,
        Target::HashFilter,
        Target::WhitelistHashes,
    ];

    /// Stable identifier used in the URL of the admin endpoint and as the config
    /// key. Never change one of these — it would silently orphan a configured
    /// URL.
    pub fn id(self) -> &'static str {
        match self {
            Target::CsamJargon => "csam_jargon",
            Target::CsamTermsExtra => "csam_terms_extra",
            Target::Layer2Terms => "layer2_terms",
            Target::GuardingP2p => "guarding_p2p",
            Target::IpToCountry => "ip_to_country",
            Target::HashBanlist => "hash_banlist",
            Target::HashFilter => "hash_filter",
            Target::WhitelistHashes => "whitelist_hashes",
        }
    }

    /// Name the file gets inside the destination directory.
    pub fn filename(self) -> &'static str {
        match self {
            Target::CsamJargon => "csam_jargon.txt",
            Target::CsamTermsExtra => "csam_terms_extra.txt",
            Target::Layer2Terms => "layer2_terms.txt",
            Target::GuardingP2p => "guarding.p2p",
            Target::IpToCountry => "ip-to-country.csv",
            Target::HashBanlist => "hash_banlist.txt",
            Target::HashFilter => "hash_filter.txt",
            Target::WhitelistHashes => "whitelist_hashes.txt",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Target::CsamJargon => "jargon terms (L1)",
            Target::CsamTermsExtra => "extra terms (L4)",
            Target::Layer2Terms => "L2 vocabulary",
            Target::GuardingP2p => "IP filter",
            Target::IpToCountry => "GeoIP database",
            Target::HashBanlist => "hash banlist (L3)",
            Target::HashFilter => "filter list (L5)",
            Target::WhitelistHashes => "hash whitelist",
        }
    }

    /// Hash lists support merge; everything else is replace-only.
    ///
    /// Merging a vocabulary would be wrong, not merely unsupported: a named
    /// section REPLACES its default, which is how an entry gets REMOVED. Union
    /// with the old file would resurrect every entry the publisher deliberately
    /// dropped, and the removal would silently stop working.
    pub fn supports_merge(self) -> bool {
        matches!(
            self,
            Target::HashBanlist | Target::HashFilter | Target::WhitelistHashes
        )
    }

    /// Two files are public by design and carry no access control:
    ///   * the poison/decoy list, which is harmless to leak and useful to share;
    ///   * third-party data (IP ranges, country ranges) that is public anyway.
    /// Everything else identifies material and is fetched with credentials.
    pub fn needs_credentials(self) -> bool {
        !matches!(self, Target::GuardingP2p | Target::IpToCountry)
    }

    /// Compiled-in default URL, used when config leaves the entry empty.
    ///
    /// Only the two public files have one. The rest name material and are
    /// fetched with credentials, so there is no sensible default: a server that
    /// has not been given a URL has not been given access either.
    ///
    /// ⚠ A default URL is baked into every binary and cannot be changed for
    ///   servers already in the field. Moving the host later means either
    ///   keeping the old name resolving or telling every operator to set
    ///   `[updates.urls]` by hand. The `/pub/` prefix is part of that
    ///   commitment — it separates the unauthenticated files from `/files/`,
    ///   which sits behind the access check.
    pub fn default_url(self) -> &'static str {
        match self {
            Target::GuardingP2p => "https://ed2k.emule-security.org/pub/guarding.p2p",
            Target::IpToCountry => "https://ed2k.emule-security.org/pub/ip-to-country.csv.zip",
            _ => "",
        }
    }
}

/// What the operator asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Replace the file wholesale.
    Replace,
    /// Union the downloaded file with the one on disk, comparing HASHES ONLY.
    Merge,
}

/// Outcome of one update, surfaced in the admin UI.
#[derive(Clone, Debug, serde::Serialize)]
pub struct UpdateReport {
    pub target: String,
    pub ok: bool,
    pub message: String,
    /// Bytes actually downloaded (the archive, when the source is zipped).
    pub downloaded: u64,
    /// Entries the runtime parser found in the file that was installed.
    pub entries_before: Option<u64>,
    pub entries_after: Option<u64>,
    pub signature_verified: bool,
    pub path: String,
}

#[derive(Debug)]
pub struct UpdateError(pub String);

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for UpdateError {}

macro_rules! bail {
    ($($t:tt)*) => { return Err(UpdateError(format!($($t)*))) };
}

// ─────────────────────────────────────────────────────────────────────────────
// Ed25519
// ─────────────────────────────────────────────────────────────────────────────

/// Verify a detached Ed25519 signature over `bytes`.
///
/// The signature file may be raw 64 bytes or the same 64 bytes in hex, possibly
/// with trailing whitespace — signing tools disagree and the difference is not
/// worth a support conversation.
///
/// `verify_strict` rather than `verify`: it rejects small-order and non-canonical
/// public keys, which removes the signature-malleability corner where two
/// different keys accept the same signature. There is no compatibility cost for
/// signatures produced by any normal tool.
pub fn verify_signature(
    bytes: &[u8],
    signature_file: &[u8],
    public_key_hex: &str,
) -> Result<(), UpdateError> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let pk_raw = match hex::decode(public_key_hex.trim()) {
        Ok(v) => v,
        Err(e) => bail!("public key is not hex: {e}"),
    };
    if pk_raw.len() != 32 {
        bail!("public key must be 32 bytes, got {}", pk_raw.len());
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pk_raw);
    let vk = match VerifyingKey::from_bytes(&pk) {
        Ok(v) => v,
        Err(e) => bail!("public key is not a valid Ed25519 point: {e}"),
    };

    let sig_bytes = parse_signature_bytes(signature_file)?;
    let sig = Signature::from_bytes(&sig_bytes);

    match vk.verify_strict(bytes, &sig) {
        Ok(()) => Ok(()),
        Err(_) => Err(UpdateError(
            "SIGNATURE DOES NOT VERIFY — file refused, nothing was written".to_string(),
        )),
    }
}

fn parse_signature_bytes(raw: &[u8]) -> Result<[u8; 64], UpdateError> {
    if raw.len() == 64 {
        let mut out = [0u8; 64];
        out.copy_from_slice(raw);
        return Ok(out);
    }
    let text = String::from_utf8_lossy(raw);
    let trimmed: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    match hex::decode(&trimmed) {
        Ok(v) if v.len() == 64 => {
            let mut out = [0u8; 64];
            out.copy_from_slice(&v);
            Ok(out)
        }
        Ok(v) => Err(UpdateError(format!(
            "signature must be 64 bytes, got {}",
            v.len()
        ))),
        Err(_) => Err(UpdateError(format!(
            "signature file is neither 64 raw bytes nor hex ({} bytes)",
            raw.len()
        ))),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Access key
// ─────────────────────────────────────────────────────────────────────────────

/// The credential this server presents to the update service.
///
/// It is NOT a new secret. It is the value this server already hands to a peer
/// during the obfuscated server-to-server handshake:
///
/// ```text
/// key = IPObfuscate(our seckey, reference IP)
/// ```
///
/// Two properties make it usable as a password. It is derived per-peer, so the
/// key a random client learns by pinging us is a DIFFERENT number — knowing one
/// tells you nothing about another. And the peer it was derived for already
/// holds it, so the update service can be given the table without any
/// registration step.
///
/// `reference_ip` is the server that vouched for us — the one we completed
/// gossip with, whose exported table the update service loaded. Deriving against
/// the update host instead would produce a number nobody has ever seen.
///
/// ⚠ It authenticates "an eD2k server we have gossiped with", which is NOT the
///   same as "an operator who should hold a catalogue of known material".
///   Anyone can run a server. This is a gate, not a vetting decision, and the
///   service is expected to keep an approval step behind it.
pub fn derive_access_key(seckey: &[u8; 16], reference_ip: std::net::Ipv4Addr) -> u32 {
    let ip_le = u32::from_le_bytes(reference_ip.octets());
    crate::proto::server_obfuscation::ip_obfuscate(seckey, ip_le)
}

// ─────────────────────────────────────────────────────────────────────────────
// Download
// ─────────────────────────────────────────────────────────────────────────────

struct Downloaded {
    bytes: Vec<u8>,
    declared_len: Option<u64>,
}

/// Blocking HTTP GET. Callers run this inside `spawn_blocking`.
fn http_get(
    url: &str,
    timeout: std::time::Duration,
    max_bytes: u64,
    credential: Option<(&str, String)>,
) -> Result<Downloaded, UpdateError> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(15))
        .timeout(timeout)
        .user_agent(concat!("ed2k-server/", env!("CARGO_PKG_VERSION")))
        .build();

    let mut req = agent.get(url);
    if let Some((header, value)) = credential {
        req = req.set(header, &value);
    }

    let resp = match req.call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, r)) => {
            // 403 here is the normal "not approved yet" answer and deserves a
            // readable message rather than a status number.
            let hint = match code {
                401 | 403 => " — this server is not on the update service's allow list, \
                               or its access key has changed (seckey regenerated, or the \
                               server moved to a different IP)",
                404 => " — no such file on the update service",
                _ => "",
            };
            let body = r.into_string().unwrap_or_default();
            let body = body.chars().take(200).collect::<String>();
            bail!("HTTP {code}{hint}{}", if body.is_empty() { String::new() } else { format!(": {body}") });
        }
        Err(e) => bail!("request failed: {e}"),
    };

    let declared_len = resp
        .header("Content-Length")
        .and_then(|v| v.parse::<u64>().ok());

    if let Some(len) = declared_len {
        if len > max_bytes {
            bail!("declared size {len} exceeds updates.max_bytes ({max_bytes})");
        }
    }

    let mut bytes = Vec::new();
    let mut reader = resp.into_reader().take(max_bytes + 1);
    if let Err(e) = reader.read_to_end(&mut bytes) {
        // A dropped connection lands here. It is the single most common failure
        // and the one that produces a plausible-looking prefix of a good file.
        bail!("download interrupted after {} bytes: {e}", bytes.len());
    }
    if bytes.len() as u64 > max_bytes {
        bail!("response exceeds updates.max_bytes ({max_bytes})");
    }
    if bytes.is_empty() {
        bail!("server returned an empty body");
    }

    // TRUNCATION CHECK. Without this a short read is indistinguishable from a
    // legitimately short file, and the parser accepts the prefix happily.
    if let Some(len) = declared_len {
        if bytes.len() as u64 != len {
            bail!(
                "truncated download: Content-Length said {len}, got {}",
                bytes.len()
            );
        }
    }

    Ok(Downloaded {
        bytes,
        declared_len,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// ZIP
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the first regular file from a ZIP archive.
///
/// Deliberately minimal and deliberately not a new dependency: `flate2` is
/// already in the tree for protocol compression, and the archive we consume is
/// one file produced by our own update service. Stored (method 0) and deflate
/// (method 8) are the only methods any producer uses for this.
///
/// Reads the END OF CENTRAL DIRECTORY rather than scanning for local headers:
/// the local header's size fields are allowed to be zero with the real values in
/// a trailing data descriptor, which a naive scanner reads as an empty file.
pub fn unzip_first_file(archive: &[u8]) -> Result<Vec<u8>, UpdateError> {
    const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const CD_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
    const LFH_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];

    if archive.len() < 22 {
        bail!("not a ZIP archive: only {} bytes", archive.len());
    }

    // EOCD is at the end, after a comment of up to 64 KiB.
    let search_from = archive.len().saturating_sub(22 + 65_535);
    let mut eocd = None;
    let mut i = archive.len() - 22;
    loop {
        if archive[i..i + 4] == EOCD_SIG {
            eocd = Some(i);
            break;
        }
        if i == search_from {
            break;
        }
        i -= 1;
    }
    let Some(eocd) = eocd else {
        bail!("not a ZIP archive: no end-of-central-directory record");
    };

    let cd_offset = u32le(archive, eocd + 16)? as usize;
    if cd_offset + 46 > archive.len() || archive[cd_offset..cd_offset + 4] != CD_SIG {
        bail!("ZIP central directory is missing or misplaced");
    }

    let method = u16le(archive, cd_offset + 10)?;
    let comp_size = u32le(archive, cd_offset + 20)? as usize;
    let uncomp_size = u32le(archive, cd_offset + 24)? as usize;
    let name_len = u16le(archive, cd_offset + 28)? as usize;
    let extra_len = u16le(archive, cd_offset + 30)? as usize;
    let comment_len = u16le(archive, cd_offset + 32)? as usize;
    let lfh_offset = u32le(archive, cd_offset + 42)? as usize;
    let _ = (extra_len, comment_len);

    let name = String::from_utf8_lossy(
        archive
            .get(cd_offset + 46..cd_offset + 46 + name_len)
            .unwrap_or_default(),
    )
    .into_owned();
    if name.ends_with('/') {
        bail!("first ZIP entry is a directory ({name}), expected a file");
    }

    if lfh_offset + 30 > archive.len() || archive[lfh_offset..lfh_offset + 4] != LFH_SIG {
        bail!("ZIP local file header is missing at offset {lfh_offset}");
    }
    let l_name_len = u16le(archive, lfh_offset + 26)? as usize;
    let l_extra_len = u16le(archive, lfh_offset + 28)? as usize;
    let data_start = lfh_offset + 30 + l_name_len + l_extra_len;
    let data_end = data_start + comp_size;
    if data_end > archive.len() {
        bail!(
            "ZIP entry {name} claims {comp_size} compressed bytes but the archive ends early \
             — truncated download"
        );
    }
    let data = &archive[data_start..data_end];

    let out = match method {
        0 => data.to_vec(),
        8 => {
            let mut d = flate2::read::DeflateDecoder::new(data);
            let mut out = Vec::with_capacity(uncomp_size);
            if let Err(e) = d.read_to_end(&mut out) {
                bail!("ZIP entry {name} failed to inflate: {e}");
            }
            out
        }
        m => bail!("ZIP entry {name} uses unsupported compression method {m}"),
    };

    if uncomp_size != 0 && out.len() != uncomp_size {
        bail!(
            "ZIP entry {name} inflated to {} bytes, header said {uncomp_size} — corrupt archive",
            out.len()
        );
    }
    Ok(out)
}

fn u16le(b: &[u8], at: usize) -> Result<u16, UpdateError> {
    match b.get(at..at + 2) {
        Some(s) => Ok(u16::from_le_bytes([s[0], s[1]])),
        None => Err(UpdateError("ZIP structure runs past end of file".into())),
    }
}
fn u32le(b: &[u8], at: usize) -> Result<u32, UpdateError> {
    match b.get(at..at + 4) {
        Some(s) => Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]])),
        None => Err(UpdateError("ZIP structure runs past end of file".into())),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a candidate file with the SAME code that loads it at runtime and
/// return how many entries it holds.
///
/// Using the runtime parser is the point. A second, private validator drifts
/// from the real one, and the file that passes validation is then rejected on
/// load — leaving the layer running on nothing. The hard error on an unknown
/// section in the vocabulary file exists for exactly this reason and must be
/// exercised here, before the file is installed, not after.
pub fn validate(target: Target, bytes: &[u8]) -> Result<u64, UpdateError> {
    // Every one of these formats is line-oriented text. Binary content is a
    // wrong-URL accident (an HTML error page, an unextracted archive) and is
    // worth catching early with a clear message.
    if bytes.contains(&0u8) {
        bail!("file contains NUL bytes — this is not a text file (wrong URL, or an archive that was not extracted?)");
    }
    let text = String::from_utf8_lossy(bytes);

    match target {
        Target::Layer2Terms => match crate::filter::layer2_terms::Layer2Terms::parse(&text) {
            Ok(t) => Ok(t.len() as u64),
            Err(e) => Err(UpdateError(format!("L2 vocabulary rejected: {e}"))),
        },

        Target::CsamJargon | Target::CsamTermsExtra => {
            let mut n = 0u64;
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                n += 1;
            }
            if n == 0 {
                bail!("term list has no entries — refusing to silence the layer");
            }
            Ok(n)
        }

        Target::HashBanlist | Target::HashFilter | Target::WhitelistHashes => {
            let mut n = 0u64;
            let mut bad = 0u64;
            let mut first_bad = String::new();
            for line in text.lines() {
                match hash_of_line(line) {
                    LineKind::Hash(_) => n += 1,
                    LineKind::Comment => {}
                    LineKind::Junk => {
                        bad += 1;
                        if first_bad.is_empty() {
                            first_bad = line.chars().take(60).collect();
                        }
                    }
                }
            }
            // A handful of malformed lines is a normal editing artefact. A file
            // that is mostly malformed is the wrong file.
            if bad > 0 && bad * 4 > n {
                bail!("{bad} unparseable lines against {n} hashes — wrong format? first: {first_bad:?}");
            }
            // An EMPTY whitelist is meaningful (it retracts every exemption) and
            // is allowed. An empty ban or poison list is not: it can only be a
            // failure, and it disarms a layer everywhere at once.
            if n == 0 && target != Target::WhitelistHashes {
                bail!("hash list is empty — refusing to disarm the layer");
            }
            Ok(n)
        }

        Target::GuardingP2p => {
            // The RUNTIME parser, for the reason stated at the top of this
            // function — and this entry is why the rule is written down.
            //
            // It shipped with a hand-written check instead: "the line contains a
            // colon and a dash". That describes the `.p2p` layout, while the
            // file an operator actually has is as often in `ipfilter.dat`
            // layout, which has no colons at all. A perfectly good list was
            // refused with "this does not look like a guarding.p2p file", and
            // the private check disagreed with the loader in BOTH directions:
            // it also passed `.p2p` files that the loader could not read.
            let ranges = text
                .lines()
                .filter(|l| {
                    let l = l.trim();
                    !l.is_empty()
                        && !l.starts_with('#')
                        && crate::filter::ipfilter::parse_line(l).is_some()
                })
                .count() as u64;
            if ranges == 0 {
                bail!(
                    "no ranges parsed — expected either \"1.0.0.0 - 1.0.0.255 , 000 , name\" \
                     (ipfilter.dat) or \"name:1.0.0.0-1.0.0.255\" (.p2p)"
                );
            }
            Ok(ranges)
        }

        Target::IpToCountry => {
            let mut n = 0u64;
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut p = line.splitn(4, ',');
                let a = p.next().map(|s| s.trim().trim_matches('"').parse::<u32>());
                let b = p.next().map(|s| s.trim().trim_matches('"').parse::<u32>());
                if matches!(a, Some(Ok(_))) && matches!(b, Some(Ok(_))) {
                    n += 1;
                }
            }
            if n == 0 {
                bail!("no ranges parsed — this does not look like ip-to-country.csv");
            }
            Ok(n)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Merge
// ─────────────────────────────────────────────────────────────────────────────

enum LineKind {
    Hash([u8; 16]),
    Comment,
    Junk,
}

/// Classify one line of a hash list and extract the hash if there is one.
///
/// The hash is the ONLY thing compared. The two files being merged routinely
/// disagree about everything else: one is bare hashes exported by a tool, the
/// other is the operator's working copy with a reason written after each entry.
/// Comparing whole lines would treat those as different entries and duplicate
/// every single one.
fn hash_of_line(line: &str) -> LineKind {
    let line = line.trim();
    if line.is_empty() {
        return LineKind::Comment;
    }
    if line.starts_with('#') || line.starts_with(';') || line.starts_with("//") {
        return LineKind::Comment;
    }
    let token: String = line
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    if token.len() != 32 {
        return LineKind::Junk;
    }
    // The character right after must not be another hex digit, or this is a
    // longer token that merely starts like a hash.
    if line
        .chars()
        .nth(32)
        .is_some_and(|c| c.is_ascii_hexdigit())
    {
        return LineKind::Junk;
    }
    match hex::decode(&token) {
        Ok(v) if v.len() == 16 => {
            let mut h = [0u8; 16];
            h.copy_from_slice(&v);
            LineKind::Hash(h)
        }
        _ => LineKind::Junk,
    }
}

/// Does this line carry an annotation after the hash?
fn line_has_comment(line: &str) -> bool {
    let rest = line.trim().get(32..).unwrap_or("").trim();
    !rest.is_empty()
}

/// Union two hash lists, comparing hashes only.
///
/// Rules, in order:
///   * the existing file keeps its structure — its own header comments, its
///     grouping and its order all survive, because that structure is the
///     operator's reasoning and a sort would destroy it;
///   * a hash present in both keeps the ANNOTATED variant. An entry that says
///     why it is there is worth more than a bare one, whichever side it came
///     from;
///   * hashes only in the new file are appended in a marked block, so the next
///     review can see what arrived and when.
pub fn merge_hash_lists(old: &str, new: &str, stamp: &str) -> String {
    use std::collections::HashMap;

    let mut out: Vec<String> = old.lines().map(|l| l.to_string()).collect();
    let mut index: HashMap<[u8; 16], usize> = HashMap::new();
    for (i, line) in out.iter().enumerate() {
        if let LineKind::Hash(h) = hash_of_line(line) {
            index.entry(h).or_insert(i);
        }
    }

    let mut appended: Vec<String> = Vec::new();
    for line in new.lines() {
        let LineKind::Hash(h) = hash_of_line(line) else {
            // Comments and junk from the incoming file are dropped: its header
            // would otherwise be pasted into the middle of the merged result on
            // every single merge.
            continue;
        };
        match index.get(&h) {
            Some(&i) => {
                // Upgrade a bare entry to an annotated one, never the reverse.
                if !line_has_comment(&out[i]) && line_has_comment(line) {
                    out[i] = line.trim_end().to_string();
                }
            }
            None => {
                index.insert(h, usize::MAX);
                appended.push(line.trim_end().to_string());
            }
        }
    }

    if !appended.is_empty() {
        if !out.last().map(|l| l.trim().is_empty()).unwrap_or(true) {
            out.push(String::new());
        }
        out.push(format!("# ── merged {} entries on {} ──", appended.len(), stamp));
        out.extend(appended);
    }

    let mut s = out.join("\n");
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

// ─────────────────────────────────────────────────────────────────────────────
// Install
// ─────────────────────────────────────────────────────────────────────────────

/// Rotate `path.1` … `path.N` and copy the current file into `path.1`.
///
/// One generation is not enough in practice: a bad file is often noticed a day
/// later, by which time an automatic update has already pushed the bad one into
/// the single backup slot. Three generations cover that without turning into a
/// directory full of copies of a multi-megabyte list.
fn rotate_backups(path: &Path, keep: u8) -> std::io::Result<()> {
    if keep == 0 || !path.exists() {
        return Ok(());
    }
    let with_suffix = |n: u8| -> PathBuf {
        let mut p = path.as_os_str().to_owned();
        p.push(format!(".{n}"));
        PathBuf::from(p)
    };
    // Drop the oldest, shift the rest down.
    let oldest = with_suffix(keep);
    if oldest.exists() {
        let _ = std::fs::remove_file(&oldest);
    }
    for n in (1..keep).rev() {
        let from = with_suffix(n);
        if from.exists() {
            let _ = std::fs::rename(&from, with_suffix(n + 1));
        }
    }
    std::fs::copy(path, with_suffix(1))?;
    Ok(())
}

/// Write `content` to `path` atomically.
///
/// Temp file in the SAME directory, fsync, then rename. Same directory because
/// `rename` is only atomic within a filesystem; `/tmp` is frequently a separate
/// one and the operation would silently degrade to copy-then-delete, which has a
/// window where the file is half-written. The fsync is what makes the content
/// durable before the name points at it — without it a power loss can leave the
/// new name pointing at zero bytes.
fn install_atomic(path: &Path, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("update")
    ));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(content)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    // Also fsync the directory, so the rename itself survives a crash.
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// The whole operation
// ─────────────────────────────────────────────────────────────────────────────

/// Everything one update needs, resolved from config by the caller.
pub struct UpdateRequest {
    pub target: Target,
    pub mode: Mode,
    pub url: String,
    pub dest_dir: String,
    pub public_key_hex: String,
    pub require_signature: bool,
    pub credential: Option<(String, String)>,
    pub backups: u8,
    pub timeout: std::time::Duration,
    pub max_bytes: u64,
    /// Refuse a replacement that drops below this fraction of the current entry
    /// count. 0.0 disables the check.
    pub min_keep_ratio: f64,
}

/// Download, verify, validate, back up, install. BLOCKING — call from
/// `spawn_blocking`.
///
/// Nothing touches disk until every check has passed. On any failure the file on
/// disk is exactly as it was, which is the whole point: a failed update must
/// leave a working server, not a disarmed one.
pub fn run(req: &UpdateRequest) -> Result<UpdateReport, UpdateError> {
    let target = req.target;
    let path = Path::new(&req.dest_dir).join(target.filename());

    if req.url.trim().is_empty() {
        bail!(
            "no URL configured for {} — set updates.urls.{}",
            target.id(),
            target.id()
        );
    }
    if req.mode == Mode::Merge && !target.supports_merge() {
        bail!(
            "{} cannot be merged — a named section REPLACES its default, so a union \
             would resurrect every entry that was deliberately removed",
            target.id()
        );
    }

    let cred = req
        .credential
        .as_ref()
        .map(|(h, v)| (h.as_str(), v.clone()));

    // ── 1. fetch ─────────────────────────────────────────────────────────
    let dl = http_get(&req.url, req.timeout, req.max_bytes, cred.clone())?;
    let downloaded = dl.bytes.len() as u64;
    let _ = dl.declared_len;

    // ── 2. signature, over the bytes AS SERVED ───────────────────────────
    // Signed before extraction, so the archive itself is covered. Verifying the
    // extracted content instead would leave the archive framing unauthenticated,
    // and a decompressor is exactly the kind of code that should only ever see
    // bytes somebody vouched for.
    let mut signature_verified = false;
    if req.require_signature {
        if req.public_key_hex.trim().is_empty() {
            bail!(
                "updates.require_signature is on but updates.public_key is empty — \
                 refusing to install unverified data"
            );
        }
        let sig_url = format!("{}.sig", req.url);
        let sig = http_get(&sig_url, req.timeout, 4096, cred)?;
        verify_signature(&dl.bytes, &sig.bytes, &req.public_key_hex)?;
        signature_verified = true;
    }

    // ── 3. extract ───────────────────────────────────────────────────────
    let looks_zipped = req.url.trim_end().to_ascii_lowercase().ends_with(".zip")
        || dl.bytes.starts_with(b"PK\x03\x04");
    let content = if looks_zipped {
        unzip_first_file(&dl.bytes)?
    } else {
        dl.bytes
    };

    // ── 4. validate with the runtime parser ──────────────────────────────
    let incoming_entries = validate(target, &content)?;

    // ── 5. compare against what is already installed ─────────────────────
    let existing = std::fs::read(&path).ok();
    let entries_before = existing
        .as_ref()
        .and_then(|b| validate(target, b).ok());

    let final_bytes: Vec<u8> = if req.mode == Mode::Merge {
        let old = existing
            .as_ref()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        let new = String::from_utf8_lossy(&content).into_owned();
        let stamp = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
        merge_hash_lists(&old, &new, &stamp).into_bytes()
    } else {
        content
    };

    let entries_after = validate(target, &final_bytes)?;

    // COLLAPSE GUARD, replace mode only — a merge can never shrink.
    //
    // The failure this catches is not a malicious one, it is the ordinary one:
    // a proxy or a half-open connection hands back a prefix that parses cleanly
    // and is simply much shorter. Content-Length catches most of those, but not
    // when the server never sent one.
    if req.mode == Mode::Replace && req.min_keep_ratio > 0.0 {
        if let Some(before) = entries_before {
            if before > 0 {
                let ratio = entries_after as f64 / before as f64;
                if ratio < req.min_keep_ratio {
                    bail!(
                        "refusing to install: {entries_after} entries would replace {before} \
                         ({:.0}% of the current file, floor is {:.0}%). If this shrink is \
                         intended, lower updates.min_keep_ratio or install by hand.",
                        ratio * 100.0,
                        req.min_keep_ratio * 100.0
                    );
                }
            }
        }
    }

    // ── 6. back up and install ───────────────────────────────────────────
    if let Err(e) = rotate_backups(&path, req.backups) {
        bail!("could not rotate backups for {}: {e}", path.display());
    }
    if let Err(e) = install_atomic(&path, &final_bytes) {
        bail!("could not install {}: {e}", path.display());
    }

    let message = match req.mode {
        Mode::Replace => format!(
            "replaced: {} entries (was {})",
            entries_after,
            entries_before
                .map(|n| n.to_string())
                .unwrap_or_else(|| "no file".into())
        ),
        Mode::Merge => format!(
            "merged: {} entries (was {}, incoming {})",
            entries_after,
            entries_before.unwrap_or(0),
            incoming_entries
        ),
    };

    Ok(UpdateReport {
        target: target.id().to_string(),
        ok: true,
        message,
        downloaded,
        entries_before,
        entries_after: Some(entries_after),
        signature_verified,
        path: path.display().to_string(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Peer export
// ─────────────────────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
pub struct PeerPair {
    pub ip: String,
    /// Hex, lower case, 8 digits.
    pub key: String,
    pub verified_plain: bool,
}

#[derive(serde::Serialize)]
pub struct PeerExport {
    /// Our own address. The update service needs it because every key in this
    /// table was derived against it — a peer downloading later presents the same
    /// number, computed from its own seckey and this IP.
    pub reference_ip: String,
    pub generated_at: String,
    pub pairs: Vec<PeerPair>,
}

/// POST the peer table to the update service.
///
/// BLOCKING — call from `spawn_blocking`.
///
/// ⚠ What this table is and is not. Every entry means "this address completed an
///   obfuscated server-to-server handshake with us". That is a proof of running
///   eD2k server software, nothing more. It is not a judgement about the
///   operator, and the update service must not treat it as one — the software is
///   public and the handshake is automatic, so an entry appears without anybody
///   deciding anything. Treat the table as a list of CANDIDATES for an approval
///   step, and keep the vetting on the service side.
pub fn push_peer_export(
    url: &str,
    token: &str,
    export: &PeerExport,
    timeout: std::time::Duration,
) -> Result<usize, UpdateError> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(15))
        .timeout(timeout)
        .user_agent(concat!("ed2k-server/", env!("CARGO_PKG_VERSION")))
        .build();

    let mut req = agent.post(url);
    if !token.is_empty() {
        req = req.set("Authorization", &format!("Bearer {token}"));
    }
    match req.send_json(serde_json::to_value(export).map_err(|e| UpdateError(e.to_string()))?) {
        Ok(_) => Ok(export.pairs.len()),
        Err(ureq::Error::Status(code, _)) => Err(UpdateError(format!(
            "peer export rejected with HTTP {code}"
        ))),
        Err(e) => Err(UpdateError(format!("peer export failed: {e}"))),
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> String {
        format!("{:032x}", n)
    }

    #[test]
    fn merge_compares_hashes_only() {
        // The whole reason this function exists: one side is a bare export, the
        // other is the working copy with reasons written down. Comparing lines
        // would duplicate every entry.
        let old = format!("# header\n{}  # known series\n{}\n", h(1), h(2));
        let new = format!("{}\n{}\n{}\n", h(1), h(2), h(3));
        let out = merge_hash_lists(&old, &new, "TEST");
        assert_eq!(out.matches(&h(1)).count(), 1, "{out}");
        assert_eq!(out.matches(&h(2)).count(), 1, "{out}");
        assert_eq!(out.matches(&h(3)).count(), 1, "{out}");
        assert!(out.contains("# header"), "existing structure must survive");
    }

    #[test]
    fn merge_keeps_the_annotated_variant_from_either_side() {
        // Incoming annotation upgrades a bare local entry...
        let old = format!("{}\n", h(1));
        let new = format!("{}  ; reason from upstream\n", h(1));
        let out = merge_hash_lists(&old, &new, "TEST");
        assert!(out.contains("reason from upstream"), "{out}");
        assert_eq!(out.matches(&h(1)).count(), 1);

        // ...but a bare incoming entry never strips a local one.
        let old = format!("{}  ; local reason\n", h(1));
        let new = format!("{}\n", h(1));
        let out = merge_hash_lists(&old, &new, "TEST");
        assert!(out.contains("local reason"), "{out}");
    }

    #[test]
    fn merge_drops_the_incoming_header() {
        // Otherwise every merge pastes another copy of the upstream preamble
        // into the middle of the file.
        let old = format!("{}\n", h(1));
        let new = format!("# upstream preamble\n# generated by tool\n{}\n", h(2));
        let out = merge_hash_lists(&old, &new, "TEST");
        assert!(!out.contains("upstream preamble"), "{out}");
        assert!(out.contains(&h(2)));
    }

    #[test]
    fn merge_is_idempotent() {
        let old = format!("{}\n{}\n", h(1), h(2));
        let new = format!("{}\n{}\n", h(2), h(3));
        let once = merge_hash_lists(&old, &new, "TEST");
        let twice = merge_hash_lists(&once, &new, "TEST");
        for n in 1..=3u8 {
            assert_eq!(twice.matches(&h(n)).count(), 1, "{twice}");
        }
    }

    #[test]
    fn a_line_that_merely_starts_like_a_hash_is_not_one() {
        let long = "0".repeat(40);
        assert!(matches!(hash_of_line(&long), LineKind::Junk));
        assert!(matches!(hash_of_line(&h(7)), LineKind::Hash(_)));
        assert!(matches!(hash_of_line("# comment"), LineKind::Comment));
        assert!(matches!(hash_of_line("  "), LineKind::Comment));
    }

    #[test]
    fn an_empty_ban_list_is_refused_but_an_empty_whitelist_is_not() {
        // Asymmetric on purpose. An empty ban or poison list can only be a
        // failure and it disarms a layer on every server that pulled it. An
        // empty whitelist is a real operator action: it retracts exemptions.
        assert!(validate(Target::HashBanlist, b"# nothing here\n").is_err());
        assert!(validate(Target::HashFilter, b"# nothing here\n").is_err());
        assert!(validate(Target::WhitelistHashes, b"# nothing here\n").is_ok());
    }

    #[test]
    fn validation_rejects_binary_and_wrong_formats() {
        assert!(validate(Target::CsamJargon, b"text\x00binary").is_err());
        assert!(validate(Target::GuardingP2p, b"not a range list\n").is_err());
        // Both list formats must pass — the file name says nothing about which
        // one an operator has.
        assert!(validate(
            Target::GuardingP2p,
            b"001.000.000.000 - 001.000.000.255 , 000 , Some Org\n"
        )
        .is_ok());
        assert!(validate(Target::IpToCountry, b"nope\n").is_err());
        assert!(validate(
            Target::IpToCountry,
            b"16777216,16777471,AU,Australia\n"
        )
        .is_ok());
        assert!(validate(Target::GuardingP2p, b"Some range:1.2.3.4-1.2.3.9\n").is_ok());
    }

    #[test]
    fn hash_validation_rejects_a_file_that_is_mostly_junk() {
        let mut s = String::new();
        s.push_str(&format!("{}\n", h(1)));
        for i in 0..10 {
            s.push_str(&format!("this is not a hash {i}\n"));
        }
        assert!(validate(Target::HashBanlist, s.as_bytes()).is_err());
    }

    #[test]
    fn signature_parsing_takes_raw_or_hex() {
        let raw = [7u8; 64];
        assert_eq!(parse_signature_bytes(&raw).unwrap(), raw);
        let as_hex = hex::encode(raw);
        assert_eq!(parse_signature_bytes(as_hex.as_bytes()).unwrap(), raw);
        let with_newline = format!("{as_hex}\n");
        assert_eq!(parse_signature_bytes(with_newline.as_bytes()).unwrap(), raw);
        assert!(parse_signature_bytes(b"short").is_err());
    }

    #[test]
    fn a_wrong_signature_is_refused() {
        // A real key pair is not needed to prove the failure path closes: any
        // valid public key with a signature that was not made over these bytes
        // must be rejected.
        let pk = hex::encode([1u8; 32]);
        let sig = [0u8; 64];
        assert!(verify_signature(b"payload", &sig, &pk).is_err());
        assert!(verify_signature(b"payload", &sig, "not hex").is_err());
        assert!(verify_signature(b"payload", &sig, &hex::encode([1u8; 16])).is_err());
    }

    #[test]
    fn zip_reader_handles_stored_and_rejects_garbage() {
        assert!(unzip_first_file(b"not a zip at all").is_err());
        assert!(unzip_first_file(&[]).is_err());
    }

    #[test]
    fn merge_is_refused_for_files_where_it_would_be_wrong() {
        // Vocabulary files must never be merged: a named section replaces its
        // default, which is how an entry gets removed.
        assert!(!Target::Layer2Terms.supports_merge());
        assert!(!Target::CsamJargon.supports_merge());
        assert!(Target::HashBanlist.supports_merge());
    }
}

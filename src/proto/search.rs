//! Search expression tree (SPEC.md §2.4).
//!
//! Recursive binary tree as the payload of SEARCHREQUEST.
//!
//! Node types:
//!   0x00 = boolean op (AND/OR/NOT) + two children
//!   0x01 = string term (utf-8 with length prefix)
//!   0x02 = meta-tag (string value + tag name)
//!   0x03 = numeric u32 (value + cmp_op + tag name)
//!   0x08 = numeric u64 (value + cmp_op + tag name)

use anyhow::{anyhow, bail, Result};

const NODE_BOOL: u8 = 0x00;
const NODE_STRING: u8 = 0x01;
const NODE_META: u8 = 0x02;
const NODE_NUMERIC32: u8 = 0x03;
const NODE_NUMERIC64: u8 = 0x08;

const OP_AND: u8 = 0x00;
const OP_OR: u8 = 0x01;
const OP_NOT: u8 = 0x02;

const CMP_EQ: u8 = 0x00;
const CMP_GT: u8 = 0x01;
const CMP_LT: u8 = 0x02;
const CMP_GE: u8 = 0x03;
const CMP_LE: u8 = 0x04;
const CMP_NE: u8 = 0x05;

const MAX_DEPTH: u32 = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoolOp {
    And,
    Or,
    Not, // binary: left AND NOT right
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Gt,
    Lt,
    Ge,
    Le,
    Ne,
}

impl CmpOp {
    pub fn matches_u64(&self, value: u64, threshold: u64) -> bool {
        match self {
            CmpOp::Eq => value == threshold,
            CmpOp::Ne => value != threshold,
            CmpOp::Gt => value > threshold,
            CmpOp::Lt => value < threshold,
            CmpOp::Ge => value >= threshold,
            CmpOp::Le => value <= threshold,
        }
    }
}

/// The tag a meta or numeric node refers to.
///
/// eMule writes a tag name of length 1 holding the raw tag ID
/// (`WriteUInt16(1); WriteUInt8(id)`). The media IDs are 0xD0-0xD5, and a lone
/// byte >= 0x80 is not valid UTF-8 — reading names as strings made every
/// artist/album/title/length/bitrate/codec search fail to parse (issue #24).
/// So a one-byte name is an ID, whatever its value; a longer one is a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchTag {
    Id(u8),
    Name(String),
}

impl SearchTag {
    fn from_bytes(b: &[u8]) -> Self {
        match b {
            [id] => SearchTag::Id(*id),
            _ => SearchTag::Name(String::from_utf8_lossy(b).into_owned()),
        }
    }

    /// The one-byte tag ID, if this is one.
    pub fn id(&self) -> Option<u8> {
        match self {
            SearchTag::Id(id) => Some(*id),
            SearchTag::Name(_) => None,
        }
    }

    /// Is this the tag `id`, or a name that some client uses for it?
    pub fn is(&self, id: u8, names: &[&str]) -> bool {
        match self {
            SearchTag::Id(i) => *i == id,
            SearchTag::Name(n) => names.iter().any(|x| n.eq_ignore_ascii_case(x)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchNode {
    /// Boolean combinator with two operands
    Bool(BoolOp, Box<SearchNode>, Box<SearchNode>),
    /// String term: must be a token in the filename
    Term(String),
    /// Meta-tag string: tag_name = value (e.g. type="Video")
    Meta { tag_name: SearchTag, value: String },
    /// Numeric constraint on a tag (size, bitrate, length…)
    Numeric {
        tag_name: SearchTag,
        op: CmpOp,
        value: u64,
    },
}

pub fn parse(payload: &[u8]) -> Result<SearchNode> {
    let mut slice = payload;
    let node = parse_node(&mut slice, 0)?;
    if !slice.is_empty() {
        // Trailing bytes - some clients send them; warn but accept
        tracing::debug!(
            trailing = slice.len(),
            "trailing bytes after search tree (ignored)"
        );
    }
    Ok(node)
}

fn parse_node(buf: &mut &[u8], depth: u32) -> Result<SearchNode> {
    if depth > MAX_DEPTH {
        bail!("search tree too deep (>{MAX_DEPTH})");
    }
    if buf.is_empty() {
        bail!("empty buffer at node start");
    }

    let kind = buf[0];
    *buf = &buf[1..];

    match kind {
        NODE_BOOL => {
            if buf.is_empty() {
                bail!("missing bool op byte");
            }
            let op_byte = buf[0];
            *buf = &buf[1..];
            let op = match op_byte {
                OP_AND => BoolOp::And,
                OP_OR => BoolOp::Or,
                OP_NOT => BoolOp::Not,
                other => bail!("unknown bool op 0x{other:02x}"),
            };
            let left = parse_node(buf, depth + 1)?;
            let right = parse_node(buf, depth + 1)?;
            Ok(SearchNode::Bool(op, Box::new(left), Box::new(right)))
        }
        NODE_STRING => {
            let s = read_short_string(buf)?;
            Ok(SearchNode::Term(s))
        }
        NODE_META => {
            // value (string), then tag_name (string)
            let value = read_short_string(buf)?;
            let tag_name = SearchTag::from_bytes(read_short_bytes(buf)?);
            Ok(SearchNode::Meta { tag_name, value })
        }
        NODE_NUMERIC32 => {
            if buf.len() < 4 {
                bail!("numeric32 truncated");
            }
            let value = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
            *buf = &buf[4..];
            let op = read_cmp_op(buf)?;
            let tag_name = SearchTag::from_bytes(read_short_bytes(buf)?);
            Ok(SearchNode::Numeric {
                tag_name,
                op,
                value,
            })
        }
        NODE_NUMERIC64 => {
            if buf.len() < 8 {
                bail!("numeric64 truncated");
            }
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&buf[..8]);
            let value = u64::from_le_bytes(arr);
            *buf = &buf[8..];
            let op = read_cmp_op(buf)?;
            let tag_name = SearchTag::from_bytes(read_short_bytes(buf)?);
            Ok(SearchNode::Numeric {
                tag_name,
                op,
                value,
            })
        }
        other => Err(anyhow!("unknown node type 0x{other:02x}")),
    }
}

fn read_short_bytes<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8]> {
    if buf.len() < 2 {
        bail!("string length prefix missing");
    }
    let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    *buf = &buf[2..];
    if buf.len() < len {
        bail!("string body truncated ({} of {} bytes)", buf.len(), len);
    }
    let (body, rest) = buf.split_at(len);
    *buf = rest;
    Ok(body)
}

/// A search term or meta value. Decoded lossily: one bad byte from an old or
/// odd client turns into U+FFFD — that word then matches nothing — instead of
/// failing the whole request.
fn read_short_string(buf: &mut &[u8]) -> Result<String> {
    Ok(String::from_utf8_lossy(read_short_bytes(buf)?).into_owned())
}

fn read_cmp_op(buf: &mut &[u8]) -> Result<CmpOp> {
    if buf.is_empty() {
        bail!("cmp op byte missing");
    }
    let op = match buf[0] {
        CMP_EQ => CmpOp::Eq,
        CMP_GT => CmpOp::Gt,
        CMP_LT => CmpOp::Lt,
        CMP_GE => CmpOp::Ge,
        CMP_LE => CmpOp::Le,
        CMP_NE => CmpOp::Ne,
        other => bail!("unknown cmp op 0x{other:02x}"),
    };
    *buf = &buf[1..];
    Ok(op)
}

/// Split a query term into its text and the markers around it.
///
/// Returns `(core, anchored, starred)`. `*` may appear at either end and means
/// "do not require this as an index token"; `^` leads and means "match at the
/// start". Both are stripped from the text.
pub fn parse_markers(t: &str) -> (&str, bool, bool) {
    let mut s = t;
    let mut starred = false;
    let mut anchored = false;
    while let Some(rest) = s.strip_prefix('*') {
        starred = true;
        s = rest;
    }
    if let Some(rest) = s.strip_prefix('^') {
        anchored = true;
        s = rest;
    }
    while let Some(rest) = s.strip_suffix('*') {
        starred = true;
        s = rest;
    }
    (s, anchored, starred)
}

/// Remove words no indexed file contains, instead of letting them empty the
/// whole search.
///
/// Returns the rewritten tree and the words that were dropped.
///
/// Before this, one word that is a token nowhere — a typo, a word from another
/// language, a release tag nobody else used — made the AND intersection empty,
/// and the search returned nothing however good the other words were. The
/// reference server behaves the same way (an unknown word sorts first at count
/// 0 and kills its branch); we deliberately do not copy that.
///
/// ⚠ THIS REWRITES THE TREE, AND BOTH SEARCH STAGES MUST USE THE RESULT.
///   Dropping the word from the candidate lookup alone does nothing visible:
///   `evaluate` requires every word of a term via `contains`, so it throws the
///   candidates away again and the search still returns nothing. This is the
///   seam between candidate lookup and post-filter that has leaked three times
///   already (#10, the diacritic fold, the starred terms). Rewriting once and
///   handing the SAME tree to both stages is what closes it.
///
/// Rules, in order of how much they protect:
///
/// * NEVER drop every word. If nothing known remains, the ORIGINAL tree is
///   returned and the search returns nothing, as before. An all-unknown query
///   must not turn into a match-everything query — that is a full scan of the
///   index on demand, from any client.
/// * Only in conjunctions. Inside an OR an unknown alternative already costs
///   nothing: the union simply gains an empty set. Rewriting there could only
///   turn a false alternative into a true one and make the OR match everything.
/// * Never on the negated side of NOT. A word there is an exclusion, not a
///   requirement; dropping it would broaden the search the other way round.
/// * Never a marked word. `*` and `^` terms are not index lookups in the first
///   place, so "unknown to the index" does not apply to them.
///
/// `is_known(token)` reports whether an index token has any posting. A word is
/// unknown if ANY of its tokens is unknown, because that is exactly the
/// condition under which it would have emptied the intersection.
pub fn drop_unknown_words(
    node: &SearchNode,
    is_known: &dyn Fn(&str) -> bool,
) -> (SearchNode, Vec<String>) {
    let mut dropped = Vec::new();
    match rewrite_conjunction(node, is_known, &mut dropped) {
        Some(tree) if !dropped.is_empty() => (tree, dropped),
        // Nothing dropped, or EVERYTHING was: keep the query as sent.
        _ => (node.clone(), Vec::new()),
    }
}

/// `None` means "this subtree was made of unknown words only and is removed
/// from the conjunction it sits in".
fn rewrite_conjunction(
    node: &SearchNode,
    is_known: &dyn Fn(&str) -> bool,
    dropped: &mut Vec<String>,
) -> Option<SearchNode> {
    match node {
        SearchNode::Term(s) => {
            // ⚠ CLASSIFY WORDS EXACTLY AS THE LOOKUP USES THEM, NOT BY A RULE OF
            //   OUR OWN. The candidate lookup tokenises the WHOLE term, and the
            //   tokenizer silently skips stop-words ("the", "and", "for") and
            //   one-character words. Those never emptied a search, so they are
            //   not ours to drop. The first version checked each word on its own
            //   through `tokenize_search_term`, whose fallback hands a skipped
            //   word back as a key; "the" then looked unknown, and on the live
            //   server 39% of searches were counted as rescued, most of them by
            //   dropping a stop-word that had never been looked up.
            //
            //   The one case where a skipped word IS the key: a term with no
            //   indexable word at all ("2", "a") is looked up whole, through
            //   that same fallback. If that key is unknown, the term emptied the
            //   search, and it is dropped as a unit.
            if crate::state::keyword_index::tokenize(s).is_empty() {
                let folded = crate::state::keyword_index::fold_for_match(s);
                let (core, anchored, starred) = parse_markers(folded.trim());
                if starred || anchored || core.is_empty() || core == "*" || core == "**" {
                    return Some(node.clone());
                }
                let key = s.trim().to_lowercase();
                if is_known(&key) {
                    return Some(node.clone());
                }
                dropped.push(s.trim().to_string());
                return None;
            }
            let mut kept: Vec<&str> = Vec::new();
            let mut lost: Vec<String> = Vec::new();
            for w in s.split_whitespace() {
                if word_is_unknown(w, is_known) {
                    lost.push(w.to_string());
                } else {
                    kept.push(w);
                }
            }
            if lost.is_empty() {
                return Some(node.clone());
            }
            dropped.extend(lost);
            if kept.is_empty() {
                None
            } else {
                Some(SearchNode::Term(kept.join(" ")))
            }
        }
        SearchNode::Bool(BoolOp::And, l, r) => {
            let nl = rewrite_conjunction(l, is_known, dropped);
            let nr = rewrite_conjunction(r, is_known, dropped);
            match (nl, nr) {
                (Some(a), Some(b)) => Some(SearchNode::Bool(BoolOp::And, Box::new(a), Box::new(b))),
                (Some(a), None) | (None, Some(a)) => Some(a),
                (None, None) => None,
            }
        }
        SearchNode::Bool(BoolOp::Not, l, r) => {
            // Only the positive side is a requirement. If it vanishes entirely
            // the NOT would stand alone and match everything except `r`, so keep
            // the original left side in that case.
            let before = dropped.len();
            match rewrite_conjunction(l, is_known, dropped) {
                Some(nl) => Some(SearchNode::Bool(BoolOp::Not, Box::new(nl), r.clone())),
                None => {
                    dropped.truncate(before);
                    Some(node.clone())
                }
            }
        }
        // OR, meta-tags and numeric constraints are left exactly as sent.
        _ => Some(node.clone()),
    }
}

fn word_is_unknown(word: &str, is_known: &dyn Fn(&str) -> bool) -> bool {
    let folded = crate::state::keyword_index::fold_for_match(word);
    let (core, anchored, starred) = parse_markers(&folded);
    if starred || anchored || core.is_empty() {
        return false;
    }
    // `tokenize`, not `tokenize_search_term`: inside a multi-word term a word the
    // tokenizer skips (stop-word, one character) is never a lookup key, so it
    // cannot be what emptied the search. See the warning in the Term arm above.
    let toks = crate::state::keyword_index::tokenize(core);
    if toks.is_empty() {
        return false;
    }
    toks.iter().any(|t| !is_known(t))
}

/// Walk the tree and collect leaf string terms (used as keywords for index lookup).
/// Skips Meta and Numeric nodes; the caller applies those as post-filters.
pub fn collect_terms(node: &SearchNode) -> Vec<String> {
    let mut out = Vec::new();
    walk_terms(node, &mut out, false);
    out
}

/// What the candidate set must contain, with the tree's shape preserved.
///
/// Each inner Vec is an OR group: a file qualifies if it holds ANY member. A
/// file must satisfy EVERY group. So `A AND (B OR C)` yields `[[A], [B, C]]`,
/// and the caller intersects the per-group unions.
///
/// ⚠ THIS EXISTS BECAUSE THE FLAT LIST SILENTLY LOST OR. `collect_terms` walks
///   And and Or identically, and the caller intersected the result — so every
///   branch of an OR was demanded at once. A client sending
///   `<series> AND (S01E05 OR 1x05 OR 01x05 OR 1x5 OR 05)`, which is what eMule,
///   aMule and the aMuTorrent bridge send for a television search, was asking
///   for a file holding all five. No file holds more than one. Every television
///   search against this server returned nothing, with no error to explain it.
pub fn collect_candidate_terms(node: &SearchNode) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    walk_groups(node, &mut out, false);
    out
}

/// The candidate lookup's groups, tokenised and ready for `find_grouped`.
///
/// ONE implementation for the TCP and UDP search paths. They used to carry a
/// copy each, identical line for line, and both had the same bug: see below.
///
/// ⚠ MARKERS BELONG TO WORDS, NOT TO TERMS. aMule sends a conjunction of plain
///   words as ONE string — `mark dvdr*` — and `*` is an ordinary word character
///   to its parser, so it arrives inside that string. This used to run
///   `parse_markers` on the whole string: the trailing star made the ENTIRE term
///   "starred", so it was dropped from the lookup, nothing was left to seed the
///   candidates, and every multi-word query containing a wildcard returned
///   nothing. Only a starred word typed on its own worked. The reference parses
///   markers per word, in `find_word`.
///
///   It went unnoticed because the test probe sent each word as its own tree
///   node — a shape no client produces for a conjunction.
pub fn candidate_groups(node: &SearchNode) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = Vec::new();
    for g in collect_candidate_terms(node) {
        // ⚠ A STARRED WORD IS NOT A CANDIDATE CONSTRAINT. The reference server
        //   excludes it from the keyword lookup and keeps it only as a filter;
        //   demanding it as an exact token is what made `1080*` return nothing.
        //   `evaluate` still applies it, so removing it here widens the
        //   candidate set and never narrows it.
        let g: Vec<String> = g
            .iter()
            .map(|t| without_starred_words(t))
            .filter(|t| !t.is_empty())
            .collect();
        if g.is_empty() {
            continue;
        }
        let is_or_group = g.len() > 1;
        let toks: Vec<Vec<String>> = g
            .iter()
            .map(|t| {
                crate::state::keyword_index::tokenize_search_term(t)
                    .into_iter()
                    .filter(|t| t != "*" && t != "**")
                    .collect::<Vec<String>>()
            })
            .collect();
        // ⚠ A GROUP OF ONE EXPANDS INTO SEVERAL GROUPS, NOT ONE BIGGER GROUP.
        //   A single term "ubuntu linux bible" tokenises into three words that
        //   must ALL match; in one group they would be alternatives, and the
        //   candidate set would be the union of three common words over the
        //   whole index — the regression that took the server from 3% to 92%
        //   CPU while every result stayed correct.
        if is_or_group {
            let flat: Vec<String> = toks.into_iter().flatten().collect();
            if !flat.is_empty() {
                out.push(flat);
            }
        } else {
            for t in toks.into_iter().flatten() {
                out.push(vec![t]);
            }
        }
    }
    out
}

/// The term with its starred words removed; anchored and plain words kept.
fn without_starred_words(t: &str) -> String {
    t.split_whitespace()
        .filter(|w| {
            let (core, _, starred) = parse_markers(w);
            !starred && !core.is_empty()
        })
        .collect::<Vec<&str>>()
        .join(" ")
}

fn walk_groups(node: &SearchNode, out: &mut Vec<Vec<String>>, in_negation: bool) {
    match node {
        SearchNode::Term(s) => {
            if !in_negation {
                out.push(vec![s.clone()]);
            }
        }
        SearchNode::Bool(op, l, r) => match op {
            BoolOp::And => {
                walk_groups(l, out, in_negation);
                walk_groups(r, out, in_negation);
            }
            BoolOp::Or => {
                if in_negation {
                    return;
                }
                // One group holding both sides' terms. An AND nested inside an
                // OR is flattened into that group, which WIDENS the candidate
                // set rather than narrowing it — `evaluate` still applies the
                // real condition afterwards, so a superset is safe and a subset
                // is not. That asymmetry is the rule for everything here.
                let mut flat = Vec::new();
                walk_terms(l, &mut flat, false);
                walk_terms(r, &mut flat, false);
                if !flat.is_empty() {
                    out.push(flat);
                }
            }
            BoolOp::Not => {
                walk_groups(l, out, in_negation);
                // The right side is negated: it must not constrain candidates.
                walk_groups(r, out, !in_negation);
            }
        },
        _ => {}
    }
}

fn walk_terms(node: &SearchNode, out: &mut Vec<String>, in_negation: bool) {
    match node {
        SearchNode::Term(s) => {
            if !in_negation {
                out.push(s.clone());
            }
        }
        SearchNode::Bool(op, l, r) => match op {
            BoolOp::And | BoolOp::Or => {
                walk_terms(l, out, in_negation);
                walk_terms(r, out, in_negation);
            }
            BoolOp::Not => {
                walk_terms(l, out, in_negation);
                // right side is negated
                walk_terms(r, out, !in_negation);
            }
        },
        _ => {}
    }
}

/// Evaluate the tree against a candidate file. Returns true if the file matches.
/// Classify a filename by extension and check if it matches an eD2k file-type
/// category ("Audio", "Video", "Pro", "Doc", "Image", "Arc", "Iso").
/// This mirrors how Lugdunum and other eD2k servers handle FT_FILETYPE search
/// constraints — they map the extension to a category, since the server only
/// stores filenames, not media metadata.
// ── Extension sets per eD2k file-type category ──────────────────────────
// Shared by the numeric classifier and the string matcher, so the two cannot
// disagree about what counts as a video.
const AUDIO_EXT: &[&str] = &[
    "mp3", "mp2", "m4a", "wav", "wma", "ogg", "flac", "aac", "ac3", "aif", "aiff", "ape", "mpc",
    "mid", "midi", "ra", "wv", "opus",
];
const VIDEO_EXT: &[&str] = &[
    "avi", "mpg", "mpeg", "mp4", "mkv", "wmv", "mov", "flv", "ogm", "m4v", "rm", "rmvb", "vob",
    "asf", "divx", "xvid", "3gp", "ts", "m2ts", "webm", "mpe", "ifo",
];
const IMAGE_EXT: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "psd", "ico", "svg", "raw", "cr2",
    "nef",
];
const PROGRAM_EXT: &[&str] = &[
    "exe", "msi", "bat", "com", "dll", "deb", "rpm", "dmg", "apk", "jar", "app", "bin", "run",
];
const DOCUMENT_EXT: &[&str] = &[
    "doc", "docx", "pdf", "txt", "rtf", "odt", "xls", "xlsx", "ppt", "pptx", "epub", "mobi",
    "djvu", "chm", "tex", "ods", "odp",
];
const ARCHIVE_EXT: &[&str] = &[
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "ace", "arj", "cab", "lzh", "z", "tgz", "zst",
];
const CDIMAGE_EXT: &[&str] = &["iso", "nrg", "cue", "img", "bin", "mdf", "ccd", "cdi"];

/// eD2k numeric file-type IDs, as defined by eserver 17.6+ and mirrored in
/// eMule's `EED2KFileType` (OtherFunctions.h:442). These are what the
/// `SRV_TCPFLG_TYPETAGINTEGER` capability bit promises: `FT_FILETYPE` delivered
/// as an integer rather than as the older "Video"/"Audio" strings.
pub mod ed2k_file_type {
    pub const ANY: u32 = 0;
    pub const AUDIO: u32 = 1;
    pub const VIDEO: u32 = 2;
    pub const IMAGE: u32 = 3;
    pub const PROGRAM: u32 = 4;
    pub const DOCUMENT: u32 = 5;
    pub const ARCHIVE: u32 = 6;
    pub const CDIMAGE: u32 = 7;
    pub const EMULECOLLECTION: u32 = 8;
}

/// Classify a filename into an eD2k file-type ID by its extension.
///
/// Returns `ANY` (0) when the extension is unknown or absent, which is the
/// "no opinion" value — a client filtering by type treats it as non-matching
/// rather than as a wrong answer.
///
/// The server stores filenames and nothing else, so extension is all there is
/// to go on; this is exactly how Lugdunum does it too.
pub fn ed2k_file_type_id(name_lower: &str) -> u32 {
    use ed2k_file_type as t;
    let ext = match name_lower.rsplit('.').next() {
        Some(e) if e != name_lower => e,
        _ => return t::ANY,
    };
    // Order matters where an extension appears in two tables: "bin" is both a
    // raw executable and a CD-image track, and PROGRAM is checked first. Either
    // answer is defensible; what matters is that it is stable, since a client
    // filtering by type will not find the file under the other category.
    for (cat, set) in [
        (t::AUDIO, AUDIO_EXT),
        (t::VIDEO, VIDEO_EXT),
        (t::IMAGE, IMAGE_EXT),
        (t::PROGRAM, PROGRAM_EXT),
        (t::DOCUMENT, DOCUMENT_EXT),
        (t::ARCHIVE, ARCHIVE_EXT),
        (t::CDIMAGE, CDIMAGE_EXT),
    ] {
        if set.contains(&ext) {
            return cat;
        }
    }
    if ext == "emulecollection" {
        return t::EMULECOLLECTION;
    }
    t::ANY
}

fn file_type_matches(name_lower: &str, type_value: &str) -> bool {
    let ext = match name_lower.rsplit('.').next() {
        Some(e) if e != name_lower => e, // require an actual "." in the name
        _ => return false,
    };

    // Extension sets per eD2k file-type category.
    let set: &[&str] = match type_value {
        "audio" => AUDIO_EXT,
        "video" => VIDEO_EXT,
        "image" => IMAGE_EXT,
        "pro" => PROGRAM_EXT,
        "doc" => DOCUMENT_EXT,
        "arc" => ARCHIVE_EXT,
        "iso" => CDIMAGE_EXT,
        // Unknown category — don't filter the file out.
        _ => return true,
    };
    set.contains(&ext)
}

/// One (already folded) query word against a folded name.
///
/// Wildcard and anchor markers, as the reference server parses them: `find_word`
/// in the Lugdunum source sets one flag bit for a `*` at either end of a word
/// and another for a leading `^`, strips them, and a starred word is NOT fed to
/// the keyword index — it survives only as a string filter over candidates the
/// other words produced. The anchor selects a match at the start of a word
/// rather than anywhere in the name.
///
/// A plain word is matched with `contains`, NOT as a whole token. That keeps
/// single-word behaviour exactly as it was: "linux" goes on matching
/// "linuxmint", and a query that worked before cannot start returning less.
fn word_matches(w: &str, name_lower: &str) -> bool {
    // "*" or "**" alone: eMule sends this for a "list everything" search.
    if w == "*" || w == "**" {
        return true;
    }
    let (core, anchored, starred) = parse_markers(w);
    if core.is_empty() {
        // A word that is nothing but markers constrains nothing.
        return true;
    }
    if anchored {
        // At the start of the name, or at the start of any word in it — a
        // leading `^` anchors to a word, not to the whole string, or `^dvd`
        // would only ever match a file whose name begins with it.
        return name_lower.starts_with(core)
            || name_lower
                .split(|c: char| !c.is_alphanumeric())
                .any(|x| x.starts_with(core));
    }
    if starred {
        return name_lower.contains(core);
    }
    name_lower.contains(w)
}

pub fn evaluate(node: &SearchNode, name_lower: &str, size: u64) -> bool {
    match node {
        SearchNode::Term(t) => {
            // Wildcard term: "*" or "**" matches every file. eMule sends this
            // for a "list everything" search. Without this check, contains("*")
            // is always false and the wildcard search returns nothing.
            // ⚠ FOLDED, NOT MERELY LOWERCASED — and the caller must hand us a
            //   folded `name_lower` to match. The candidate lookup folds
            //   diacritics, so `château` finds a file named `chateau`; if this
            //   predicate then compares the raw accented term against the raw
            //   name it throws that file away again, and the search returns
            //   nothing while the index did its job perfectly.
            //
            //   This is the second time the same seam has leaked. The comment
            //   below records #10, where the candidate lookup was taught to
            //   split multi-word terms and this predicate was left comparing the
            //   unsplit string. Whatever the index does to a token, this has to
            //   do to the term.
            let tl = crate::state::keyword_index::fold_for_match(t);
            // A term is not necessarily one word. Some clients send a whole
            // query as a single node, and testing it as one substring makes the
            // WORD ORDER significant: "Ubuntu Linux Bible" contains the phrase
            // "ubuntu linux" and not "linux ubuntu", so the same two words
            // returned 12 results one way round and 3 the other. Lugdunum
            // returns the same count either way. So every word must appear, in
            // any order — the second half of the #10 fix.
            //
            // ⚠ AND EACH WORD CARRIES ITS OWN MARKERS. `mark ^dvdrip` used to be
            //   tested for the literal substring `^dvdrip`, and `mark dvdr*` as
            //   the phrase `mark dvdr`, because `*` and `^` were only recognised
            //   at the ends of the whole string. See `candidate_groups`.
            tl.split_whitespace().all(|w| word_matches(w, name_lower))
        }
        SearchNode::Meta { tag_name, value } => {
            // tag_name is usually a 1-char string holding a byte ID (eMule sends
            // the meta-tag ID as a 1-byte name). Match the known search tags:
            //   FT_FILETYPE   (0x03) — value is "Audio"/"Video"/"Pro"/"Doc"/etc.
            //   FT_FILEFORMAT (0x04) — value is a file extension like "avi"
            let tag_id = tag_name.id().unwrap_or(0);
            // Folded for the same reason as the term above: the name we are
            // handed is folded, so an unfolded value would never match one.
            let val_lower = crate::state::keyword_index::fold_for_match(value);

            match tag_id {
                // FT_FILETYPE — classify by the file's extension
                0x03 => file_type_matches(name_lower, &val_lower),
                // FT_FILEFORMAT — the file's extension must equal `value`
                0x04 => name_lower
                    .rsplit('.')
                    .next()
                    .map(|ext| ext == val_lower)
                    .unwrap_or(false),
                // Unknown meta tag — treat the value as a filename substring,
                // but if that fails, be permissive rather than dropping the file.
                _ => name_lower.contains(&val_lower),
            }
        }
        SearchNode::Numeric {
            tag_name,
            op,
            value,
        } => {
            // eMule sends the meta-tag ID as a 1-byte name. FT_FILESIZE = 0x02.
            // Some clients send the literal string "size". Handle both.
            let is_filesize = tag_name.is(0x02, &["size", "filesize"]);

            if is_filesize {
                op.matches_u64(size, *value)
            } else {
                // FT_SOURCES, FT_COMPLETE_SOURCES, bitrate, length, etc. — we
                // don't track these per file. Be permissive (don't drop the file).
                true
            }
        }
        SearchNode::Bool(op, l, r) => match op {
            BoolOp::And => evaluate(l, name_lower, size) && evaluate(r, name_lower, size),
            BoolOp::Or => evaluate(l, name_lower, size) || evaluate(r, name_lower, size),
            BoolOp::Not => evaluate(l, name_lower, size) && !evaluate(r, name_lower, size),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc_str(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + s.len());
        out.extend_from_slice(&(s.len() as u16).to_le_bytes());
        out.extend_from_slice(s.as_bytes());
        out
    }

    #[test]
    fn a_multi_word_term_ignores_word_order() {
        // Issue #10, second half. The candidate lookup was fixed to split terms,
        // but this predicate still tested the unsplit string as one substring —
        // so "Ubuntu Linux Bible" matched "ubuntu linux" and not "linux ubuntu",
        // and the same two words returned 12 results one way and 3 the other.
        let name = "ubuntu linux bible, 10ed, clinton, negus, 2021.pdf";
        for q in ["ubuntu linux", "linux ubuntu", "bible ubuntu", "linux 2021"] {
            assert!(
                evaluate(&SearchNode::Term(q.to_string()), name, 0),
                "{q} must match regardless of order"
            );
        }
        // A word that is absent still fails the whole term.
        assert!(!evaluate(
            &SearchNode::Term("ubuntu fedora".to_string()),
            name,
            0
        ));
    }

    #[test]
    fn single_word_terms_are_untouched() {
        // Each word is matched with `contains`, not as a whole token, so a
        // one-word query behaves exactly as before — including matching inside a
        // longer word. A query that worked must not start returning less.
        assert!(evaluate(
            &SearchNode::Term("linux".to_string()),
            "linuxmint tutorial.pdf",
            0
        ));
        assert!(evaluate(
            &SearchNode::Term("mint".to_string()),
            "linuxmint tutorial.pdf",
            0
        ));
        assert!(!evaluate(
            &SearchNode::Term("fedora".to_string()),
            "linuxmint tutorial.pdf",
            0
        ));
    }

    #[test]
    fn wildcards_still_match_everything() {
        for w in ["*", "**"] {
            assert!(evaluate(
                &SearchNode::Term(w.to_string()),
                "anything.avi",
                0
            ));
        }
    }

    #[test]
    fn parse_simple_term() {
        // [01] [05 00] "linux"
        let mut data = vec![NODE_STRING];
        data.extend(enc_str("linux"));
        let tree = parse(&data).unwrap();
        assert_eq!(tree, SearchNode::Term("linux".into()));
    }

    #[test]
    fn parse_and_two_terms() {
        // [00] [00] [01 "linux"] [01 "debian"]
        let mut data = vec![NODE_BOOL, OP_AND, NODE_STRING];
        data.extend(enc_str("linux"));
        data.push(NODE_STRING);
        data.extend(enc_str("debian"));
        let tree = parse(&data).unwrap();
        match tree {
            SearchNode::Bool(BoolOp::And, l, r) => {
                assert_eq!(*l, SearchNode::Term("linux".into()));
                assert_eq!(*r, SearchNode::Term("debian".into()));
            }
            _ => panic!("expected AND tree"),
        }
    }

    #[test]
    fn parse_size_constraint() {
        // numeric32: value=1000000, op=GT, tag_name="size"
        let mut data = vec![NODE_NUMERIC32];
        data.extend_from_slice(&1_000_000u32.to_le_bytes());
        data.push(CMP_GT);
        data.extend(enc_str("size"));
        let tree = parse(&data).unwrap();
        match tree {
            SearchNode::Numeric { op, value, .. } => {
                assert_eq!(op, CmpOp::Gt);
                assert_eq!(value, 1_000_000);
            }
            _ => panic!("expected numeric"),
        }
    }

    #[test]
    fn rejects_too_deep() {
        // Build 30 nested AND nodes manually
        let mut data = Vec::new();
        for _ in 0..30 {
            data.push(NODE_BOOL);
            data.push(OP_AND);
        }
        data.push(NODE_STRING);
        data.extend(enc_str("a"));
        data.push(NODE_STRING);
        data.extend(enc_str("b"));
        // Will fail at depth 24
        assert!(parse(&data).is_err());
    }

    #[test]
    fn collect_terms_skips_negated() {
        // (linux AND NOT windows)
        let tree = SearchNode::Bool(
            BoolOp::Not,
            Box::new(SearchNode::Term("linux".into())),
            Box::new(SearchNode::Term("windows".into())),
        );
        let terms = collect_terms(&tree);
        assert_eq!(terms, vec!["linux".to_string()]);
    }

    #[test]
    fn evaluates_complex() {
        // (linux AND NOT windows) with size > 1000
        let inner = SearchNode::Bool(
            BoolOp::Not,
            Box::new(SearchNode::Term("linux".into())),
            Box::new(SearchNode::Term("windows".into())),
        );
        let tree = SearchNode::Bool(
            BoolOp::And,
            Box::new(inner),
            Box::new(SearchNode::Numeric {
                tag_name: SearchTag::Name("size".into()),
                op: CmpOp::Gt,
                value: 1000,
            }),
        );
        assert!(evaluate(&tree, "linux mint installer", 5000));
        assert!(!evaluate(&tree, "linux mint", 100)); // size too small
        assert!(!evaluate(&tree, "windows 11 iso", 5000)); // matches windows
    }
}

#[cfg(test)]
mod filetype_tests {
    use super::*;

    #[test]
    fn numeric_file_type_ids_match_the_ed2k_table() {
        use ed2k_file_type as t;
        // Values are fixed by eserver 17.6+ / eMule's EED2KFileType — a client
        // filtering by type compares against these exact numbers.
        assert_eq!(ed2k_file_type_id("song.mp3"), t::AUDIO);
        assert_eq!(ed2k_file_type_id("movie.mkv"), t::VIDEO);
        assert_eq!(ed2k_file_type_id("photo.jpeg"), t::IMAGE);
        assert_eq!(ed2k_file_type_id("setup.exe"), t::PROGRAM);
        assert_eq!(ed2k_file_type_id("book.pdf"), t::DOCUMENT);
        assert_eq!(ed2k_file_type_id("pack.rar"), t::ARCHIVE);
        assert_eq!(ed2k_file_type_id("disc.iso"), t::CDIMAGE);
        assert_eq!(
            ed2k_file_type_id("list.emulecollection"),
            t::EMULECOLLECTION
        );

        // ANY means "no opinion", and the caller must not emit a tag for it —
        // a literal 0 would read as a category matching nothing.
        assert_eq!(ed2k_file_type_id("readme"), t::ANY, "no extension at all");
        assert_eq!(ed2k_file_type_id("data.qqq"), t::ANY, "unknown extension");
        assert_eq!(
            ed2k_file_type_id(".hidden"),
            t::ANY,
            "dotfile, not an extension"
        );

        // Ambiguous extension resolves to the first table that lists it.
        assert_eq!(ed2k_file_type_id("firmware.bin"), t::PROGRAM);
    }

    #[test]
    fn numeric_and_string_classifiers_agree() {
        // The two share one set of extension tables precisely so they cannot
        // drift; this pins that.
        use ed2k_file_type as t;
        for (name, cat, s) in [
            ("a.mp3", t::AUDIO, "audio"),
            ("a.avi", t::VIDEO, "video"),
            ("a.png", t::IMAGE, "image"),
            ("a.exe", t::PROGRAM, "pro"),
            ("a.epub", t::DOCUMENT, "doc"),
            ("a.7z", t::ARCHIVE, "arc"),
        ] {
            assert_eq!(ed2k_file_type_id(name), cat);
            assert!(file_type_matches(name, s), "{name} vs {s}");
        }
    }

    #[test]
    fn file_type_by_extension() {
        // FT_FILETYPE meta tag (id 0x02 as 1-char string) — eMule sends tag
        // name as a single byte. Here we test the classifier directly.
        assert!(file_type_matches("cool.movie.avi", "video"));
        assert!(file_type_matches("song.mp3", "audio"));
        assert!(file_type_matches("ubuntu.iso", "iso"));
        assert!(file_type_matches("setup.exe", "pro"));
        assert!(file_type_matches("book.pdf", "doc"));
        assert!(!file_type_matches("song.mp3", "video"));
        assert!(!file_type_matches("noextension", "video"));
        // Unknown category is permissive
        assert!(file_type_matches("whatever.xyz", "unknowncat"));
    }

    #[test]
    fn search_with_filetype_meta() {
        // Tree: AND( Term("ubuntu"), Meta{tag=[0x03], value="Iso"} )
        // File "ubuntu-22.04.iso" should match: name has "ubuntu" + ext "iso"
        let tree = SearchNode::Bool(
            BoolOp::And,
            Box::new(SearchNode::Term("ubuntu".into())),
            Box::new(SearchNode::Meta {
                tag_name: SearchTag::Id(0x03),
                value: "Iso".into(),
            }),
        );
        assert!(
            evaluate(&tree, "ubuntu-22.04.iso", 1_000_000),
            "ubuntu iso should match type=Iso search"
        );
        assert!(
            !evaluate(&tree, "ubuntu-manual.pdf", 1000),
            "ubuntu pdf should NOT match type=Iso search"
        );
    }

    /// eMule's meta-tag name: length 1, then the raw tag ID.
    fn enc_tag_id(id: u8) -> Vec<u8> {
        vec![1, 0, id]
    }

    fn enc_str(s: &str) -> Vec<u8> {
        let mut out = (s.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(s.as_bytes());
        out
    }

    #[test]
    fn media_tag_searches_parse_issue_24() {
        // AND( "beatles", bitrate >= 128 ), bitrate tag 0xD4 as eMule sends it.
        let mut data = vec![NODE_BOOL, OP_AND, NODE_STRING];
        data.extend(enc_str("beatles"));
        data.push(NODE_NUMERIC32);
        data.extend_from_slice(&128u32.to_le_bytes());
        data.push(CMP_GE);
        data.extend(enc_tag_id(0xD4));
        let tree = parse(&data).expect("a lone byte >= 0x80 is a tag ID, not text");
        match &tree {
            SearchNode::Bool(BoolOp::And, _, r) => assert_eq!(
                **r,
                SearchNode::Numeric { tag_name: SearchTag::Id(0xD4), op: CmpOp::Ge, value: 128 }
            ),
            other => panic!("unexpected tree {other:?}"),
        }
        // Bitrate is not tracked per file: the constraint does not drop files.
        assert!(evaluate(&tree, "beatles - help.mp3", 4_000_000));

        // Artist (0xD0) as a string meta node.
        let mut data = vec![NODE_META];
        data.extend(enc_str("Beatles"));
        data.extend(enc_tag_id(0xD0));
        assert_eq!(
            parse(&data).unwrap(),
            SearchNode::Meta { tag_name: SearchTag::Id(0xD0), value: "Beatles".into() }
        );

        // Every media ID 0xD0-0xD5 parses, as a numeric and as a meta node.
        for id in 0xD0..=0xD5u8 {
            let mut n = vec![NODE_NUMERIC32, 1, 0, 0, 0, CMP_GT];
            n.extend(enc_tag_id(id));
            assert!(parse(&n).is_ok(), "numeric 0x{id:02x}");
            let mut m = vec![NODE_META];
            m.extend(enc_str("x"));
            m.extend(enc_tag_id(id));
            assert!(parse(&m).is_ok(), "meta 0x{id:02x}");
        }
    }

    #[test]
    fn longer_tag_names_stay_names() {
        let mut data = vec![NODE_NUMERIC32];
        data.extend_from_slice(&5u32.to_le_bytes());
        data.push(CMP_GT);
        data.extend(enc_str("size"));
        match parse(&data).unwrap() {
            SearchNode::Numeric { tag_name, .. } => {
                assert_eq!(tag_name, SearchTag::Name("size".into()));
                assert!(tag_name.is(0x02, &["size"]));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_bad_byte_in_a_term_no_longer_fails_the_request() {
        let mut data = vec![NODE_STRING, 4, 0];
        data.extend_from_slice(b"ab\xffc");
        match parse(&data).unwrap() {
            SearchNode::Term(t) => assert_eq!(t, "ab\u{FFFD}c"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn search_filesize_byte_id() {
        // Numeric with tag_name = 1-char string holding byte 0x02 (FT_FILESIZE)
        let tree = SearchNode::Numeric {
            tag_name: SearchTag::Id(0x02),
            op: CmpOp::Ge,
            value: 1000,
        };
        assert!(evaluate(&tree, "anyfile.bin", 5000));
        assert!(!evaluate(&tree, "anyfile.bin", 500));
    }
    #[test]
    fn the_post_filter_folds_the_same_way_the_index_does() {
        // The seam that leaked twice. The candidate lookup folds diacritics, so
        // `château` finds a file named `chateau`; if this predicate compares the
        // raw accented term against the raw name it discards the file again and
        // the search returns nothing while the index did its job perfectly.
        //
        // The caller hands us a FOLDED name, so these tests do too.
        let folded_name =
            crate::state::keyword_index::fold_for_match("Le Chateau dans le Ciel 1986");
        for q in ["chateau", "château", "CHÂTEAU", "chateau\u{301}"] {
            assert!(
                evaluate(&SearchNode::Term(q.to_string()), &folded_name, 0),
                "{q} should match a folded name"
            );
        }
        assert!(!evaluate(
            &SearchNode::Term("castle".to_string()),
            &folded_name,
            0
        ));
    }

    #[test]
    fn wildcard_and_anchor_markers_are_parsed_off_the_term() {
        assert_eq!(parse_markers("1080*"), ("1080", false, true));
        assert_eq!(parse_markers("*1080"), ("1080", false, true));
        assert_eq!(parse_markers("*1080*"), ("1080", false, true));
        assert_eq!(parse_markers("^dvd"), ("dvd", true, false));
        assert_eq!(parse_markers("^dvd*"), ("dvd", true, true));
        assert_eq!(parse_markers("plain"), ("plain", false, false));
        // Nothing but markers constrains nothing.
        assert_eq!(parse_markers("*").0, "");
        assert_eq!(parse_markers("**").0, "");
    }

    #[test]
    fn a_starred_term_matches_a_longer_token() {
        // The compatibility gap: `1080*` tokenised to `1080`, was demanded as
        // an exact keyword, and matched nothing because the file's token is
        // `1080p`. The reference server drops a starred term from the lookup
        // and applies it as a filter, which is what this asserts.
        let name =
            crate::state::keyword_index::fold_for_match("Some.Title.S01E08.1080p.WEB-DL.mkv");
        assert!(evaluate(&SearchNode::Term("1080*".into()), &name, 0));
        assert!(evaluate(&SearchNode::Term("s01*".into()), &name, 0));
        // A star does not turn the term into "match anything".
        assert!(!evaluate(&SearchNode::Term("2160*".into()), &name, 0));
    }

    #[test]
    fn an_anchor_matches_the_start_of_a_word_not_the_middle() {
        // `^` anchors to a word, not to the whole string — otherwise `^dvd`
        // could only ever match a file whose NAME begins with it, which is not
        // what a user means by it.
        let name = crate::state::keyword_index::fold_for_match("Some.Title.dvdrip.avi");
        assert!(evaluate(&SearchNode::Term("^dvd".into()), &name, 0));
        assert!(evaluate(&SearchNode::Term("^some".into()), &name, 0));
        // An infix must not match an anchored term, which is the one thing the
        // reporter's measurements were unambiguous about.
        assert!(!evaluate(&SearchNode::Term("^rip".into()), &name, 0));
        assert!(!evaluate(&SearchNode::Term("^itle".into()), &name, 0));
    }

    // ─── drop_unknown_words ───────────────────────────────────────────────

    fn known(tok: &str) -> bool {
        // A stand-in index: these tokens exist, everything else does not.
        matches!(tok, "alpha" | "bravo" | "show" | "s01e05" | "1x05" | "mkv")
    }

    fn term(s: &str) -> SearchNode {
        SearchNode::Term(s.to_string())
    }
    fn and(l: SearchNode, r: SearchNode) -> SearchNode {
        SearchNode::Bool(BoolOp::And, Box::new(l), Box::new(r))
    }
    fn or(l: SearchNode, r: SearchNode) -> SearchNode {
        SearchNode::Bool(BoolOp::Or, Box::new(l), Box::new(r))
    }
    fn not(l: SearchNode, r: SearchNode) -> SearchNode {
        SearchNode::Bool(BoolOp::Not, Box::new(l), Box::new(r))
    }

    #[test]
    fn an_unknown_word_in_a_one_string_query_is_dropped() {
        // The shape aMule actually sends for a conjunction: one string.
        let (t, dropped) = drop_unknown_words(&term("alpha zzznope"), &known);
        assert_eq!(t, term("alpha"));
        assert_eq!(dropped, vec!["zzznope"]);
    }

    #[test]
    fn an_unknown_word_as_its_own_and_operand_is_dropped() {
        let (t, dropped) = drop_unknown_words(&and(term("alpha"), term("zzznope")), &known);
        assert_eq!(t, term("alpha"));
        assert_eq!(dropped, vec!["zzznope"]);
    }

    #[test]
    fn a_query_of_only_unknown_words_is_left_as_sent() {
        // The guard that matters most: dropping everything would leave a query
        // that matches everything — a full index scan, on demand, from anyone.
        for q in [
            term("zzznope"),
            term("zzznope qqqnope"),
            and(term("zzznope"), term("qqqnope")),
        ] {
            let (t, dropped) = drop_unknown_words(&q, &known);
            assert_eq!(t, q);
            assert!(dropped.is_empty());
        }
    }

    #[test]
    fn an_or_is_never_rewritten() {
        // An unknown alternative already costs nothing in a union. Treating it
        // as satisfied would make the OR match everything.
        let q = or(term("alpha"), term("zzznope"));
        let (t, dropped) = drop_unknown_words(&q, &known);
        assert_eq!(t, q);
        assert!(dropped.is_empty());
    }

    #[test]
    fn the_negated_side_is_never_rewritten() {
        let q = not(term("alpha"), term("zzznope"));
        let (t, dropped) = drop_unknown_words(&q, &known);
        assert_eq!(t, q);
        assert!(dropped.is_empty());

        // And a NOT whose positive side is entirely unknown keeps it, or the
        // query would become "everything except bravo".
        let q = not(term("zzznope"), term("bravo"));
        let (t, dropped) = drop_unknown_words(&q, &known);
        assert_eq!(t, q);
        assert!(dropped.is_empty());
    }

    #[test]
    fn a_marked_word_is_not_an_index_lookup_and_is_kept() {
        let (t, dropped) = drop_unknown_words(&term("alpha zzz*"), &known);
        assert_eq!(t, term("alpha zzz*"));
        assert!(dropped.is_empty());
        let (t, _) = drop_unknown_words(&term("alpha ^zzz"), &known);
        assert_eq!(t, term("alpha ^zzz"));
    }

    #[test]
    fn a_television_search_keeps_its_episode_alternatives() {
        // What aMuTorrent sends, with a typo in the title. The typo goes; the
        // OR group of episode spellings is untouched, unknown members included.
        let episodes = or(or(term("S01E05"), term("1x05")), term("01x05"));
        let q = and(term("show typpo"), episodes.clone());
        let (t, dropped) = drop_unknown_words(&q, &known);
        assert_eq!(t, and(term("show"), episodes));
        assert_eq!(dropped, vec!["typpo"]);
    }

    #[test]
    fn nothing_unknown_means_nothing_changes() {
        let q = and(term("alpha bravo"), or(term("s01e05"), term("1x05")));
        let (t, dropped) = drop_unknown_words(&q, &known);
        assert_eq!(t, q);
        assert!(dropped.is_empty());
    }

    #[test]
    fn the_rewritten_tree_is_what_evaluate_needs() {
        // Why the rewrite exists at all. On the ORIGINAL tree `evaluate` rejects
        // the file, because it demands every word of the term — so dropping the
        // word from the candidate lookup alone would change nothing visible.
        let name = "alpha one.mkv";
        let original = term("alpha zzznope");
        assert!(!evaluate(&original, name, 0));
        let (rewritten, _) = drop_unknown_words(&original, &known);
        assert!(evaluate(&rewritten, name, 0));
    }
}

#[cfg(test)]
mod drop_unknown_classification {
    use super::*;

    fn known(tok: &str) -> bool {
        matches!(tok, "lord" | "of" | "rings" | "rocky" | "alpha")
    }

    #[test]
    fn a_stop_word_is_not_dropped_because_it_was_never_looked_up() {
        // The bug the live counter exposed: "the" is skipped by the tokenizer,
        // so it never emptied a search, and must not be counted as rescued.
        let q = SearchNode::Term("lord of the rings".into());
        let (t, dropped) = drop_unknown_words(&q, &known);
        assert_eq!(t, q);
        assert!(
            dropped.is_empty(),
            "stop-word counted as dropped: {dropped:?}"
        );
    }

    #[test]
    fn a_one_character_word_inside_a_longer_term_is_not_dropped() {
        let q = SearchNode::Term("rocky 2".into());
        let (t, dropped) = drop_unknown_words(&q, &known);
        assert_eq!(t, q);
        assert!(dropped.is_empty());
    }

    #[test]
    fn a_term_with_no_indexable_word_is_dropped_as_a_unit() {
        // eMule's tree form: AND(rocky, 2). "2" alone is looked up whole through
        // the tokenizer's fallback, is unknown, and used to empty the search.
        let q = SearchNode::Bool(
            BoolOp::And,
            Box::new(SearchNode::Term("rocky".into())),
            Box::new(SearchNode::Term("2".into())),
        );
        let (t, dropped) = drop_unknown_words(&q, &known);
        assert_eq!(t, SearchNode::Term("rocky".into()));
        assert_eq!(dropped, vec!["2"]);
    }

    #[test]
    fn a_short_starred_term_is_kept() {
        let q = SearchNode::Bool(
            BoolOp::And,
            Box::new(SearchNode::Term("alpha".into())),
            Box::new(SearchNode::Term("a*".into())),
        );
        let (t, dropped) = drop_unknown_words(&q, &known);
        assert_eq!(t, q);
        assert!(dropped.is_empty());
    }

    #[test]
    fn a_real_unknown_word_is_still_dropped() {
        let (t, dropped) =
            drop_unknown_words(&SearchNode::Term("lord of the zzqtypo".into()), &known);
        assert_eq!(t, SearchNode::Term("lord of the".into()));
        assert_eq!(dropped, vec!["zzqtypo"]);
    }
}

#[cfg(test)]
mod markers_are_per_word {
    //! aMule sends `mark dvdr*` as ONE string. Markers used to be read at the
    //! ends of the whole string, so every multi-word query with a wildcard or
    //! an anchor returned nothing. Found by switching the test probe to the
    //! shape clients actually send.
    use super::*;

    fn t(s: &str) -> SearchNode {
        SearchNode::Term(s.into())
    }

    #[test]
    fn a_starred_word_leaves_the_lookup_but_the_other_words_stay() {
        assert_eq!(
            candidate_groups(&t("mark dvdr*")),
            vec![vec!["mark".to_string()]]
        );
        assert_eq!(
            candidate_groups(&t("mark bundle xvidqual*")),
            vec![vec!["mark".to_string()], vec!["bundle".to_string()]]
        );
    }

    #[test]
    fn an_anchored_word_is_still_looked_up() {
        assert_eq!(
            candidate_groups(&t("mark ^dvdrip")),
            vec![vec!["mark".to_string()], vec!["dvdrip".to_string()]]
        );
    }

    #[test]
    fn a_term_of_only_starred_words_contributes_no_group() {
        assert!(candidate_groups(&t("dvdr* xvid*")).is_empty());
    }

    #[test]
    fn evaluate_applies_the_star_to_its_own_word() {
        let name = "mark dvdrip xvidquality bundle";
        assert!(evaluate(&t("mark dvdr*"), name, 0));
        assert!(evaluate(&t("mark bundle xvidqual*"), name, 0));
        assert!(
            !evaluate(&t("mark zzzq*"), name, 0),
            "a star is not match-anything"
        );
    }

    #[test]
    fn evaluate_applies_the_anchor_to_its_own_word() {
        let name = "mark dvdrip xvidquality bundle";
        assert!(evaluate(&t("mark ^dvdrip"), name, 0));
        assert!(
            !evaluate(&t("mark ^vidrip"), name, 0),
            "an anchor rejects an infix"
        );
    }

    #[test]
    fn single_words_behave_exactly_as_before() {
        let name = "mark dvdrip xvidquality bundle";
        assert!(evaluate(&t("dvdr*"), name, 0));
        assert!(evaluate(&t("^dvdrip"), name, 0));
        assert!(!evaluate(&t("^vidrip"), name, 0));
        assert!(evaluate(&t("*"), name, 0));
        assert!(
            evaluate(&t("linux"), "linuxmint 22.iso", 0),
            "plain words still use contains"
        );
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchNode {
    /// Boolean combinator with two operands
    Bool(BoolOp, Box<SearchNode>, Box<SearchNode>),
    /// String term: must be a token in the filename
    Term(String),
    /// Meta-tag string: tag_name = value (e.g. type="Video")
    Meta { tag_name: String, value: String },
    /// Numeric constraint on a tag (size, bitrate, length…)
    Numeric {
        tag_name: String,
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
            let tag_name = read_short_string(buf)?;
            Ok(SearchNode::Meta { tag_name, value })
        }
        NODE_NUMERIC32 => {
            if buf.len() < 4 {
                bail!("numeric32 truncated");
            }
            let value =
                u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
            *buf = &buf[4..];
            let op = read_cmp_op(buf)?;
            let tag_name = read_short_string(buf)?;
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
            let tag_name = read_short_string(buf)?;
            Ok(SearchNode::Numeric {
                tag_name,
                op,
                value,
            })
        }
        other => Err(anyhow!("unknown node type 0x{other:02x}")),
    }
}

fn read_short_string(buf: &mut &[u8]) -> Result<String> {
    if buf.len() < 2 {
        bail!("string length prefix missing");
    }
    let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    *buf = &buf[2..];
    if buf.len() < len {
        bail!("string body truncated ({} of {} bytes)", buf.len(), len);
    }
    let s = std::str::from_utf8(&buf[..len])
        .map_err(|e| anyhow!("invalid utf-8 in search term: {e}"))?
        .to_string();
    *buf = &buf[len..];
    Ok(s)
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

/// Walk the tree and collect leaf string terms (used as keywords for index lookup).
/// Skips Meta and Numeric nodes; the caller applies those as post-filters.
pub fn collect_terms(node: &SearchNode) -> Vec<String> {
    let mut out = Vec::new();
    walk_terms(node, &mut out, false);
    out
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
fn file_type_matches(name_lower: &str, type_value: &str) -> bool {
    let ext = match name_lower.rsplit('.').next() {
        Some(e) if e != name_lower => e, // require an actual "." in the name
        _ => return false,
    };

    // Extension sets per eD2k file-type category.
    const AUDIO: &[&str] = &[
        "mp3", "mp2", "m4a", "wav", "wma", "ogg", "flac", "aac", "ac3",
        "aif", "aiff", "ape", "mpc", "mid", "midi", "ra", "wv", "opus",
    ];
    const VIDEO: &[&str] = &[
        "avi", "mpg", "mpeg", "mp4", "mkv", "wmv", "mov", "flv", "ogm",
        "m4v", "rm", "rmvb", "vob", "asf", "divx", "xvid", "3gp", "ts",
        "m2ts", "webm", "mpe", "ifo",
    ];
    const IMAGE: &[&str] = &[
        "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "psd",
        "ico", "svg", "raw", "cr2", "nef",
    ];
    const PROGRAM: &[&str] = &[
        "exe", "msi", "bat", "com", "dll", "deb", "rpm", "dmg", "apk",
        "jar", "app", "bin", "run",
    ];
    const DOCUMENT: &[&str] = &[
        "doc", "docx", "pdf", "txt", "rtf", "odt", "xls", "xlsx", "ppt",
        "pptx", "epub", "mobi", "djvu", "chm", "tex", "ods", "odp",
    ];
    const ARCHIVE: &[&str] = &[
        "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "ace", "arj",
        "cab", "lzh", "z", "tgz", "zst",
    ];
    const CDIMAGE: &[&str] = &[
        "iso", "nrg", "cue", "img", "bin", "mdf", "ccd", "cdi",
    ];

    let set: &[&str] = match type_value {
        "audio" => AUDIO,
        "video" => VIDEO,
        "image" => IMAGE,
        "pro"   => PROGRAM,
        "doc"   => DOCUMENT,
        "arc"   => ARCHIVE,
        "iso"   => CDIMAGE,
        // Unknown category — don't filter the file out.
        _ => return true,
    };
    set.contains(&ext)
}

pub fn evaluate(node: &SearchNode, name_lower: &str, size: u64) -> bool {
    match node {
        SearchNode::Term(t) => {
            // Wildcard term: "*" or "**" matches every file. eMule sends this
            // for a "list everything" search. Without this check, contains("*")
            // is always false and the wildcard search returns nothing.
            let tl = t.to_lowercase();
            if tl == "*" || tl == "**" || tl.is_empty() {
                return true;
            }
            name_lower.contains(&tl)
        }
        SearchNode::Meta { tag_name, value } => {
            // tag_name is usually a 1-char string holding a byte ID (eMule sends
            // the meta-tag ID as a 1-byte name). Match the known search tags:
            //   FT_FILETYPE   (0x03) — value is "Audio"/"Video"/"Pro"/"Doc"/etc.
            //   FT_FILEFORMAT (0x04) — value is a file extension like "avi"
            let tag_id = tag_name.as_bytes().first().copied().unwrap_or(0);
            let val_lower = value.to_lowercase();

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
            let tag_id = tag_name.as_bytes().first().copied().unwrap_or(0);
            let is_filesize = tag_id == 0x02
                || tag_name.eq_ignore_ascii_case("size")
                || tag_name.eq_ignore_ascii_case("filesize");

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
                tag_name: "size".into(),
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
                tag_name: "\u{03}".into(), // 1-char string holding byte 0x03
                value: "Iso".into(),
            }),
        );
        assert!(evaluate(&tree, "ubuntu-22.04.iso", 1_000_000),
            "ubuntu iso should match type=Iso search");
        assert!(!evaluate(&tree, "ubuntu-manual.pdf", 1000),
            "ubuntu pdf should NOT match type=Iso search");
    }

    #[test]
    fn search_filesize_byte_id() {
        // Numeric with tag_name = 1-char string holding byte 0x02 (FT_FILESIZE)
        let tree = SearchNode::Numeric {
            tag_name: "\u{02}".into(),
            op: CmpOp::Ge,
            value: 1000,
        };
        assert!(evaluate(&tree, "anyfile.bin", 5000));
        assert!(!evaluate(&tree, "anyfile.bin", 500));
    }
}

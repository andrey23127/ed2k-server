//! Tag encoding (newtags + STR1..STR16, see SPEC.md §2.2).
//!
//! Robustness notes (learned from real client traffic):
//! - Non-UTF-8 bytes in strings are replaced with U+FFFD (lossy).
//! - Unknown tag types stop tag parsing without dropping the connection.

use bytes::{BufMut, BytesMut};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TagError {
    #[error("buffer underrun while parsing tag")]
    Underrun,
    #[error("unsupported tag type 0x{0:02x}")]
    UnsupportedType(u8),
    #[error("string too long ({0} bytes)")]
    StringTooLong(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagName {
    Byte(u8),
    Str(String),
}

impl TagName {
    pub fn as_byte(&self) -> Option<u8> {
        match self {
            TagName::Byte(b) => Some(*b),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TagValue {
    String(String),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Float(f32),
    Bool(bool),
    Blob(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tag {
    pub name: TagName,
    pub value: TagValue,
}

impl Tag {
    pub fn byte(name: u8, value: TagValue) -> Self {
        Self { name: TagName::Byte(name), value }
    }

    pub fn str_value(&self) -> Option<&str> {
        if let TagValue::String(s) = &self.value { Some(s) } else { None }
    }

    pub fn as_u32(&self) -> Option<u32> {
        match &self.value {
            TagValue::U32(v) => Some(*v),
            TagValue::U16(v) => Some(*v as u32),
            TagValue::U8(v)  => Some(*v as u32),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match &self.value {
            TagValue::U64(v) => Some(*v),
            TagValue::U32(v) => Some(*v as u64),
            _ => None,
        }
    }
}

const TYPE_HASH: u8     = 0x01;
const TYPE_STRING: u8   = 0x02;
const TYPE_UINT32: u8   = 0x03;
const TYPE_FLOAT: u8    = 0x04;
const TYPE_BOOL: u8     = 0x05;
const TYPE_BLOB: u8     = 0x07;
const TYPE_UINT16: u8   = 0x08;
const TYPE_UINT8: u8    = 0x09;
const TYPE_UINT64: u8   = 0x0B;
const TYPE_STR1_BASE: u8   = 0x10;
const TYPE_NEWTAG_BIT: u8  = 0x80;

pub fn read_tag(buf: &mut &[u8]) -> Result<Tag, TagError> {
    if buf.is_empty() { return Err(TagError::Underrun); }
    let type_byte = buf[0];
    *buf = &buf[1..];

    let has_short_name = type_byte & TYPE_NEWTAG_BIT != 0;
    let real_type = type_byte & !TYPE_NEWTAG_BIT;

    let name = if has_short_name {
        if buf.is_empty() { return Err(TagError::Underrun); }
        let n = buf[0]; *buf = &buf[1..];
        TagName::Byte(n)
    } else {
        if buf.len() < 2 { return Err(TagError::Underrun); }
        let nl = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        *buf = &buf[2..];
        if buf.len() < nl { return Err(TagError::Underrun); }
        // Normalise: old-format 1-byte name == compact name (NEWTAGS).
        // eMule sends LOGINREQUEST with old format (no 0x80 bit) but 1-byte
        // names like [0x01]=CT_NAME, [0x20]=CT_SERVER_FLAGS, etc.
        // Treat them identically to TagName::Byte so all lookups work.
        let result = if nl == 1 {
            TagName::Byte(buf[0])
        } else {
            TagName::Str(String::from_utf8_lossy(&buf[..nl]).into_owned())
        };
        *buf = &buf[nl..];
        result
    };

    let value = match real_type {
        TYPE_STRING => {
            if buf.len() < 2 { return Err(TagError::Underrun); }
            let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
            *buf = &buf[2..];
            if buf.len() < len { return Err(TagError::Underrun); }
            let s = String::from_utf8_lossy(&buf[..len]).into_owned();
            *buf = &buf[len..];
            TagValue::String(s)
        }
        TYPE_UINT32 => {
            if buf.len() < 4 { return Err(TagError::Underrun); }
            let v = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            *buf = &buf[4..]; TagValue::U32(v)
        }
        TYPE_UINT16 => {
            if buf.len() < 2 { return Err(TagError::Underrun); }
            let v = u16::from_le_bytes([buf[0], buf[1]]);
            *buf = &buf[2..]; TagValue::U16(v)
        }
        TYPE_UINT8 => {
            if buf.is_empty() { return Err(TagError::Underrun); }
            let v = buf[0]; *buf = &buf[1..]; TagValue::U8(v)
        }
        TYPE_UINT64 => {
            if buf.len() < 8 { return Err(TagError::Underrun); }
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&buf[..8]);
            *buf = &buf[8..]; TagValue::U64(u64::from_le_bytes(arr))
        }
        TYPE_FLOAT => {
            if buf.len() < 4 { return Err(TagError::Underrun); }
            let v = f32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            *buf = &buf[4..]; TagValue::Float(v)
        }
        TYPE_BOOL => {
            if buf.is_empty() { return Err(TagError::Underrun); }
            let v = buf[0] != 0; *buf = &buf[1..]; TagValue::Bool(v)
        }
        TYPE_BLOB => {
            if buf.len() < 4 { return Err(TagError::Underrun); }
            let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            *buf = &buf[4..];
            if buf.len() < len { return Err(TagError::Underrun); }
            let v = buf[..len].to_vec(); *buf = &buf[len..];
            TagValue::Blob(v)
        }
        t if (TYPE_STR1_BASE + 1..=TYPE_STR1_BASE + 16).contains(&t) => {
            let len = (t - TYPE_STR1_BASE) as usize;
            if buf.len() < len { return Err(TagError::Underrun); }
            let s = String::from_utf8_lossy(&buf[..len]).into_owned();
            *buf = &buf[len..]; TagValue::String(s)
        }
        TYPE_HASH => {
            if buf.len() < 16 { return Err(TagError::Underrun); }
            let v = buf[..16].to_vec(); *buf = &buf[16..];
            TagValue::Blob(v)
        }
        // BOOLARRAY: uint16 bit-count + packed bytes — skip gracefully
        0x06 => {
            if buf.len() < 2 { return Err(TagError::Underrun); }
            let bit_count = u16::from_le_bytes([buf[0], buf[1]]) as usize;
            let byte_count = (bit_count + 7) / 8;
            *buf = &buf[2..];
            if buf.len() < byte_count { return Err(TagError::Underrun); }
            let v = buf[..byte_count].to_vec(); *buf = &buf[byte_count..];
            TagValue::Blob(v)
        }
        // BSOB: uint8 length + bytes
        0x0A => {
            if buf.is_empty() { return Err(TagError::Underrun); }
            let len = buf[0] as usize; *buf = &buf[1..];
            if buf.len() < len { return Err(TagError::Underrun); }
            let v = buf[..len].to_vec(); *buf = &buf[len..];
            TagValue::Blob(v)
        }
        other => return Err(TagError::UnsupportedType(other)),
    };

    Ok(Tag { name, value })
}

/// Parse N tags, stopping early on unknown type rather than erroring.
/// This matches Lugdunum's tolerance for extended client tags.
pub fn read_tag_list(buf: &mut &[u8], count: u32) -> Vec<Tag> {
    let mut tags = Vec::with_capacity(count as usize);
    for _ in 0..count {
        match read_tag(buf) {
            Ok(tag) => tags.push(tag),
            Err(TagError::UnsupportedType(t)) => {
                tracing::debug!(
                    tag_type = format!("0x{t:02x}"),
                    "unknown tag type — stopping tag parse (connection kept)"
                );
                break;
            }
            Err(e) => {
                tracing::debug!(error = %e, "tag parse stopped early");
                break;
            }
        }
    }
    tags
}

pub fn write_tag(out: &mut BytesMut, tag: &Tag) {
    let (short_name, type_base) = match &tag.name {
        TagName::Byte(_) => (true, TYPE_NEWTAG_BIT),
        TagName::Str(_)  => (false, 0),
    };

    let type_marker = match &tag.value {
        TagValue::String(s) => {
            if short_name && (1..=16).contains(&s.len()) {
                TYPE_STR1_BASE + s.len() as u8
            } else {
                TYPE_STRING
            }
        }
        TagValue::U32(_)   => TYPE_UINT32,
        TagValue::U16(_)   => TYPE_UINT16,
        TagValue::U8(_)    => TYPE_UINT8,
        TagValue::U64(_)   => TYPE_UINT64,
        TagValue::Float(_) => TYPE_FLOAT,
        TagValue::Bool(_)  => TYPE_BOOL,
        TagValue::Blob(_)  => TYPE_BLOB,
    };

    out.put_u8(type_base | type_marker);

    match &tag.name {
        TagName::Byte(b) => out.put_u8(*b),
        TagName::Str(s)  => { out.put_u16_le(s.len() as u16); out.put_slice(s.as_bytes()); }
    }

    match &tag.value {
        TagValue::String(s) => {
            if (1..=16).contains(&s.len()) && type_marker > TYPE_STR1_BASE {
                out.put_slice(s.as_bytes());
            } else {
                out.put_u16_le(s.len() as u16);
                out.put_slice(s.as_bytes());
            }
        }
        TagValue::U32(v)   => out.put_u32_le(*v),
        TagValue::U16(v)   => out.put_u16_le(*v),
        TagValue::U8(v)    => out.put_u8(*v),
        TagValue::U64(v)   => out.put_u64_le(*v),
        TagValue::Float(v) => out.put_f32_le(*v),
        TagValue::Bool(v)  => out.put_u8(if *v { 1 } else { 0 }),
        TagValue::Blob(b)  => { out.put_u32_le(b.len() as u32); out.put_slice(b); }
    }
}

pub fn write_tag_list(out: &mut BytesMut, tags: &[Tag]) {
    out.put_u32_le(tags.len() as u32);
    for t in tags { write_tag(out, t); }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(tag: Tag) {
        let mut buf = BytesMut::new();
        write_tag(&mut buf, &tag);
        let mut slice: &[u8] = &buf;
        let parsed = read_tag(&mut slice).unwrap();
        assert_eq!(parsed, tag);
        assert!(slice.is_empty());
    }

    #[test] fn rt_string_short() { round_trip(Tag::byte(0x01, TagValue::String("file.mp4".into()))); }
    #[test] fn rt_string_long()  { round_trip(Tag::byte(0x01, TagValue::String("a".repeat(50)))); }
    #[test] fn rt_u32()  { round_trip(Tag::byte(0x02, TagValue::U32(366465024))); }
    #[test] fn rt_u8()   { round_trip(Tag::byte(0x03, TagValue::U8(2))); }
    #[test] fn rt_u64()  { round_trip(Tag::byte(0x02, TagValue::U64(0xDEADBEEF_FEEDFACE))); }

    #[test]
    fn lossy_utf8_does_not_crash() {
        // 0x80 is invalid UTF-8 (valid Windows-1252 for €).
        // newtags STRING: [0x82][CT_NAME=0x01][len=5][a b 0x80 c d]
        let raw: &[u8] = &[0x82, 0x01, 0x05, 0x00, b'a', b'b', 0x80, b'c', b'd'];
        let tag = read_tag(&mut &raw[..]).unwrap();
        if let TagValue::String(s) = tag.value {
            assert!(s.contains("ab") && s.contains("cd"));
        } else { panic!("expected String"); }
    }

    #[test]
    fn unknown_type_stops_not_crashes() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x83); buf.put_u8(0x20); buf.put_u32_le(999); // valid UINT32
        buf.put_u8(0x42); buf.put_u8(0x01);                       // unknown type
        let tags = read_tag_list(&mut &buf[..], 2);
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].as_u32(), Some(999));
    }

    #[test]
    fn old_format_1byte_name_normalised_to_byte() {
        // eMule sends LOGINREQUEST with old-format tags (no 0x80 bit in type).
        // type=0x02, name_len=1, name=[0x01] → should parse as TagName::Byte(0x01)
        // This is the exact format seen in production captures from eMule 0.49+.
        let raw: &[u8] = &[
            0x02,       // type = STRING, no 0x80 bit → old format
            0x01, 0x00, // name_len = 1
            0x01,       // name = CT_NAME (0x01)
            0x05, 0x00, // string_len = 5
            b'h', b'e', b'l', b'l', b'o', // "hello"
        ];
        let tag = read_tag(&mut &raw[..]).unwrap();
        // Key assertion: must parse as Byte(0x01), NOT Str("\x01")
        assert_eq!(tag.name, TagName::Byte(0x01),
            "old-format 1-byte name must normalise to TagName::Byte");
        assert_eq!(tag.str_value(), Some("hello"));
    }

    #[test]
    fn old_format_loginrequest_tags_all_found() {
        // Exact tag bytes from real eMule LOGINREQUEST capture
        // 4 tags: CT_NAME, CT_VERSION, CT_SERVER_FLAGS, CT_EMULE_VERSION
        let raw: &[u8] = &[
            // Tag 0: CT_NAME = "http://xtreme-mod.net"
            0x02, 0x01, 0x00, 0x01, 0x15, 0x00,
            b'h',b't',b't',b'p',b':',b'/',b'/',b'x',b't',b'r',
            b'e',b'm',b'e',b'-',b'm',b'o',b'd',b'.',b'n',b'e',b't',
            // Tag 1: CT_VERSION = 60
            0x03, 0x01, 0x00, 0x11, 0x3c, 0x00, 0x00, 0x00,
            // Tag 2: CT_SERVER_FLAGS = 0x0719 = 1817
            0x03, 0x01, 0x00, 0x20, 0x19, 0x07, 0x00, 0x00,
            // Tag 3: CT_EMULE_VERSION = 50432
            0x03, 0x01, 0x00, 0xfb, 0x00, 0xc5, 0x00, 0x00,
        ];
        let tags = read_tag_list(&mut &raw[..], 4);
        assert_eq!(tags.len(), 4, "all 4 tags must parse");

        // Find by Byte(id) — this must work for old-format tags too
        let nick = tags.iter().find(|t| t.name == TagName::Byte(0x01));
        assert!(nick.is_some(), "CT_NAME not found");
        assert_eq!(nick.unwrap().str_value(), Some("http://xtreme-mod.net"));

        let flags = tags.iter().find(|t| t.name == TagName::Byte(0x20));
        assert!(flags.is_some(), "CT_SERVER_FLAGS not found");
        assert_eq!(flags.unwrap().as_u32(), Some(0x0719));
    }

    #[test]
    fn parses_real_offerfiles_sample() {
        let tag_bytes: &[u8] = &[
            0x82, 0x01, 0x21, 0x00,
            b'[',b'D',b'i',b'v',b'X',b' ',b'I',b'T',b'A',b']',b' ',
            b'N',b'C',b'I',b'S',b' ',b'4',b'x',b'0',b'1',b' ',b'-',b' ',
            b'S',b'h',b'a',b'l',b'o',b'm',b'.',b'a',b'v',b'i',
            0x83, 0x02, 0x00, 0xd0, 0xd7, 0x15,
            0x89, 0x03, 0x02,
        ];
        let tags = read_tag_list(&mut &tag_bytes[..], 3);
        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0].value, TagValue::String("[DivX ITA] NCIS 4x01 - Shalom.avi".into()));
        assert_eq!(tags[1].as_u32(), Some(366465024));
        assert_eq!(tags[2].as_u32(), Some(2));
    }
}

    #[test]
    fn old_format_single_byte_name_normalized() {
        // This is the exact old-format loginrequest tag encoding eMule uses:
        // type=0x02 (no high bit) + name_len=1 + name=0x01 + string value
        let raw: &[u8] = &[
            0x02, 0x01, 0x00, 0x01,   // type=STRING old-fmt, name_len=1, name=CT_NAME=0x01
            0x15, 0x00,               // string len = 21
            // "http://xtreme-mod.net"
            0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f,0x78,0x74,0x72,
            0x65,0x6d,0x65,0x2d,0x6d,0x6f,0x64,0x2e,0x6e,0x65,0x74,
        ];
        let tags = read_tag_list(&mut &raw[..], 1);
        assert_eq!(tags.len(), 1, "should parse 1 tag");
        assert_eq!(tags[0].name, TagName::Byte(0x01), "name should be normalized to Byte(1)");
        assert_eq!(tags[0].str_value(), Some("http://xtreme-mod.net"));
    }

    #[test]
    fn old_format_uint32_tag_normalized() {
        // type=0x03 (UINT32, no high bit) + name_len=1 + name=0x20 + u32 value
        let raw: &[u8] = &[
            0x03, 0x01, 0x00, 0x20,   // CT_SERVER_FLAGS
            0x19, 0x07, 0x00, 0x00,   // 0x0719 = 1817
        ];
        let tags = read_tag_list(&mut &raw[..], 1);
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].name, TagName::Byte(0x20));
        assert_eq!(tags[0].as_u32(), Some(1817));
    }

    #[test]
    fn full_loginrequest_old_format_tags() {
        // All 4 tags from the real eMule LOGINREQUEST captured on 2026-05-12
        let _raw = bytes::Bytes::from(
            hex::decode(
                "020100011500687474703a2f2f787472656d652d6d6f642e6e6574\
                 030100113c000000\
                 030100201907000003010\
                 0fb00c50000"
            ).unwrap_or_default()
        );
        // Use the raw bytes directly
        let raw2: &[u8] = &[
            0x02,0x01,0x00,0x01,0x15,0x00,
            0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f,0x78,0x74,0x72,0x65,0x6d,0x65,
            0x2d,0x6d,0x6f,0x64,0x2e,0x6e,0x65,0x74,
            0x03,0x01,0x00,0x11,0x3c,0x00,0x00,0x00,
            0x03,0x01,0x00,0x20,0x19,0x07,0x00,0x00,
            0x03,0x01,0x00,0xfb,0x00,0xc5,0x00,0x00,
        ];
        let tags = read_tag_list(&mut &raw2[..], 4);
        assert_eq!(tags.len(), 4, "all 4 tags should parse");
        // Tag 0: CT_NAME = 0x01
        assert_eq!(tags[0].name, TagName::Byte(0x01));
        assert_eq!(tags[0].str_value(), Some("http://xtreme-mod.net"));
        // Tag 1: CT_VERSION = 0x11
        assert_eq!(tags[1].name, TagName::Byte(0x11));
        assert_eq!(tags[1].as_u32(), Some(60));
        // Tag 2: CT_SERVER_FLAGS = 0x20
        assert_eq!(tags[2].name, TagName::Byte(0x20));
        assert_eq!(tags[2].as_u32(), Some(1817));
        // Tag 3: CT_EMULE_VERSION = 0xFB
        assert_eq!(tags[3].name, TagName::Byte(0xfb));
    }

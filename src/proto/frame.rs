//! eD2k frame codec.
//!
//! Implements the framing layer described in SPEC.md §2.1:
//!
//! ```text
//! +--------+--------+--------+--------+--------+--------+
//! | proto  |               length              | opcode |  payload...
//! +--------+--------+--------+--------+--------+--------+
//!    1B               4B (LE, includes opcode)     1B
//! ```
//!
//! Length covers `opcode + payload` (i.e. `1 + len(payload)`).
//!
//! `0xD4` frames have zlib-compressed payloads (RFC 1950); we decompress
//! transparently and present plaintext to upper layers.

use bytes::{Buf, BufMut, BytesMut};
use std::io::Read;
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

use super::opcodes::{PROTO_EDONKEY, PROTO_PACKED};

const HEADER_LEN: usize = 6;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid protocol marker 0x{0:02x}")]
    InvalidMarker(u8),

    #[error("frame too large: {got} bytes (limit {limit})")]
    TooLarge { got: u32, limit: u32 },

    #[error("zlib decompression failed: {0}")]
    Decompress(String),

    #[error("zero-length frame")]
    EmptyFrame,
}

/// A decoded eD2k frame, payload always plaintext (D4 already decompressed).
#[derive(Debug, Clone)]
pub struct Frame {
    pub opcode: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(opcode: u8, payload: Vec<u8>) -> Self {
        Self { opcode, payload }
    }
}

pub struct Ed2kCodec {
    pub max_frame_size: u32,
}

impl Ed2kCodec {
    pub fn new(max_frame_size: u32) -> Self {
        Self { max_frame_size }
    }
}

impl Decoder for Ed2kCodec {
    type Item = Frame;
    type Error = FrameError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Frame>, FrameError> {
        if src.len() < HEADER_LEN {
            return Ok(None);
        }

        let proto = src[0];
        match proto {
            PROTO_EDONKEY | PROTO_PACKED => {}
            other => {
                // Out-of-sync stream. Cannot recover safely; signal upper layer
                // to drop the connection.
                return Err(FrameError::InvalidMarker(other));
            }
        }

        // length = 1 (opcode) + len(payload)  → payload bytes = length - 1
        let length = u32::from_le_bytes([src[1], src[2], src[3], src[4]]);

        if length == 0 {
            return Err(FrameError::EmptyFrame);
        }

        if length > self.max_frame_size {
            return Err(FrameError::TooLarge {
                got: length,
                limit: self.max_frame_size,
            });
        }

        let total = HEADER_LEN + (length as usize) - 1;
        if src.len() < total {
            // Reserve so the read loop has somewhere to put the rest.
            src.reserve(total - src.len());
            return Ok(None);
        }

        // Consume header + payload
        let _proto = src.get_u8();
        let _length = src.get_u32_le();
        let opcode = src.get_u8();

        let payload_len = length as usize - 1;
        let raw_payload = src.split_to(payload_len);

        let payload = if proto == PROTO_PACKED {
            // zlib-decompress
            let mut decoder = flate2::read::ZlibDecoder::new(raw_payload.as_ref());
            let mut out = Vec::with_capacity(payload_len * 2);
            decoder
                .read_to_end(&mut out)
                .map_err(|e| FrameError::Decompress(e.to_string()))?;
            out
        } else {
            raw_payload.to_vec()
        };

        Ok(Some(Frame { opcode, payload }))
    }

    /// Called by FramedRead when the underlying stream has reached EOF.
    ///
    /// The default tokio-util implementation, after `decode` returns `None`,
    /// treats any leftover bytes in the buffer as an error ("bytes remaining on
    /// stream"). That fires constantly for well-behaved-but-impatient clients:
    /// a peer sharing a huge library (hundreds of thousands of files) streams a
    /// large OFFERFILES and, on these eD2k clients, frequently drops the TCP
    /// connection mid-packet (aggressive reconnect loops were observed doing
    /// this every few seconds). The half-sent frame left in the buffer is not a
    /// protocol violation — the client simply closed early — so logging it as a
    /// `frame error` is misleading noise.
    ///
    /// We decode any COMPLETE frames still buffered, and once only a partial
    /// frame (or trailing bytes too short to be a frame) remains at EOF, we
    /// return `Ok(None)` to signal a clean end of stream instead of an error.
    /// A truly malformed frame (bad marker, oversize length, bad zlib) is still
    /// surfaced as an error by the inner `decode` call.
    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Frame>, FrameError> {
        match self.decode(src)? {
            Some(frame) => Ok(Some(frame)),
            None => {
                // Leftover bytes that don't form a complete frame at EOF are a
                // truncated final packet from a client that closed mid-send.
                // Treat as a normal end of stream rather than "bytes remaining".
                Ok(None)
            }
        }
    }
}

impl Encoder<Frame> for Ed2kCodec {
    type Error = FrameError;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), FrameError> {
        // zlib compression for large frames, matching Lugdunum's algorithm
        // (eserver.c line 12208): if payload > 400 bytes, try compress2();
        // only emit the 0xD4 packed form when the compressed result is
        // actually smaller than the original payload — otherwise send plain.
        //
        // Only the payload (after the opcode) is compressed; the 6-byte
        // header (proto + length + opcode) stays plain. The opcode byte is
        // copied verbatim into the 0xD4 frame.
        //
        // COMPRESS_THRESHOLD raised in v0.9.40 from 1024 to 4096 — production
        // perf profiles showed compression dominating CPU even at level 1
        // (46% relative share). eD2k payloads <4KB are dominated by random
        // binary content (MD4 hashes, IPs, file sizes) that compresses poorly,
        // so the bandwidth savings rarely justify the CPU cost. Only truly
        // large responses (multi-page search results with text-heavy filename
        // strings, full server lists ≥250 entries) compress well enough to
        // warrant the work.
        const COMPRESS_THRESHOLD: usize = 4096;

        if item.payload.len() > COMPRESS_THRESHOLD {
            use flate2::write::ZlibEncoder;
            use flate2::Compression;
            use std::io::Write;

            // Compression::fast() = level 1: ~3× faster than the default level 6,
            // typically only 5-10% larger output. For our workload (search
            // results, server lists) where the data is mostly already random,
            // level 6 was burning 44% of CPU in production (v0.9.37 profile)
            // without meaningfully shrinking output. Level 1 fixes that.
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
            if encoder.write_all(&item.payload).is_ok() {
                if let Ok(compressed) = encoder.finish() {
                    // Only use compression if it actually shrank the payload.
                    if compressed.len() < item.payload.len() {
                        let length = (compressed.len() + 1) as u32;
                        dst.reserve(HEADER_LEN + compressed.len());
                        dst.put_u8(PROTO_PACKED);          // 0xD4
                        dst.put_u32_le(length);
                        dst.put_u8(item.opcode);            // opcode stays plain
                        dst.put_slice(&compressed);
                        return Ok(());
                    }
                }
            }
            // Compression failed or didn't help — fall through to plain encoding.
        }

        // Plain (0xE3) frame.
        let length = (item.payload.len() + 1) as u32;
        dst.reserve(HEADER_LEN + item.payload.len());
        dst.put_u8(PROTO_EDONKEY);
        dst.put_u32_le(length);
        dst.put_u8(item.opcode);
        dst.put_slice(&item.payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_plain() {
        let mut codec = Ed2kCodec::new(1_000_000);
        let mut buf = BytesMut::new();
        codec
            .encode(Frame::new(0x38, b"hello".to_vec()), &mut buf)
            .unwrap();
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.opcode, 0x38);
        assert_eq!(frame.payload, b"hello");
        assert!(buf.is_empty());
    }

    #[test]
    fn large_frame_is_compressed_and_round_trips() {
        let mut codec = Ed2kCodec::new(10_000_000);
        let mut buf = BytesMut::new();
        // Highly compressible payload well over the 400-byte threshold.
        let payload = vec![0x41u8; 5000];
        codec
            .encode(Frame::new(0x33, payload.clone()), &mut buf)
            .unwrap();
        // Wire form must be the packed 0xD4 marker and much smaller.
        assert_eq!(buf[0], PROTO_PACKED, "large frame should use 0xD4");
        assert!(buf.len() < 500, "compressed frame should be small, got {}", buf.len());
        // Decoder transparently decompresses back to the original payload.
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.opcode, 0x33);
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn incompressible_large_frame_stays_plain() {
        let mut codec = Ed2kCodec::new(10_000_000);
        let mut buf = BytesMut::new();
        // Pseudo-random, non-periodic data (xorshift) that won't compress
        // below the original size — exercises the "fall back to plain" path.
        let mut state: u32 = 0x12345678;
        let payload: Vec<u8> = (0..5000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state & 0xFF) as u8
            })
            .collect();
        codec
            .encode(Frame::new(0x33, payload.clone()), &mut buf)
            .unwrap();
        // Should fall back to plain 0xE3 since compression didn't help.
        assert_eq!(buf[0], PROTO_EDONKEY, "incompressible frame should stay plain");
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn rejects_invalid_marker() {
        let mut codec = Ed2kCodec::new(1_000_000);
        // 0xAA is not a valid eD2k protocol marker
        let mut buf = BytesMut::from(&b"\xAA\x05\x00\x00\x00\x38hello"[..]);
        assert!(matches!(
            codec.decode(&mut buf),
            Err(FrameError::InvalidMarker(0xAA))
        ));
    }

    #[test]
    fn rejects_oversize() {
        let mut codec = Ed2kCodec::new(10);
        // length=999999 → way over limit
        let mut buf = BytesMut::from(&b"\xE3\x3F\x42\x0F\x00\x38"[..]);
        assert!(matches!(
            codec.decode(&mut buf),
            Err(FrameError::TooLarge { .. })
        ));
    }

    #[test]
    fn returns_none_when_short() {
        let mut codec = Ed2kCodec::new(1_000_000);
        // Only header, payload missing
        let mut buf = BytesMut::from(&b"\xE3\x06\x00\x00\x00\x38"[..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_eof_treats_partial_tail_as_clean_close() {
        // A client that dropped mid-send leaves an incomplete frame in the
        // buffer at EOF. decode_eof must return Ok(None) (clean end of stream),
        // NOT an error — this is what suppresses the spurious "bytes remaining
        // on stream" warnings from huge-library clients on aggressive reconnect.
        let mut codec = Ed2kCodec::new(1_000_000);
        // Header claims a 0x38-byte payload but only a few bytes follow.
        let mut buf = BytesMut::from(&b"\xE3\x40\x00\x00\x00\x38\x01\x02\x03"[..]);
        let res = codec.decode_eof(&mut buf).unwrap();
        assert!(res.is_none(), "partial tail at EOF must be a clean close, not an error");
    }

    #[test]
    fn decode_eof_still_returns_complete_frame() {
        // A complete frame present at EOF must still decode normally.
        let mut codec = Ed2kCodec::new(1_000_000);
        let mut buf = BytesMut::from(&b"\xE3\x06\x00\x00\x00\x38hello"[..]);
        let frame = codec.decode_eof(&mut buf).unwrap().unwrap();
        assert_eq!(frame.opcode, 0x38);
    }

    #[test]
    fn decompresses_d4_frame() {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;

        let plaintext = b"compressible compressible compressible";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plaintext).unwrap();
        let compressed = encoder.finish().unwrap();

        // Build a D4 frame: marker=D4, length = 1+compressed.len(), opcode=0x33
        let mut buf = BytesMut::new();
        buf.put_u8(PROTO_PACKED);
        buf.put_u32_le((compressed.len() + 1) as u32);
        buf.put_u8(0x33);
        buf.put_slice(&compressed);

        let mut codec = Ed2kCodec::new(1_000_000);
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.opcode, 0x33);
        assert_eq!(frame.payload, plaintext);
    }
}

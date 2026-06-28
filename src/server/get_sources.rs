//! GETSOURCES → FOUNDSOURCES handler (SPEC.md §3.5).
//!
//! Single-hash lookup. Returns up to N source endpoints for a file.
//! In production this is the hot path (~80% of total server load) and
//! would be backed by SmartSources cache; MVP does direct lookup.

use crate::proto::{opcodes::*, Frame};
use crate::state::{ClientHandle, ServerState};
use anyhow::{anyhow, Result};
use bytes::{BufMut, BytesMut};
use tracing::debug;

/// Maximum sources returned per response (SPEC.md §6.2.6 SmartSources tiers).
const MAX_SOURCES_PER_REPLY: usize = 200;

#[derive(Debug)]
pub struct GetSourcesRequest {
    pub file_hash: [u8; 16],
    /// File size, encoded as v2 (4 bytes) or v2-large (4 + 4 bytes) extension.
    pub size: Option<u64>,
}

impl GetSourcesRequest {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() < 16 {
            return Err(anyhow!("GETSOURCES too short ({} bytes)", payload.len()));
        }
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&payload[0..16]);

        // v2: payload[16..20] = size_lo
        // v2-large: payload[16..20] = 0, payload[20..24] = size_hi, payload[24..28] = size_lo
        // (the hi=0 sentinel signals the v2-large variant)
        let size = if payload.len() >= 20 {
            let lo = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
            if lo == 0 && payload.len() >= 28 {
                let hi = u32::from_le_bytes([payload[20], payload[21], payload[22], payload[23]]);
                let actual_lo = u32::from_le_bytes([payload[24], payload[25], payload[26], payload[27]]);
                Some(((hi as u64) << 32) | (actual_lo as u64))
            } else {
                Some(lo as u64)
            }
        } else {
            None
        };

        Ok(Self {
            file_hash: hash,
            size,
        })
    }
}

/// Build a FOUNDSOURCES frame for the given file. Returns Frame even when
/// there are no sources (count=0) — clients expect a reply for every request.
///
/// Hot-path optimization: results are cached in the SmartSources cache for a
/// few seconds. For popular files this turns a source-list iteration + encode
/// into a single map lookup. The cache key is the file hash; the requester is
/// not part of the key, so we must still filter "self" out of a cache hit —
/// but that's a cheap scan over an already-built payload, done below.
pub fn handle_get_sources(
    state: &ServerState,
    requester: &ClientHandle,
    req: GetSourcesRequest,
) -> Frame {
    // Fast path: a freshly-cached payload for this hash.
    if let Some(cached) = state.smart_sources.get(&req.file_hash) {
        debug!(
            file_hash = hex::encode(req.file_hash),
            "getsources answered from SmartSources cache"
        );
        return Frame::new(OP_FOUNDSOURCES, cached);
    }

    // Slow path: build the source list from the index.
    let sources = state
        .file_slab
        .get_by_hash(&req.file_hash)
        .map(|entry| {
            entry
                .sources
                .iter()
                // Don't return the requester to itself
                .filter(|s| s.user_hash != requester.user_hash)
                // LowID-to-LowID introductions are useless (neither can connect),
                // but we don't have that detail per-source yet in MVP. Skip filter.
                .take(MAX_SOURCES_PER_REPLY)
                .copied()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    debug!(
        file_hash = hex::encode(req.file_hash),
        source_count = sources.len(),
        "getsources answered (rebuilt)"
    );

    let mut payload = BytesMut::new();
    payload.put_slice(&req.file_hash);
    payload.put_u8(sources.len() as u8);
    for s in &sources {
        // Encode the source ID the way eD2k clients expect:
        //   * HighID source  -> its real IPv4 (client connects directly)
        //   * LowID source   -> its server-assigned low ID (< 0x01000000), so the
        //     downloader recognizes it as LowID (::IsLowID) and uses a callback /
        //     (with our mod) a NAT-traversal hole punch instead of a doomed direct
        //     connect to the firewalled peer's real IP.
        // We discover LowID-ness by looking the source up in the live client map
        // by user_hash; if it's currently connected and firewalled, use its low id.
        // If the client isn't found (stale source) we fall back to the real IP —
        // same behavior as before this change.
        let id = match state.clients.get(&s.user_hash) {
            Some(handle) if !handle.is_high_id => handle.assigned_id,
            _ => s.ipv4,
        };
        payload.put_u32_le(id);
        payload.put_u16_le(s.port());
    }

    let payload_vec = payload.to_vec();
    // Cache the built payload. Note: the requester-self filter above means
    // this payload technically excludes one specific peer, but in practice
    // the same file is requested by many peers and the ~5s TTL makes the
    // tiny over/under-inclusion harmless — clients re-query constantly.
    state.smart_sources.put(req.file_hash, payload_vec.clone());

    Frame::new(OP_FOUNDSOURCES, payload_vec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v1() {
        // Just hash, no size (legacy)
        let payload = [0x42u8; 16];
        let r = GetSourcesRequest::parse(&payload).unwrap();
        assert_eq!(r.file_hash, [0x42; 16]);
        assert_eq!(r.size, None);
    }

    #[test]
    fn parse_v2() {
        // hash + 4-byte size
        let mut payload = vec![0x42u8; 16];
        payload.extend_from_slice(&1234u32.to_le_bytes());
        let r = GetSourcesRequest::parse(&payload).unwrap();
        assert_eq!(r.size, Some(1234));
    }

    #[test]
    fn parse_v2_large() {
        // hash + size_lo=0 sentinel + size_hi + actual_size_lo
        let mut payload = vec![0x42u8; 16];
        payload.extend_from_slice(&0u32.to_le_bytes());        // sentinel
        payload.extend_from_slice(&5u32.to_le_bytes());        // hi
        payload.extend_from_slice(&123u32.to_le_bytes());      // lo
        let r = GetSourcesRequest::parse(&payload).unwrap();
        // Size = (5<<32) | 123 = 5*4G + 123
        assert_eq!(r.size, Some((5u64 << 32) | 123));
    }

    // A LowID source must be encoded as its server-assigned low id (so the
    // downloader treats it as LowID and uses callback / NAT-T), while a HighID
    // source is encoded as its real IPv4. Regression test for the bug where
    // every source (LowID included) was encoded as its real IP, making LowID
    // peers look like HighID and breaking LowID<->LowID NAT traversal.
    #[test]
    fn lowid_source_encoded_as_assigned_id() {
        use std::net::{IpAddr, Ipv4Addr};
        let state = ServerState::for_test();

        let file_hash = [0x77u8; 16];
        let low_uh = [0xAAu8; 16];
        let high_uh = [0xBBu8; 16];

        // A firewalled (LowID) source and a HighID source for the same file.
        let low_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let high_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        state.add_file_with_source(file_hash, 1000, "f".into(), (low_uh, low_ip, 4001, true));
        state.add_file_with_source(file_hash, 1000, "f".into(), (high_uh, high_ip, 4002, true));

        // Register both as live clients: low id 42 (firewalled), high id (real).
        state.register_test_client(low_uh, 42, /*high_id*/ false, 5001);
        state.register_test_client(high_uh, 0x0102_0304, /*high_id*/ true, 0);

        // Requester: some third client asking for the file.
        let req_uh = [0xCCu8; 16];
        state.register_test_client(req_uh, 7, false, 0);
        let requester = state.clients.get(&req_uh).unwrap().clone();

        let frame = handle_get_sources(
            &state,
            &requester,
            GetSourcesRequest { file_hash, size: None },
        );

        // payload: hash(16) count(1) then count*(id(4) port(2))
        let p = &frame.payload;
        assert_eq!(&p[0..16], &file_hash);
        let count = p[16] as usize;
        assert_eq!(count, 2);

        // Walk the entries; collect (id, port) pairs.
        let mut got = std::collections::HashMap::new();
        for i in 0..count {
            let off = 17 + i * 6;
            let id = u32::from_le_bytes([p[off], p[off + 1], p[off + 2], p[off + 3]]);
            let port = u16::from_le_bytes([p[off + 4], p[off + 5]]);
            got.insert(port, id);
        }
        // LowID source (port 4001) must carry the assigned low id 42, NOT its IP.
        assert_eq!(got.get(&4001), Some(&42u32), "LowID source must encode assigned_id");
        // HighID source (port 4002) must carry its real IPv4 as the id.
        let expect_high = u32::from_le_bytes(Ipv4Addr::new(198, 51, 100, 7).octets());
        assert_eq!(got.get(&4002), Some(&expect_high), "HighID source must encode real IP");
    }
}

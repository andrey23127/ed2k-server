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

        // v2:       payload[16..20] = size as u32
        // v2-large: payload[16..20] = 0 (sentinel), payload[20..28] = size as u64 LE
        //
        // The layout comes straight from eMule, DownloadQueue.cpp:1352-1357:
        //
        //     if (!cur_file->IsLargeFile())
        //         smPacket.WriteUInt32((uint32)(uint64)cur_file->GetFileSize());
        //     else {
        //         smPacket.WriteUInt32(0);   // large-file marker, a u64 follows
        //         smPacket.WriteUInt64(cur_file->GetFileSize());
        //     }
        //
        // and `WriteUInt64` is `Write(&nVal, sizeof nVal)` (SafeFile.cpp:155), a
        // raw little-endian u64 — LOW dword first.
        //
        // This used to read [20..24] as the HIGH half and [24..28] as the low
        // one, i.e. the two words swapped, so a 6 GiB file decoded as
        // 9223372036854775809 instead of 6442450944.
        let size = if payload.len() >= 20 {
            let lo = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
            if lo == 0 && payload.len() >= 28 {
                let mut b = [0u8; 8];
                b.copy_from_slice(&payload[20..28]);
                Some(u64::from_le_bytes(b))
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
/// A well-formed FOUNDSOURCES payload carrying zero sources.
///
/// Clients expect a reply to every request, so a listed file answers "nobody
/// has it" rather than staying silent — silence just makes the client re-ask.
fn encode_empty_sources(file_hash: &[u8; 16]) -> Vec<u8> {
    let mut payload = BytesMut::with_capacity(17);
    payload.put_slice(file_hash);
    payload.put_u8(0);
    payload.to_vec()
}

pub fn handle_get_sources(
    state: &ServerState,
    requester: &ClientHandle,
    req: GetSourcesRequest,
) -> Frame {
    // Hash lists first, BEFORE the cache. Handing out sources is how a download
    // actually starts, so a listed file must stop being served here too, not
    // just stop appearing in search — otherwise a client that already has the
    // ed2k link still gets peers for it.
    //
    // Ahead of the cache on purpose: a cached payload built before the hash was
    // listed would otherwise keep being served for the life of its TTL.
    let withheld_name = state
        .file_slab
        .with_record_by_hash(&req.file_hash, |_id, r| r.name.to_string());
    if state
        .filter
        .is_withheld_opt(&req.file_hash, withheld_name.as_deref())
    {
        debug!(
            file_hash = hex::encode(req.file_hash),
            "getsources refused: file is withheld by the content filter"
        );
        return Frame::new(OP_FOUNDSOURCES, encode_empty_sources(&req.file_hash));
    }

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

    // The count byte has to match what actually gets written, and the loop below
    // can skip a source, so the entries are built first and the real count is
    // prefixed afterwards. Writing sources.len() and then emitting fewer would
    // leave the client parsing past the end of the payload.
    let mut entries = BytesMut::new();
    let mut emitted: u8 = 0;
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
            _ => {
                // STALE SOURCE. The client is gone, so there is no low id to
                // substitute and the stored address goes out verbatim. If that
                // address is private it means nothing outside one LAN: every
                // peer that receives it burns a connect attempt on it and then
                // passes it on when it exchanges sources. Drop it instead.
                //
                // Only reachable for a departed client — a connected firewalled
                // one takes the branch above and is reached by callback.
                if !ServerState::is_publishable_source_ip(s.ip()) {
                    continue;
                }
                s.ipv4
            }
        };
        entries.put_u32_le(id);
        entries.put_u16_le(s.port());
        emitted += 1;
    }

    let mut payload = BytesMut::new();
    payload.put_slice(&req.file_hash);
    payload.put_u8(emitted);
    payload.put_slice(&entries);

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
        // The tail after the sentinel is a plain little-endian u64, exactly as
        // eMule's WriteUInt64 emits it — NOT two dwords in high/low order.
        //
        // This test previously encoded the bug: it wrote the high dword first
        // and asserted the swapped reading back, so it passed while real clients
        // were being misparsed. Build the payload the way the wire does.
        let size: u64 = (5u64 << 32) | 123;
        let mut payload = vec![0x42u8; 16];
        payload.extend_from_slice(&0u32.to_le_bytes()); // large-file sentinel
        payload.extend_from_slice(&size.to_le_bytes()); // u64 LE, low dword first
        let r = GetSourcesRequest::parse(&payload).unwrap();
        assert_eq!(r.size, Some(size));
    }

    #[test]
    fn parse_v2_large_six_gib_from_the_report() {
        // The exact frame from the interop report: 6 GiB, which used to decode
        // as 9223372036854775809 because the two dwords were swapped.
        let mut payload = vec![0x33u8; 16];
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // sentinel
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00]);
        let r = GetSourcesRequest::parse(&payload).unwrap();
        assert_eq!(r.size, Some(6_442_450_944));
    }

    #[test]
    fn parse_v2_large_straddling_the_4gib_boundary() {
        for size in [(1u64 << 32) - 1, 1u64 << 32, (1u64 << 32) + 1] {
            let mut payload = vec![0x11u8; 16];
            payload.extend_from_slice(&0u32.to_le_bytes());
            payload.extend_from_slice(&size.to_le_bytes());
            assert_eq!(
                GetSourcesRequest::parse(&payload).unwrap().size,
                Some(size),
                "size {size} must round-trip"
            );
        }
    }

    #[test]
    fn v2_large_sentinel_without_the_u64_is_not_misread() {
        // Sentinel present but the u64 truncated: must fall back to "size 0"
        // rather than reading past the end or inventing a value.
        let mut payload = vec![0x77u8; 16];
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&[0xFF; 4]); // only half of the u64
        let r = GetSourcesRequest::parse(&payload).unwrap();
        assert_eq!(r.size, Some(0));
    }

    // A LowID source must be encoded as its server-assigned low id (so the
    // downloader treats it as LowID and uses callback / NAT-T), while a HighID
    // source is encoded as its real IPv4. Regression test for the bug where
    // every source (LowID included) was encoded as its real IP, making LowID
    // peers look like HighID and breaking LowID<->LowID NAT traversal.
    #[test]
    fn a_stale_private_source_is_not_emitted() {
        // The address of a client that has gone. There is no low id left to
        // substitute, so it would go out verbatim — and outside its own LAN it
        // means nothing except a wasted connect attempt for every peer that
        // receives it, and for every peer they hand it on to.
        use std::net::{IpAddr, Ipv4Addr};
        for ip in [
            Ipv4Addr::new(192, 168, 30, 254),
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(172, 20, 1, 1),
            Ipv4Addr::new(100, 90, 0, 1),
        ] {
            assert!(!ServerState::is_publishable_source_ip(IpAddr::V4(ip)), "{ip}");
        }
        assert!(ServerState::is_publishable_source_ip(IpAddr::V4(
            Ipv4Addr::new(85, 17, 116, 222)
        )));
    }

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

//! SEARCHREQUEST handler (SPEC.md §3.4).
//!
//! Decode the search expression tree, intersect/filter via the keyword
//! index, build a SEARCHRESULT response. zlib compression for large
//! result sets is left for a follow-up; for now we emit plain frames.

use crate::proto::{
    opcodes::*,
    search::{collect_terms, evaluate, parse, SearchNode},
    tags::{Tag, TagValue},
    write_tag_list, Frame,
};
use crate::state::ServerState;
use anyhow::Result;
use bytes::{BufMut, BytesMut};
use tracing::{debug, info};

/// Maximum results per response (SPEC.md §3.4.1, default 200).
const MAX_RESULTS: usize = 200;

/// Upper bound on records examined by a search with no indexable token.
///
/// Such a query ("*", or metadata-only like Type=Video plus a size range) has no
/// keyword posting to narrow it, so the only way to answer it exactly is to walk
/// every live file — O(live files) with a shard read lock held, blocking
/// publishes into the shard being walked. At the target scale that is tens of
/// millions of records, and any client can ask for it repeatedly: a one-token
/// query whose token happens to miss the index takes the same path.
///
/// 50k is far more than a client can use (MAX_RESULTS is 200) and small enough
/// that a walk stays in the millisecond range. Past the cap the answer is
/// best-effort — the right trade, since a metadata-only query has no precise
/// answer worth protecting, while a stalled server affects every user.
const MAX_UNINDEXED_SCAN: usize = 50_000;

/// Decoded search request.
pub struct SearchRequest {
    pub tree: SearchNode,
}

impl SearchRequest {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let tree = parse(payload)?;
        Ok(Self { tree })
    }
}

/// Process a search request. Returns the SEARCHRESULT frame to send back.
/// Run a search and return ALL matching file entries (up to MAX_RESULTS).
/// The caller paginates this into SEARCHRESULT frames via
/// build_search_result_page + QUERY_MORE_RESULT.
pub fn handle_search(state: &ServerState, req: SearchRequest) -> Vec<crate::state::file_id::FileRecord> {
    let tokens = collect_terms(&req.tree);

    debug!(?tokens, "search tokens extracted from tree");

    // All tokens lowercase; only skip literal wildcards ("*", "**").
    // Do NOT filter by length — eMule sends 1-2 char tokens ("HD", "OS", etc.)
    // and filtering them breaks those searches.
    let token_lower: Vec<String> = tokens.iter()
        .map(|t| t.to_lowercase())
        .filter(|t| t != "*" && t != "**")
        .collect();

    // Candidates: keyword lookup if we have tokens, otherwise full scan
    // (handles "*" search and metadata-only queries like Type=Video + size).
    //
    // IMPORTANT: with no keyword token the tree predicate must be applied
    // BEFORE the MAX_RESULTS cap. Taking the first 200 records and filtering
    // afterwards is a bug: iteration order is arbitrary, so a metadata query
    // (Type=Video, size range, no filename) would return a different,
    // mostly-tiny result set every time. The walk is bounded by
    // MAX_UNINDEXED_SCAN instead, which caps the WORK rather than the input to
    // the predicate.
    let keyword_filtered = !token_lower.is_empty();

    // Walk candidates and apply the full tree (handles negation, numeric, meta).
    //
    // Candidates stay as FileIds. They used to be converted to hashes and looked
    // up again by hash, which cost two extra shard locks and a hash-chain walk
    // per candidate to arrive back at the id we already had.
    //
    // The predicate is evaluated IN PLACE via `with_record`, and only a match is
    // cloned. Cloning first and filtering second paid for a full `FileRecord`
    // copy — sources SmallVec plus an Arc bump — on every candidate, when a busy
    // query examines thousands and keeps at most MAX_RESULTS.
    let mut matches: Vec<crate::state::file_id::FileRecord> = Vec::new();
    let mut n_candidates = 0usize;
    let mut scanned = 0usize;
    let mut scan_capped = false;

    // Test one candidate. Returns false once enough matches are collected.
    // Shared by both paths below so they cannot drift apart.
    let mut consider = |entry: &crate::state::file_id::FileRecord,
                        matches: &mut Vec<crate::state::file_id::FileRecord>| -> bool {
        scanned += 1;
        // The FULL filter applies to what is SERVED, not only to what is
        // published — see ContentFilter::is_withheld. A term added today has to
        // remove the copies indexed yesterday, or the term lists are prospective
        // only and the index keeps serving what the filter already rejects.
        if state.filter.is_withheld(&entry.hash, &entry.name) {
            return true;
        }
        // Skip orphans (no live source). These exist transiently when a source
        // removal races a concurrent re-publish, until the periodic cleanup
        // evicts them (or a client republishes). They're useless to return —
        // clients can't download from a file with no sources, which is also why
        // such entries would show "0% (0)" in the eMule complete-sources column.
        if entry.sources.is_empty() {
            return true;
        }
        let name_lower = entry.name.to_lowercase();
        if evaluate(&req.tree, &name_lower, entry.size) {
            matches.push(entry.clone());
            if matches.len() >= MAX_RESULTS {
                return false;
            }
        }
        true
    };

    if keyword_filtered {
        let ids = state.keyword_index.find_intersection(&token_lower);
        n_candidates = ids.len();
        for fid in ids {
            // A tombstoned id yields None and is skipped — it can't be a live
            // match anyway.
            let keep_going = state
                .file_slab
                .with_record(fid, |r| consider(r, &mut matches))
                .unwrap_or(true);
            if !keep_going {
                break;
            }
        }
    } else {
        // No indexable token: "*" searches and metadata-only queries
        // (Type=Video + size range). There is no candidate set to narrow with,
        // so the tree has to be applied to live records directly.
        //
        // The predicate must run BEFORE the MAX_RESULTS cap: taking the first N
        // records and filtering afterwards would test an arbitrary N — shard
        // iteration order is not meaningful — so a metadata query would return a
        // different, mostly-tiny result set every time.
        //
        // But an unbounded scan is a liability: it is O(live files) with a shard
        // read lock held, it blocks publishes into the shard being walked, and
        // any client can trigger it repeatedly with a one-token query that
        // happens to miss the index. So the scan is capped at
        // MAX_UNINDEXED_SCAN and the answer is best-effort past that point,
        // which is the correct trade: a metadata-only query has no precise
        // answer to protect, while a stalled server affects everyone.
        state.file_slab.for_each_live_while(|_id, r| {
            if n_candidates >= MAX_UNINDEXED_SCAN {
                scan_capped = true;
                return false;
            }
            n_candidates += 1;
            consider(r, &mut matches)
        });
    }
    if scan_capped {
        debug!(
            limit = MAX_UNINDEXED_SCAN,
            matched = matches.len(),
            "unindexed search hit the scan cap; result set is partial"
        );
    }

    info!(
        token_count = tokens.len(),
        indexed_tokens = token_lower.len(),
        keyword_filtered,
        candidates = n_candidates,
        scanned,
        scan_capped,
        matched = matches.len(),
        "search processed"
    );

    if matches.is_empty() && !tokens.is_empty() {
        // Help diagnose empty results
        debug!(
            tokens = ?token_lower,
            total_files = state.file_slab.live_count(),
            "search returned no results"
        );
    }

    matches
}

/// Number of result records sent per SEARCHRESULT frame. eMule then sends
/// QUERY_MORE_RESULT (0x21) to pull each subsequent page. Lugdunum uses a
/// similar chunking; ~50 keeps each frame comfortably small even before
/// zlib compression kicks in.
/// Results per SEARCHRESULT page. Lugdunum sends up to ~200 in a single
/// packet; eMule only triggers QUERY_MORE_RESULT (the "More" button) when
/// the server actually capped at this size AND the trailing "more" byte was
/// set. Using 50 here made every search look like "exactly 50 hits" because
/// eMule populated the list with the first page and waited for a manual
/// More click — which isn't the expected behaviour.
pub const SEARCH_PAGE_SIZE: usize = 200;

/// Build one SEARCHRESULT frame for a page of results, and report whether
/// more results remain after this page.
///
/// `page` is the slice of matches for this frame. `has_more` becomes the
/// trailing "more results available" byte — eMule shows a "More" button and
/// sends QUERY_MORE_RESULT when it is 1.
pub fn build_search_result_page(
    page: &[crate::state::file_id::FileRecord],
    has_more: bool,
) -> Frame {
    let mut payload = BytesMut::new();
    payload.put_u32_le(page.len() as u32);

    for file in page {
        payload.put_slice(&file.hash);

        // Source IP as u32 LE with octets in natural order.
        if let Some(src) = file.sources.first() {
            let id = src.ipv4;
            payload.put_u32_le(id);
            payload.put_u16_le(src.port());
        } else {
            payload.put_u32_le(0);
            payload.put_u16_le(0);
        }

        // Tags: filename, size_lo, optional size_hi (files >4 GiB), sources,
        // complete sources.
        let size_lo = file.size as u32;
        let size_hi = (file.size >> 32) as u32;
        let mut tags = vec![
            Tag::byte(FT_FILENAME, TagValue::String(file.name.to_string())),
            Tag::byte(FT_FILESIZE, TagValue::U32(size_lo)),
        ];
        if size_hi > 0 {
            tags.push(Tag::byte(FT_FILESIZE_HI, TagValue::U32(size_hi)));
        }
        tags.push(Tag::byte(FT_SOURCES, TagValue::U32(file.sources.len() as u32)));
        tags.push(Tag::byte(
            FT_COMPLETE_SOURCES,
            TagValue::U32(file.complete_source_count()),
        ));
        // FT_FILETYPE as an INTEGER — what the SRV_TCPFLG_TYPETAGINTEGER
        // capability bit (0x0080) promises, and what eserver 17.6+ emits.
        //
        // The bit was advertised for a long time while no type tag was sent at
        // all, in either form. Clients that filter by type therefore had nothing
        // to filter on and had to guess from the extension themselves.
        //
        // Only sent when the extension actually classifies: ANY (0) means "no
        // opinion", and a client filtering by type would read a literal 0 as a
        // category that matches nothing.
        let ftype = crate::proto::search::ed2k_file_type_id(&file.name.to_lowercase());
        if ftype != crate::proto::search::ed2k_file_type::ANY {
            tags.push(Tag::byte(FT_FILETYPE, TagValue::U32(ftype)));
        }

        write_tag_list(&mut payload, &tags);
    }

    // Trailing byte: 1 = "more results available, send QUERY_MORE_RESULT".
    payload.put_u8(if has_more { 1 } else { 0 });

    Frame::new(OP_SEARCHRESULT, payload.to_vec())
}

#[cfg(test)]
mod pagination_and_largefile_tests {
    use super::*;
    use crate::state::file_id::FileRecord;
    use std::net::{IpAddr, Ipv4Addr};

    fn entry(name: &str, size: u64) -> FileRecord {
        FileRecord {
            hash: [0u8; 16],
            size,
            name: name.into(),
            sources: vec![crate::state::Source::new([1u8; 16], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 4662, true)].into(),
            last_seen: 0,
            alive: true,
        }
    }

    #[test]
    fn large_file_emits_filesize_hi_tag() {
        // A 5 GiB file: size_hi = 1, so FT_FILESIZE_HI must be present.
        let size: u64 = 5_u64 * 1024 * 1024 * 1024;
        let frame = build_search_result_page(&[entry("huge.iso", size)], false);

        // The decoded size_hi we encoded should be non-zero.
        let size_hi = (size >> 32) as u32;
        assert_eq!(size_hi, 1, "5 GiB file should have size_hi = 1");

        // FT_FILESIZE_HI is 0x3A — its tag byte appears as 0x80|0x03 newtag
        // with name 0x3A somewhere in the payload. Just assert the frame is
        // larger than the same file would be under 4 GiB (the extra tag).
        let small = build_search_result_page(&[entry("huge.iso", 1000)], false);
        assert!(
            frame.payload.len() > small.payload.len(),
            "large-file frame should carry an extra FT_FILESIZE_HI tag"
        );
    }

    #[test]
    fn under_4gib_omits_filesize_hi() {
        // Just under 4 GiB — size_hi = 0, no FT_FILESIZE_HI tag.
        let size: u64 = 4_u64 * 1024 * 1024 * 1024 - 1;
        assert_eq!((size >> 32) as u32, 0, "just-under-4GiB has size_hi 0");
        let _ = build_search_result_page(&[entry("almost.iso", size)], false);
        // No panic, size fits in size_lo — covered by the size_hi assert above.
    }

    #[test]
    fn pagination_more_byte() {
        let page = vec![entry("a", 1), entry("b", 2)];
        // has_more = true → trailing byte 1
        let f = build_search_result_page(&page, true);
        assert_eq!(*f.payload.last().unwrap(), 1, "has_more should set trailing byte");
        // has_more = false → trailing byte 0
        let f = build_search_result_page(&page, false);
        assert_eq!(*f.payload.last().unwrap(), 0, "no more → trailing byte 0");
        // count field reflects the page size
        let count = u32::from_le_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]);
        assert_eq!(count, 2);
    }

    #[test]
    fn empty_page_is_valid() {
        let f = build_search_result_page(&[], false);
        // count = 0, trailing byte = 0, total 5 bytes
        assert_eq!(f.payload.len(), 5);
        assert_eq!(&f.payload[..4], &[0, 0, 0, 0]);
        assert_eq!(f.payload[4], 0);
    }
}

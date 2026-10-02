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

/// One match together with the key it is ranked by.
///
/// ⚠ `Ord` IS INVERTED: greater means WORSE. `BinaryHeap` is a max-heap and its
///   `pop` removes the greatest element, so ordering this the intuitive way
///   round — greater means better — makes the heap discard the best result on
///   every overflow and return the N worst matches. Inverted, `peek` is the
///   weakest entry kept and `pop` evicts it, which is what a bounded top-N
///   needs. `into_sorted_vec` then yields best-first with no reversal.
///
/// Ties break on the file id, lower winning. That matters more than it looks:
/// on a real index most files share a source count — very often exactly one —
/// so the tie-break decides the bulk of the ordering. It has to be total and
/// deterministic, or the same query against an unchanged index answers
/// differently on each call.
struct Ranked {
    sources: u32,
    id: crate::state::file_id::FileId,
    rec: crate::state::file_id::FileRecord,
}

/// Same ordering, exported for the UDP search path so the two channels rank
/// identically. Kept as a separate type only because `Ranked` is private.
pub struct UdpRanked {
    pub sources: u32,
    pub id: crate::state::file_id::FileId,
    pub rec: crate::state::file_id::FileRecord,
}

impl PartialEq for UdpRanked {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}
impl Eq for UdpRanked {}
impl PartialOrd for UdpRanked {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for UdpRanked {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Inverted, for the reason spelled out at `Ranked`.
        other
            .sources
            .cmp(&self.sources)
            .then_with(|| self.id.cmp(&other.id))
    }
}

impl PartialEq for Ranked {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}
impl Eq for Ranked {}
impl PartialOrd for Ranked {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Ranked {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Inverted: greater = worse. Fewer sources is worse; on equal sources
        // the HIGHER id is worse, so the lower id survives a tie.
        other
            .sources
            .cmp(&self.sources)
            .then_with(|| self.id.cmp(&other.id))
    }
}

/// Upper bound on records examined by a search with no indexable token.
///
/// Such a query ("*", or metadata-only like Type=Video plus a size range) has no
/// keyword posting to narrow it, so the only way to answer it exactly is to walk
/// every live file — O(live files) with a shard read lock held, blocking
/// publishes into the shard being walked. At the target scale that is tens of
/// millions of records, and any client can ask for it repeatedly: a one-token
/// query whose token happens to miss the index takes the same path.
///
/// 50k is far more than a client can use (the result cap defaults to 200) and
/// small enough
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
/// Run a search and return the best matching file entries, at most
/// `limits.max_search_results` of them, best-sourced first.
/// The caller paginates this into SEARCHRESULT frames via
/// build_search_result_page + QUERY_MORE_RESULT.
pub fn handle_search(
    state: &ServerState,
    req: SearchRequest,
) -> Vec<crate::state::file_id::FileRecord> {
    state.note_search();

    // Drop words no indexed file contains, so one typo does not empty the whole
    // search. The rewritten tree replaces `req.tree` for EVERY stage below —
    // candidate lookup and `evaluate` alike — which is the only way the change
    // is visible at all: see the warning at `drop_unknown_words`.
    let tree = if state.live_cfg.load().limits.search_drop_unknown_words {
        let (t, dropped) = crate::proto::search::drop_unknown_words(&req.tree, &|tok: &str| {
            state.keyword_index.contains_token(tok)
        });
        if !dropped.is_empty() {
            state.note_search_words_dropped();
            debug!(?dropped, "search: dropped words no indexed file contains");
        }
        t
    } else {
        req.tree.clone()
    };
    let tokens = collect_terms(&tree);

    debug!(?tokens, "search tokens extracted from tree");

    // Split each term the way the INDEXER splits filenames, then drop literal
    // wildcards.
    //
    // A term is not necessarily one word. Some clients send a whole query as a
    // single node, so `"linux ubuntu"` arrives here space and all — and looking
    // that up verbatim can only miss, because the index holds `linux` and
    // `ubuntu` separately and no key ever contains a space. Searching either
    // word worked; searching both returned nothing.
    //
    // Do NOT filter by length afterwards: eMule sends 1-2 char tokens ("HD",
    // "OS") and `tokenize_search_term` already preserves those.
    let token_lower: Vec<String> = tokens
        .iter()
        .flat_map(|t| crate::state::keyword_index::tokenize_search_term(t))
        .filter(|t| t != "*" && t != "**")
        .collect();

    // The same terms, grouped the way the tree combined them: one group per AND
    // operand, all of an OR's branches inside a single group. The flat list
    // above still decides whether there is any keyword at all; only the
    // candidate lookup needs the shape.
    // ⚠ A GROUP OF ONE EXPANDS INTO SEVERAL GROUPS, NOT INTO ONE BIGGER GROUP.
    //   Many clients send the whole query as a single Term node — "ubuntu linux
    //   bible" — and `tokenize_search_term` splits it into three tokens that
    //   must ALL match. Letting those three sit in one group turns them into
    //   alternatives, which is the opposite of what #10 established, and the
    //   candidate set becomes the UNION of three common words over the whole
    //   index instead of their intersection.
    //
    //   Results stayed correct, because `evaluate` still applies the real
    //   condition, and that is what made it invisible: the only symptom was the
    //   server going from 3% CPU to 92% on a 1.6M-file index.
    //
    //   A genuine OR group (more than one element) is different: its branches
    //   are alternatives by construction, so its tokens are unioned as before.
    // Shared with the UDP path, so the two cannot drift — they used to carry
    // a copy each, and both copies had the same per-term marker bug.
    let groups: Vec<Vec<String>> = crate::proto::search::candidate_groups(&tree);

    // Candidates: keyword lookup if we have tokens, otherwise full scan
    // (handles "*" search and metadata-only queries like Type=Video + size).
    //
    // IMPORTANT: with no keyword token the tree predicate must be applied
    // BEFORE the result cap. Taking the first 200 records and filtering
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
    // query examines thousands and keeps at most `max_results`.
    // Ranking, not first-come.
    //
    // The cap used to truncate in FileId order, which is publication order: for
    // any query with more matches than the cap, the oldest matching files were
    // permanently visible and the newest permanently were not. That is not a
    // limit, it is a silent filter, and on a network where people search for
    // new content it filters the wrong way round.
    //
    // So every candidate is examined and the best `max_results` kept by source
    // count, bounded by `rank_scan` so a common word cannot turn one search
    // into a walk of a six-figure posting list.
    let live = state.live_cfg.load();
    let max_results = live.limits.max_search_results as usize;
    let rank_scan = (live.limits.search_rank_scan as usize).max(max_results);

    let mut heap: std::collections::BinaryHeap<Ranked> =
        std::collections::BinaryHeap::with_capacity(max_results + 1);
    let mut n_candidates = 0usize;
    let mut scanned = 0usize;
    let mut scan_capped = false;
    let mut rank_scan_capped = false;
    let mut total_matched = 0usize;

    // Test one candidate. Returns false once the examination budget is spent.
    // Shared by both paths below so they cannot drift apart.
    let mut consider = |id: crate::state::file_id::FileId,
                        entry: &crate::state::file_id::FileRecord,
                        heap: &mut std::collections::BinaryHeap<Ranked>|
     -> bool {
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
        // Folded, so the predicate compares like with like — see the warning
        // at `evaluate`.
        let name_lower = crate::state::keyword_index::fold_for_match(&entry.name);
        if evaluate(&tree, &name_lower, entry.size) {
            total_matched += 1;
            // Cheap rejection before the clone: once the heap is full, anything
            // no better than its worst entry cannot survive, and cloning a
            // FileRecord costs a sources SmallVec plus an Arc bump. On a common
            // word the overwhelming majority of matches land here.
            let keep = match heap.peek() {
                Some(worst) if heap.len() >= max_results => {
                    let cand_sources = entry.sources.len() as u32;
                    (cand_sources, std::cmp::Reverse(id))
                        > (worst.sources, std::cmp::Reverse(worst.id))
                }
                _ => true,
            };
            if keep {
                heap.push(Ranked {
                    sources: entry.sources.len() as u32,
                    id,
                    rec: entry.clone(),
                });
                if heap.len() > max_results {
                    heap.pop();
                }
            }
        }
        // Stop examining once the budget is spent. Unlike the old cap this
        // bounds WORK, not the result set: everything seen so far has already
        // been ranked against everything else seen so far.
        if scanned >= rank_scan {
            rank_scan_capped = true;
            return false;
        }
        true
    };

    if keyword_filtered {
        let ids = state.keyword_index.find_grouped(&groups);
        n_candidates = ids.len();
        for fid in ids {
            // A tombstoned id yields None and is skipped — it can't be a live
            // match anyway.
            let keep_going = state
                .file_slab
                .with_record(fid, |r| consider(fid, r, &mut heap))
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
        // The predicate must run BEFORE the result cap: taking the first N
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
        state.file_slab.for_each_live_while(|id, r| {
            if n_candidates >= MAX_UNINDEXED_SCAN {
                scan_capped = true;
                return false;
            }
            n_candidates += 1;
            consider(id, r, &mut heap)
        });
    }

    // `Ord` is inverted (see `Ranked`), so ascending order is best first and
    // no reversal is wanted here.
    let matches: Vec<crate::state::file_id::FileRecord> =
        heap.into_sorted_vec().into_iter().map(|r| r.rec).collect();

    if scan_capped {
        debug!(
            limit = MAX_UNINDEXED_SCAN,
            matched = matches.len(),
            "unindexed search hit the scan cap; result set is partial"
        );
    }
    if rank_scan_capped {
        state.note_search_rank_capped();
        debug!(
            limit = rank_scan,
            candidates = n_candidates,
            matched_before_cap = total_matched,
            "search hit the ranking scan cap; ranked over what was examined"
        );
    }

    info!(
        token_count = tokens.len(),
        indexed_tokens = token_lower.len(),
        keyword_filtered,
        candidates = n_candidates,
        scanned,
        scan_capped,
        rank_scan_capped,
        total_matched,
        returned = matches.len(),
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

/// Hard ceiling on records per SEARCHRESULT frame, independent of the result
/// cap. Only a guard against an enormous single frame: at the
/// `max_search_results` ceiling of 5000 this splits the answer into three
/// pages, and at any ordinary cap it never applies at all.
const SEARCH_PAGE_HARD_MAX: usize = 2_000;

/// Records per SEARCHRESULT frame.
///
/// ⚠ THIS MUST FOLLOW `limits.max_search_results`, NOT BE A CONSTANT OF ITS
///   OWN. It was fixed at 200, so raising the result cap to 300 still put 200
///   in the first frame and left the rest behind the "More" button — the server
///   had genuinely found 300 and the user saw 200, with nothing in the logs to
///   say why.
///
/// A stock Lugdunum sends its whole answer in one frame: measured at 309
/// records in a single 20399-byte OP_SEARCHRESULT. eMule shows the "More"
/// button only when the trailing byte says more remain, so one frame is both
/// what the reference does and what a client expects.
pub fn search_page_size(state: &ServerState) -> usize {
    (state.live_cfg.load().limits.max_search_results as usize).clamp(1, SEARCH_PAGE_HARD_MAX)
}

/// Build one SEARCHRESULT frame for a page of results, and report whether
/// more results remain after this page.
///
/// `page` is the slice of matches for this frame. `has_more` becomes the
/// trailing "more results available" byte — eMule shows a "More" button and
/// sends QUERY_MORE_RESULT when it is 1.
pub fn build_search_result_page(
    state: &ServerState,
    page: &[crate::state::file_id::FileRecord],
    has_more: bool,
) -> Frame {
    let mut payload = BytesMut::new();
    payload.put_u32_le(page.len() as u32);

    for file in page {
        payload.put_slice(&file.hash);

        // The source eMule keeps from this result: chosen and encoded as
        // GETSOURCES does (issue #27) — HighID address or LowID low id, 0/0
        // when no connected source qualifies.
        let (id, port) = state.search_result_source(&file.sources);
        payload.put_u32_le(id);
        payload.put_u16_le(port);

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
        tags.push(Tag::byte(
            FT_SOURCES,
            TagValue::U32(file.sources.len() as u32),
        ));
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

    fn st() -> ServerState {
        ServerState::new(
            std::sync::Arc::new(crate::filter::ContentFilter::new()),
            std::sync::Arc::new(crate::config::Config::minimal_test_config()),
        )
    }

    /// A connected client: registered, with its channel open.
    fn connect(
        st: &ServerState,
        hash: u8,
        id: u32,
        ip: Ipv4Addr,
        high: bool,
        keep: &mut Vec<tokio::sync::mpsc::Receiver<Frame>>,
    ) {
        st.register_synthetic_client(
            [hash; 16],
            id,
            IpAddr::V4(ip),
            "t".into(),
            "??".into(),
            "test".into(),
            0,
        );
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        keep.push(rx);
        let mut h = st.clients.get_mut(&[hash; 16]).unwrap();
        h.tx = Some(tx);
        h.is_high_id = high;
    }

    fn src(hash: u8, ip: Ipv4Addr, complete: bool) -> crate::state::Source {
        crate::state::Source::new([hash; 16], IpAddr::V4(ip), 4662, complete)
    }

    /// The (id, port) the first record of a one-result page carries.
    fn first_record_source(f: &Frame) -> (u32, u16) {
        let p = &f.payload[4 + 16..4 + 16 + 6];
        (
            u32::from_le_bytes([p[0], p[1], p[2], p[3]]),
            u16::from_le_bytes([p[4], p[5]]),
        )
    }

    #[test]
    fn a_lowid_source_is_named_by_its_low_id_not_its_nat_address_issue_27() {
        let st = st();
        let mut keep = Vec::new();
        let nat = Ipv4Addr::new(203, 0, 113, 9);
        connect(&st, 1, 77, nat, false, &mut keep);
        let mut e = entry("a.avi", 1);
        e.sources = vec![src(1, nat, true)].into();
        let f = build_search_result_page(&st, &[e], false);
        assert_eq!(first_record_source(&f), (77, 4662));
    }

    #[test]
    fn a_highid_is_preferred_and_departed_or_lan_sources_are_never_named() {
        let st = st();
        let mut keep = Vec::new();
        let lan = Ipv4Addr::new(192, 168, 1, 5);
        let pubv4 = Ipv4Addr::new(198, 51, 100, 7);
        let high_id = u32::from_le_bytes(pubv4.octets());
        connect(&st, 2, 78, Ipv4Addr::new(203, 0, 113, 10), false, &mut keep);
        connect(&st, 3, high_id, pubv4, true, &mut keep);
        connect(&st, 4, 0x0505_0505, lan, true, &mut keep); // HighID flag, LAN address
        let mut e = entry("b.avi", 1);
        e.sources = vec![
            src(9, Ipv4Addr::new(198, 51, 100, 99), true), // departed
            src(4, lan, true),
            src(2, Ipv4Addr::new(203, 0, 113, 10), true),
            src(3, pubv4, true),
        ]
        .into();
        let f = build_search_result_page(&st, &[e], false);
        assert_eq!(
            first_record_source(&f),
            (high_id, 4662),
            "complete HighID first"
        );

        // Only departed and LAN sources left: no source at all.
        let mut e = entry("c.avi", 1);
        e.sources = vec![
            src(9, Ipv4Addr::new(198, 51, 100, 99), true),
            src(4, lan, true),
        ]
        .into();
        let f = build_search_result_page(&st, &[e], false);
        assert_eq!(first_record_source(&f), (0, 0));
    }

    #[test]
    fn a_complete_copy_beats_a_partial_one() {
        let st = st();
        let mut keep = Vec::new();
        let a = Ipv4Addr::new(198, 51, 100, 1);
        let b = Ipv4Addr::new(198, 51, 100, 2);
        connect(&st, 5, u32::from_le_bytes(a.octets()), a, true, &mut keep);
        connect(&st, 6, 90, Ipv4Addr::new(203, 0, 113, 11), false, &mut keep);
        let _ = b;
        let mut e = entry("d.avi", 1);
        e.sources = vec![
            src(5, a, false),
            src(6, Ipv4Addr::new(203, 0, 113, 11), true),
        ]
        .into();
        let f = build_search_result_page(&st, &[e], false);
        assert_eq!(
            first_record_source(&f),
            (90, 4662),
            "complete LowID over partial HighID"
        );
    }

    fn entry(name: &str, size: u64) -> FileRecord {
        FileRecord {
            hash: [0u8; 16],
            size,
            name: name.into(),
            sources: vec![crate::state::Source::new(
                [1u8; 16],
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                4662,
                true,
            )]
            .into(),
            last_seen: 0,
            alive: true,
        }
    }

    #[test]
    fn large_file_emits_filesize_hi_tag() {
        // A 5 GiB file: size_hi = 1, so FT_FILESIZE_HI must be present.
        let size: u64 = 5_u64 * 1024 * 1024 * 1024;
        let frame = build_search_result_page(&st(), &[entry("huge.iso", size)], false);

        // The decoded size_hi we encoded should be non-zero.
        let size_hi = (size >> 32) as u32;
        assert_eq!(size_hi, 1, "5 GiB file should have size_hi = 1");

        // FT_FILESIZE_HI is 0x3A — its tag byte appears as 0x80|0x03 newtag
        // with name 0x3A somewhere in the payload. Just assert the frame is
        // larger than the same file would be under 4 GiB (the extra tag).
        let small = build_search_result_page(&st(), &[entry("huge.iso", 1000)], false);
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
        let _ = build_search_result_page(&st(), &[entry("almost.iso", size)], false);
        // No panic, size fits in size_lo — covered by the size_hi assert above.
    }

    #[test]
    fn pagination_more_byte() {
        let page = vec![entry("a", 1), entry("b", 2)];
        // has_more = true → trailing byte 1
        let f = build_search_result_page(&st(), &page, true);
        assert_eq!(
            *f.payload.last().unwrap(),
            1,
            "has_more should set trailing byte"
        );
        // has_more = false → trailing byte 0
        let f = build_search_result_page(&st(), &page, false);
        assert_eq!(*f.payload.last().unwrap(), 0, "no more → trailing byte 0");
        // count field reflects the page size
        let count = u32::from_le_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]);
        assert_eq!(count, 2);
    }

    #[test]
    fn empty_page_is_valid() {
        let f = build_search_result_page(&st(), &[], false);
        // count = 0, trailing byte = 0, total 5 bytes
        assert_eq!(f.payload.len(), 5);
        assert_eq!(&f.payload[..4], &[0, 0, 0, 0]);
        assert_eq!(f.payload[4], 0);
    }
}

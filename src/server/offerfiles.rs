//! OFFERFILES handler (SPEC.md §3.3).
//!
//! Each record describes a file the client wishes to publish as a source.
//! The mandatory content filter (§7.6) runs on every record; matches drop
//! the file silently and increment the publisher's csam_attempts counter.

use crate::filter::FilterResult;
use crate::proto::{
    opcodes::{FT_FILENAME, FT_FILESIZE, FT_FILESIZE_HI, SELF_INCOMPLETE_ID, SELF_INCOMPLETE_PORT},
    tags::{read_tag_list, TagName},
};
use crate::state::{ClientHandle, ServerState};
use anyhow::{anyhow, Result};
use tracing::{debug, info, warn};

#[derive(Debug)]
pub struct OfferedFile {
    pub hash: [u8; 16],
    pub client_id: u32,
    pub port: u16,
    pub filename: String,
    pub size: u64,
}

pub fn parse_offerfiles(payload: &[u8]) -> Result<Vec<OfferedFile>> {
    if payload.len() < 4 {
        return Err(anyhow!("OFFERFILES too short"));
    }
    let count = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if count > 100_000 {
        return Err(anyhow!("OFFERFILES count {} unreasonable", count));
    }

    let mut out = Vec::with_capacity(count as usize);
    let mut slice = &payload[4..];

    for _ in 0..count {
        if slice.len() < 26 {
            return Err(anyhow!("file_record header truncated"));
        }
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&slice[0..16]);
        let client_id = u32::from_le_bytes([slice[16], slice[17], slice[18], slice[19]]);
        let port = u16::from_le_bytes([slice[20], slice[21]]);
        let tag_count = u32::from_le_bytes([slice[22], slice[23], slice[24], slice[25]]);
        slice = &slice[26..];

        if tag_count > 50 {
            return Err(anyhow!("file_record tag_count {} unreasonable", tag_count));
        }

        let mut filename = String::new();
        let mut size_lo: u32 = 0;
        let mut size_hi: u32 = 0;

        for tag in read_tag_list(&mut slice, tag_count) {
            if let TagName::Byte(b) = tag.name {
                match b {
                    FT_FILENAME => {
                        if let Some(s) = tag.str_value() {
                            filename = s.to_string();
                        }
                    }
                    FT_FILESIZE => {
                        if let Some(v) = tag.as_u32() {
                            size_lo = v;
                        }
                    }
                    FT_FILESIZE_HI => {
                        if let Some(v) = tag.as_u32() {
                            size_hi = v;
                        }
                    }
                    _ => {}
                }
            }
        }

        let size = ((size_hi as u64) << 32) | (size_lo as u64);

        out.push(OfferedFile {
            hash,
            client_id,
            port,
            filename,
            size,
        });
    }

    Ok(out)
}

/// Process an OFFERFILES batch. Returns (accepted, blocked) counts.
pub fn handle_offerfiles(
    state: &ServerState,
    client: &mut ClientHandle,
    files: Vec<OfferedFile>,
) -> (u32, u32) {
    let mut accepted = 0u32;
    let mut blocked = 0u32;

    // SOFT FILE LIMIT (`limits.soft_limit_files`, live; 0 = no limit).
    //
    // Lugdunum semantics (issue #18): the soft limit is the indexing budget of
    // one client, counted in files actually indexed for it across all its
    // OFFERFILES. Records beyond it are not indexed, the session stays up, and
    // the client gets one server message per connection saying so. (The HARD
    // limit is a different thing — a per-packet record count, enforced in the
    // connection loop before the packet is parsed; see `over_hard_limit`.)
    //
    // What counts is the number of distinct files this client currently
    // sources (`user_files`), which is what Lugdunum's per-client share count
    // amounts to. Re-offering a hash it already sources is a refresh, not a new
    // file, and is always accepted (Lugdunum ignores refreshes too once the
    // budget is spent; accepting them keeps the complete/partial state current
    // and costs no budget). Records the content filter blocks are never indexed
    // and never counted. Each accepted record is added whole (slab, keyword
    // index, user_files), so a partly accepted batch leaves nothing half-done.
    //
    // A v1 session (issue #19) uses the soft limit it was told at login.
    let soft_limit = match &client.offer_policy {
        Some(p) => p.soft,
        None => state.live_cfg.load().limits.soft_limit_files,
    } as usize;
    let mut sourced = if soft_limit > 0 {
        layer_count(state, &client.user_hash).unwrap_or(0)
    } else {
        0
    };
    let mut over_limit = 0u32;
    // limits.max_string_size (live): names are STORED capped. The content
    // filter above runs on the full name first — see cap_string.
    let max_string = state.live_cfg.load().limits.max_string_size;

    for file in files {
        // Replace placeholder client_id/port with real values.
        // Determine whether the publisher holds a COMPLETE copy of the file.
        // With SRV_TCPFLG_COMPRESSION advertised, eMule 0.49c sends explicit
        // markers in OFFERFILES (SharedFileList.cpp CreateOfferedFilePacket):
        //   client_id 0xFBFBFBFB + port 0xFBFB = complete file
        //   client_id 0xFCFCFCFC + port 0xFCFC = partial file (still downloading)
        // Any other client_id = a real HighID source, which by definition
        // shares a complete file (you don't publish partials with a real ID).
        let has_complete = !matches!(
            (file.client_id, file.port),
            (SELF_INCOMPLETE_ID, SELF_INCOMPLETE_PORT)
        );

        // §7.6: mandatory content filter. Always runs, cannot be skipped.
        match state.filter.check(&file.hash, &file.filename) {
            FilterResult::Block(layer, reason) => {
                blocked += 1;
                // Does this block say anything about the PUBLISHER?
                //
                // For every layer but L5 the answer is yes: the client offered
                // material the filter rejected, and repeat offences end in a ban.
                // L5 is the poisoned-index list — the client is offering a decoy
                // it downloaded like anyone else. The file still must not be
                // indexed, but nothing about the client changes: no csam_attempts,
                // no unique-IP tally, no ban progress. Ask the layer rather than
                // testing it here, so a future layer cannot inherit the wrong
                // treatment by being pattern-matched in the wrong place.
                let counts = layer.counts_against_publisher();
                if counts {
                    client.csam_attempts = client.csam_attempts.saturating_add(1);
                }
                // Count this hash exactly ONCE in block_stats and csam_unique_ips.
                // Without dedup, a client republishing the same blocked file every
                // keepalive cycle inflated counters massively (observed 464925
                // counted blocks against only 264700 indexed files in production).
                let is_new_hash = state
                    .csam_blocked_hashes
                    .insert(file.hash, std::time::Instant::now())
                    .is_none();
                if is_new_hash {
                    // Keep the headline "csam" counter meaning CSAM. Poisoned-index
                    // hits get their own total; folding them in would inflate the
                    // number the operator reports and watches for trends.
                    let total_key = if counts { "csam" } else { "poison" };
                    *state.block_stats.entry(total_key.to_string()).or_insert(0) += 1;
                    // Break down by layer so the operator can see WHICH filter
                    // catches most files — helps spot if a specific layer is
                    // producing false positives.
                    *state
                        .block_stats
                        .entry(layer.stat_key().to_string())
                        .or_insert(0) += 1;
                    if counts {
                        *state
                            .csam_unique_ips
                            .entry(state.source_key(client.ip))
                            .or_insert(0) += 1;
                    }
                }
                // Q1: ban CSAM publishers by USER_HASH (stable across the IP
                // changes that are common for these clients). Counts DISTINCT
                // blocked file hashes per user — republishing the SAME (possibly
                // false-positive) file never advances the count past 1, so a
                // single rare FP can never accumulate to a ban across reconnects.
                // Done OUTSIDE the global is_new_hash guard because that dedup is
                // server-wide; we need a PER-USER distinct-file count here.
                if counts {
                    let cfg = state.live_cfg.load();
                    let threshold = cfg.content_filter.publisher_attempt_disconnect_threshold;
                    // Two different windows: files count toward the threshold over
                    // `count_window` (short — judge recent behaviour), while the
                    // records themselves are retained for `ban_ttl` so the review
                    // exports keep their history.
                    let count_window = cfg.content_filter.count_window();
                    let retention = cfg.content_filter.ban_ttl();
                    if state.record_csam_file_for_user(
                        client.user_hash,
                        file.hash,
                        &file.filename,
                        file.size,
                        layer,
                        &reason,
                        threshold,
                        count_window,
                        retention,
                    ) {
                        // Threshold of distinct blocked files reached. ban_publisher
                        // is idempotent (it reports whether the ban was newly
                        // added), so log the ban line exactly ONCE — not once per
                        // remaining file in the batch. A single OFFERFILES packet
                        // can carry hundreds of files; before this, a spammer who
                        // tripped the threshold at file #3 produced one ban log per
                        // file (152 lines seen in production for a 152-file batch)
                        // and the server kept filtering the rest of the batch for a
                        // client it had already banned.
                        if state.ban_publisher_is_new(client.user_hash) {
                            warn!(
                                publisher_user_hash = hex::encode(client.user_hash),
                                threshold, "csam publisher threshold reached — user_hash banned"
                            );
                        }
                        // Log this blocked file (it counts toward the totals) then
                        // stop processing the remainder of the batch: the publisher
                        // is banned, every further record would only be blocked too,
                        // and the connection loop will drop the session on the
                        // csam_attempts threshold. This preserves the "3+ distinct
                        // files => ban" rule (the ban already fired) while cutting
                        // the redundant work and log spam.
                        use sha2::Digest;
                        let mut hasher = sha2::Sha256::new();
                        hasher.update(file.filename.as_bytes());
                        let name_sha = hex::encode(hasher.finalize());
                        warn!(
                            publisher_ip = %client.ip,
                            publisher_user_hash = hex::encode(client.user_hash),
                            layer = ?layer,
                            file_hash = hex::encode(file.hash),
                            filename_sha256 = %name_sha,
                            csam_attempt_count = client.csam_attempts,
                            "csam_publish_blocked"
                        );
                        if let Some(mut entry) = state.clients.get_mut(&client.user_hash) {
                            entry.csam_attempts = client.csam_attempts;
                        }
                        break;
                    }
                }
                use sha2::Digest;
                let mut hasher = sha2::Sha256::new();
                hasher.update(file.filename.as_bytes());
                let name_sha = hex::encode(hasher.finalize());
                if counts {
                    warn!(
                        publisher_ip = %client.ip,
                        publisher_user_hash = hex::encode(client.user_hash),
                        layer = ?layer,
                        file_hash = hex::encode(file.hash),
                        filename_sha256 = %name_sha,
                        csam_attempt_count = client.csam_attempts,
                        "csam_publish_blocked"
                    );
                } else {
                    // INFO, not WARN: a decoy is routine and carries no accusation.
                    // The health tab's ring buffer only keeps WARN/ERROR, and a
                    // poisoned swarm can touch thousands of files — logging these
                    // at WARN would evict the records an operator actually needs.
                    info!(
                        publisher_ip = %client.ip,
                        file_hash = hex::encode(file.hash),
                        filename_sha256 = %name_sha,
                        "poisoned_index_publish_blocked"
                    );
                }
                continue;
            }
            FilterResult::Allow => {}
        }

        if soft_limit > 0 && sourced >= soft_limit && !already_sources(state, client, &file.hash) {
            over_limit += 1;
            continue;
        }

        // Index the file with this client as a source.
        let source = (client.user_hash, client.ip, client.port, has_complete);
        let stored_name = crate::proto::tags::cap_string(&file.filename, max_string).to_string();
        state.add_file_with_source(file.hash, file.size, stored_name, source);
        accepted += 1;

        if tracing::enabled!(tracing::Level::DEBUG) {
            debug!(
                hash = hex::encode(file.hash),
                size = file.size,
                name = %file.filename,
                "offerfiles indexed"
            );
        }

        // Update the actual client's record in the table (csam counter)
        if let Some(mut entry) = state.clients.get_mut(&client.user_hash) {
            entry.csam_attempts = client.csam_attempts;
        }

        // §7.6.5: thresholded disconnect handled at the connection-loop level
        // by inspecting csam_attempts; not here.

        if soft_limit > 0 {
            sourced = layer_count(state, &client.user_hash).unwrap_or(sourced);
        }
    }

    if over_limit > 0 {
        state.note_offer_over_soft_limit(over_limit);
        // The caller sends the server message when this flips to true.
        let first = !client.soft_limit_warned;
        client.soft_limit_warned = true;
        // INFO, once per connection: a client at the limit re-offers roughly
        // every minute, and the health tab keeps only WARN/ERROR.
        if first {
            info!(
                ip = %client.ip,
                nick = %client.nick,
                soft_limit,
                sourced,
                not_indexed = over_limit,
                "offerfiles: soft file limit reached, further new files not indexed"
            );
        }
    }

    if accepted > 0 || blocked > 0 {
        info!(
            ip = %client.ip,
            nick = %client.nick,
            accepted,
            blocked,
            total_files = state.file_count(),
            "offerfiles processed"
        );
    }

    (accepted, blocked)
}

/// The record count an OFFERFILES payload declares (its first four bytes).
pub fn declared_count(payload: &[u8]) -> Option<u32> {
    payload
        .get(..4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// HARD FILE LIMIT (`limits.hard_limit_files`, live; 0 = no limit).
///
/// Lugdunum semantics (issue #18): a per-packet boundary on the declared
/// record count. A packet declaring `>= hard` records is rejected before any
/// record is read, and the connection is closed. Lugdunum uses `>=` for plain
/// packets and `>` for compressed ones; this server applies `>=` to both (the
/// payload is already decompressed here), which is the rule a client can rely
/// on: every OFFERFILES strictly below ST_HARDFILES.
pub fn over_hard_limit(declared: u32, hard: u32) -> bool {
    hard > 0 && declared >= hard
}

/// The server message Lugdunum sends, once per connection, when the soft limit
/// stops indexing. Same text, so tools that recognise it keep working.
pub fn soft_limit_message(soft: u32) -> String {
    format!(
        "WARNING : This server accepts {soft} shares per client. Some of your shares are ignored."
    )
}

/// Does this client already source `hash`? A re-offer of such a file is a
/// refresh and does not count against the soft limit.
fn already_sources(state: &ServerState, client: &ClientHandle, hash: &[u8; 16]) -> bool {
    let Some(id) = state.file_slab.id_of(hash) else {
        return false;
    };
    state
        .user_files
        .get(&client.user_hash)
        .is_some_and(|set| set.contains(&id))
}

/// Number of files this user is currently sourcing. O(1) via the user_files
/// reverse index — before v0.9.36 this was O(N) over the whole file table,
/// which dominated CPU at scale (62%+ in production profile at 250k files).
fn layer_count(state: &ServerState, user_hash: &[u8; 16]) -> Option<usize> {
    Some(state.user_files.get(user_hash).map_or(0, |s| s.len()))
}

#[cfg(test)]
mod large_file_tests {
    use super::*;
    use crate::filter::ContentFilter;
    use crate::state::ServerState;
    use std::sync::Arc;

    #[test]
    fn offerfiles_accepts_file_over_4gib() {
        // Build an OFFERFILES payload for a single 5 GiB file. The size is
        // split across FT_FILESIZE (low 32 bits) and FT_FILESIZE_HI (high 32),
        // exactly how eMule sends it when the server advertised LARGEFILES.
        let size_64: u64 = 5_u64 * 1024 * 1024 * 1024; // 5 GiB
        let size_lo = size_64 as u32;
        let size_hi = (size_64 >> 32) as u32;
        assert_eq!(size_hi, 1, "5 GiB → high word = 1");

        let fname = b"huge-iso-image.iso";
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes()); // file_count

        // file record: hash(16) + client_id(4) + port(2) + tag_count(4) + tags
        payload.extend_from_slice(&[0x77; 16]); // hash
        payload.extend_from_slice(&0xFBFB_FBFBu32.to_le_bytes()); // complete marker
        payload.extend_from_slice(&0xFBFBu16.to_le_bytes()); // port marker
        payload.extend_from_slice(&3u32.to_le_bytes()); // tag_count = 3

        // FT_FILENAME (newtag string with 1-byte name)
        payload.push(0x82);
        payload.push(FT_FILENAME);
        payload.extend_from_slice(&(fname.len() as u16).to_le_bytes());
        payload.extend_from_slice(fname);

        // FT_FILESIZE (newtag uint32, low 32 bits)
        payload.push(0x83);
        payload.push(FT_FILESIZE);
        payload.extend_from_slice(&size_lo.to_le_bytes());

        // FT_FILESIZE_HI (newtag uint32, high 32 bits)
        payload.push(0x83);
        payload.push(FT_FILESIZE_HI);
        payload.extend_from_slice(&size_hi.to_le_bytes());

        let files = parse_offerfiles(&payload).expect("parse should succeed");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].size, size_64, "full 5 GiB size must round-trip");
        assert_eq!(files[0].filename, "huge-iso-image.iso");

        // End-to-end through state: file should be searchable AND the search
        // result should carry an FT_FILESIZE_HI tag.
        let filter = Arc::new(ContentFilter::new());
        let state = ServerState::new(
            filter,
            std::sync::Arc::new(crate::config::Config::minimal_test_config()),
        );
        state.add_file_with_source(
            files[0].hash,
            files[0].size,
            files[0].filename.clone(),
            (
                [1u8; 16],
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                4662,
                true,
            ),
        );

        let entry = state
            .file_slab
            .get_by_hash(&files[0].hash)
            .expect("indexed");
        assert_eq!(entry.size, size_64, "stored size still 5 GiB");
    }
}

#[cfg(test)]
mod soft_limit_tests {
    //! `limits.soft_limit_files` and `limits.soft_limit_files` (issue #18).
    use super::*;
    use crate::filter::ContentFilter;
    use crate::proto::{SELF_COMPLETE_ID, SELF_COMPLETE_PORT};
    use crate::state::ServerState;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Instant;

    fn state_with(soft: u32, filter: ContentFilter) -> ServerState {
        let mut cfg = crate::config::Config::minimal_test_config();
        cfg.limits.soft_limit_files = soft;
        ServerState::new(Arc::new(filter), Arc::new(cfg))
    }

    fn set_live_limit(state: &ServerState, soft: u32) {
        let mut cfg = (**state.live_cfg.load()).clone();
        cfg.limits.soft_limit_files = soft;
        state.live_cfg.store(Arc::new(cfg));
    }

    fn client() -> ClientHandle {
        ClientHandle {
            user_hash: [9; 16],
            assigned_id: 0x0A00_0001,
            ip: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 10)),
            port: 4662,
            udp_port: 0,
            natt_capable: false,
            nick: "t".into(),
            server_flags: 0,
            ipv6_capable: false,
            ipv6: None,
            is_high_id: true,
            connected_at: Instant::now(),
            country: "??".into(),
            software: "test".into(),
            csam_attempts: 0,
            soft_limit_warned: false,
            offer_policy: None,
            slot: Default::default(),
            tx: None,
            last_activity_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Distinct files `from..to`, each with its own hash and an innocent name.
    fn files(from: u16, to: u16) -> Vec<OfferedFile> {
        (from..to)
            .map(|n| {
                let mut hash = [0u8; 16];
                hash[..2].copy_from_slice(&n.to_le_bytes());
                hash[15] = 0x5A;
                OfferedFile {
                    hash,
                    client_id: SELF_COMPLETE_ID,
                    port: SELF_COMPLETE_PORT,
                    filename: format!("holiday clip number {n}.avi"),
                    size: 1_000_000 + n as u64,
                }
            })
            .collect()
    }

    fn sourced(state: &ServerState, c: &ClientHandle) -> usize {
        state.user_files.get(&c.user_hash).map_or(0, |s| s.len())
    }

    #[test]
    fn a_client_below_the_limit_is_untouched() {
        let state = state_with(10, ContentFilter::new());
        let mut c = client();
        assert_eq!(handle_offerfiles(&state, &mut c, files(0, 5)), (5, 0));
        assert_eq!(sourced(&state, &c), 5);
        assert_eq!(state.offer_over_soft_stats(), (0, 0));
    }

    #[test]
    fn a_batch_ending_exactly_at_the_limit_is_accepted_whole() {
        let state = state_with(5, ContentFilter::new());
        let mut c = client();
        assert_eq!(handle_offerfiles(&state, &mut c, files(0, 5)), (5, 0));
        assert_eq!(sourced(&state, &c), 5);
        assert_eq!(state.offer_over_soft_stats(), (0, 0));
    }

    #[test]
    fn a_batch_crossing_the_limit_is_cut_at_it_and_counted() {
        let state = state_with(5, ContentFilter::new());
        let mut c = client();
        assert_eq!(handle_offerfiles(&state, &mut c, files(0, 8)), (5, 0));
        assert_eq!(sourced(&state, &c), 5);
        assert_eq!(state.offer_over_soft_stats(), (1, 3));
        // The records past the limit left nothing behind in the index.
        for f in files(5, 8) {
            assert!(state.file_slab.get_by_hash(&f.hash).is_none());
        }
        // A later batch of new files gets nothing more in.
        assert_eq!(handle_offerfiles(&state, &mut c, files(8, 11)), (0, 0));
        assert_eq!(sourced(&state, &c), 5);
        assert_eq!(state.offer_over_soft_stats(), (2, 6));
    }

    #[test]
    fn republishing_files_already_sourced_is_always_accepted() {
        let state = state_with(5, ContentFilter::new());
        let mut c = client();
        handle_offerfiles(&state, &mut c, files(0, 5));
        // At the limit: the same five again are refreshes, not new files.
        assert_eq!(handle_offerfiles(&state, &mut c, files(0, 5)), (5, 0));
        assert_eq!(sourced(&state, &c), 5);
        assert_eq!(state.offer_over_soft_stats(), (0, 0));
        // Mixed: known ones refresh, the new ones stop at the limit.
        assert_eq!(handle_offerfiles(&state, &mut c, files(3, 9)), (2, 0));
        assert_eq!(state.offer_over_soft_stats(), (1, 4));
    }

    #[test]
    fn a_non_default_limit_is_the_one_applied() {
        let state = state_with(3, ContentFilter::new());
        let mut c = client();
        assert_eq!(handle_offerfiles(&state, &mut c, files(0, 10)), (3, 0));
        assert_eq!(sourced(&state, &c), 3);
    }

    #[test]
    fn zero_means_no_limit() {
        let state = state_with(0, ContentFilter::new());
        let mut c = client();
        assert_eq!(handle_offerfiles(&state, &mut c, files(0, 50)), (50, 0));
        assert_eq!(state.offer_over_soft_stats(), (0, 0));
    }

    #[test]
    fn the_limit_follows_the_live_configuration() {
        let state = state_with(4, ContentFilter::new());
        let mut c = client();
        assert_eq!(handle_offerfiles(&state, &mut c, files(0, 6)), (4, 0));
        // Raised: the next batch fills up to the new value.
        set_live_limit(&state, 7);
        assert_eq!(handle_offerfiles(&state, &mut c, files(4, 10)), (3, 0));
        assert_eq!(sourced(&state, &c), 7);
        // Lowered: nothing already indexed is evicted, nothing new gets in.
        set_live_limit(&state, 2);
        assert_eq!(handle_offerfiles(&state, &mut c, files(20, 22)), (0, 0));
        assert_eq!(sourced(&state, &c), 7);
        // Known files still refresh below or above the new value.
        assert_eq!(handle_offerfiles(&state, &mut c, files(0, 2)), (2, 0));
    }

    #[test]
    fn files_the_filter_blocks_do_not_use_up_the_limit() {
        let filter = ContentFilter::new().with_extra_terms(["qxzmarker".to_string()]);
        let state = state_with(2, filter);
        let mut c = client();
        let mut batch = files(0, 3);
        batch[0].filename = "qxzmarker clip.avi".into();
        // One blocked, two accepted — the blocked record did not take a slot.
        assert_eq!(handle_offerfiles(&state, &mut c, batch), (2, 1));
        assert_eq!(sourced(&state, &c), 2);
        assert_eq!(state.offer_over_soft_stats(), (0, 0));
    }

    #[test]
    fn the_message_is_flagged_once_per_connection() {
        let state = state_with(2, ContentFilter::new());
        let mut c = client();
        handle_offerfiles(&state, &mut c, files(0, 2));
        assert!(!c.soft_limit_warned, "at the limit, nothing ignored yet");
        handle_offerfiles(&state, &mut c, files(2, 4));
        assert!(c.soft_limit_warned);
        // Further batches over the limit keep counting but do not re-arm it.
        handle_offerfiles(&state, &mut c, files(4, 6));
        assert!(c.soft_limit_warned);
        assert_eq!(state.offer_over_soft_stats(), (2, 4));
        // A new connection starts unwarned.
        assert!(!client().soft_limit_warned);
    }

    #[test]
    fn the_message_text_is_lugdunums() {
        assert_eq!(
            soft_limit_message(1000),
            "WARNING : This server accepts 1000 shares per client. Some of your shares are ignored."
        );
    }

    #[test]
    fn hard_limit_is_a_per_packet_bound_on_the_declared_count() {
        assert!(!over_hard_limit(199, 200));
        assert!(
            over_hard_limit(200, 200),
            ">= rejects, as Lugdunum does for plain packets"
        );
        assert!(over_hard_limit(5000, 200));
        assert!(!over_hard_limit(u32::MAX, 0), "0 = no limit");
    }

    #[test]
    fn declared_count_reads_the_first_four_bytes() {
        assert_eq!(declared_count(&[0xC8, 0, 0, 0, 0xFF]), Some(200));
        assert_eq!(declared_count(&[1, 2, 3]), None);
    }
}

#[cfg(test)]
mod string_size_tests {
    //! `limits.max_string_size` on stored file names.
    use super::*;
    use crate::filter::ContentFilter;
    use crate::proto::{SELF_COMPLETE_ID, SELF_COMPLETE_PORT};
    use crate::state::ServerState;
    use std::sync::Arc;

    fn state_with(max: u32, filter: ContentFilter) -> ServerState {
        let mut cfg = crate::config::Config::minimal_test_config();
        cfg.limits.max_string_size = max;
        ServerState::new(Arc::new(filter), Arc::new(cfg))
    }

    fn offer(name: &str, n: u8) -> OfferedFile {
        OfferedFile {
            hash: [n; 16],
            client_id: SELF_COMPLETE_ID,
            port: SELF_COMPLETE_PORT,
            filename: name.to_string(),
            size: 123_456,
        }
    }

    fn client() -> ClientHandle {
        ClientHandle {
            user_hash: [3; 16],
            assigned_id: 0x0A00_0003,
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 0, 0, 3)),
            port: 4662,
            udp_port: 0,
            natt_capable: false,
            nick: "t".into(),
            server_flags: 0,
            ipv6_capable: false,
            ipv6: None,
            is_high_id: true,
            connected_at: std::time::Instant::now(),
            country: "??".into(),
            software: "test".into(),
            csam_attempts: 0,
            soft_limit_warned: false,
            offer_policy: None,
            slot: Default::default(),
            tx: None,
            last_activity_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    #[test]
    fn a_long_name_is_stored_capped() {
        let state = state_with(20, ContentFilter::new());
        let mut c = client();
        let name = "a very long holiday clip name that goes on.avi";
        assert_eq!(
            handle_offerfiles(&state, &mut c, vec![offer(name, 1)]),
            (1, 0)
        );
        let rec = state.file_slab.get_by_hash(&[1; 16]).unwrap();
        assert_eq!(rec.name(), &name[..20]);
    }

    #[test]
    fn the_filter_sees_the_whole_name_before_the_cap() {
        // The marker sits past the cut. Capping first would let it through.
        let filter = ContentFilter::new().with_extra_terms(["qxzmarker".to_string()]);
        let state = state_with(20, filter);
        let mut c = client();
        let name = "an ordinary long clip name then qxzmarker.avi";
        assert_eq!(
            handle_offerfiles(&state, &mut c, vec![offer(name, 2)]),
            (0, 1)
        );
        assert!(state.file_slab.get_by_hash(&[2; 16]).is_none());
    }

    #[test]
    fn zero_stores_names_whole() {
        let state = state_with(0, ContentFilter::new());
        let mut c = client();
        let name = "x".repeat(600) + ".avi";
        handle_offerfiles(&state, &mut c, vec![offer(&name, 3)]);
        assert_eq!(
            state.file_slab.get_by_hash(&[3; 16]).unwrap().name().len(),
            604
        );
    }
}

//! OFFERFILES handler (SPEC.md §3.3).
//!
//! Each record describes a file the client wishes to publish as a source.
//! The mandatory content filter (§7.6) runs on every record; matches drop
//! the file silently and increment the publisher's csam_attempts counter.

use crate::filter::FilterResult;
use crate::proto::{
    opcodes::{
        FT_FILENAME, FT_FILESIZE, FT_FILESIZE_HI, SELF_COMPLETE_ID, SELF_COMPLETE_PORT,
        SELF_INCOMPLETE_ID, SELF_INCOMPLETE_PORT,
    },
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
                    FT_FILENAME  => { if let Some(s) = tag.str_value() { filename = s.to_string(); } }
                    FT_FILESIZE  => { if let Some(v) = tag.as_u32() { size_lo = v; } }
                    FT_FILESIZE_HI => { if let Some(v) = tag.as_u32() { size_hi = v; } }
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

        // Per SPEC.md §3.3, 0xFBFBFBFB / 0xFCFCFCFC + matching port = self-source.
        let _is_self_source = matches!(
            (file.client_id, file.port),
            (SELF_COMPLETE_ID, SELF_COMPLETE_PORT) | (SELF_INCOMPLETE_ID, SELF_INCOMPLETE_PORT)
        );

        // §7.6: mandatory content filter. Always runs, cannot be skipped.
        match state.filter.check(&file.hash, &file.filename) {
            FilterResult::Block(layer) => {
                blocked += 1;
                client.csam_attempts = client.csam_attempts.saturating_add(1);
                // Count this hash exactly ONCE in block_stats and csam_unique_ips.
                // Without dedup, a client republishing the same blocked file every
                // keepalive cycle inflated counters massively (observed 464925
                // counted blocks against only 264700 indexed files in production).
                let is_new_hash = state.csam_blocked_hashes.insert(file.hash, ()).is_none();
                if is_new_hash {
                    *state.block_stats.entry("csam".to_string()).or_insert(0) += 1;
                    // Break down by layer so the operator can see WHICH filter
                    // catches most files — helps spot if a specific layer is
                    // producing false positives.
                    let layer_key = match layer {
                        crate::filter::Layer::L1Jargon     => "csam_L1_jargon",
                        crate::filter::Layer::L2AgePattern => "csam_L2_age",
                        crate::filter::Layer::L3HashBlock  => "csam_L3_hash",
                        crate::filter::Layer::L4Extra      => "csam_L4_extra",
                    };
                    *state.block_stats.entry(layer_key.to_string()).or_insert(0) += 1;
                    if let std::net::IpAddr::V4(v4) = client.ip {
                        *state.csam_unique_ips.entry(v4).or_insert(0) += 1;
                    }
                }
                // Q1: ban CSAM publishers by USER_HASH (stable across the IP
                // changes that are common for these clients). Counts DISTINCT
                // blocked file hashes per user — republishing the SAME (possibly
                // false-positive) file never advances the count past 1, so a
                // single rare FP can never accumulate to a ban across reconnects.
                // Done OUTSIDE the global is_new_hash guard because that dedup is
                // server-wide; we need a PER-USER distinct-file count here.
                {
                    let cfg = state.live_cfg.load();
                    let threshold = cfg.content_filter.publisher_attempt_disconnect_threshold;
                    let ttl = std::time::Duration::from_secs(
                        cfg.content_filter.publisher_blacklist_seconds);
                    if state.record_csam_file_for_user(
                        client.user_hash, file.hash, threshold, ttl)
                    {
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
                            warn!(publisher_user_hash = hex::encode(client.user_hash),
                                  threshold, "csam publisher threshold reached — user_hash banned");
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
                warn!(
                    publisher_ip = %client.ip,
                    publisher_user_hash = hex::encode(client.user_hash),
                    layer = ?layer,
                    file_hash = hex::encode(file.hash),
                    filename_sha256 = %name_sha,
                    csam_attempt_count = client.csam_attempts,
                    "csam_publish_blocked"
                );
                continue;
            }
            FilterResult::Allow => {}
        }

        // Index the file with this client as a source.
        let source = (client.user_hash, client.ip, client.port, has_complete);
        state.add_file_with_source(file.hash, file.size, file.filename.clone(), source);
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

        // Light hard_limit policy
        if matches!(layer_count(state, &client.user_hash), Some(n) if n > 4000) {
            // SPEC.md §3.3 says drop connection on hard_limit. The handler
            // returns its accumulated counts; the caller will check the
            // connection state and disconnect. (MVP shortcut.)
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
        payload.extend_from_slice(&[0x77; 16]);                       // hash
        payload.extend_from_slice(&0xFBFB_FBFBu32.to_le_bytes());     // complete marker
        payload.extend_from_slice(&0xFBFBu16.to_le_bytes());           // port marker
        payload.extend_from_slice(&3u32.to_le_bytes());               // tag_count = 3

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
        let state = ServerState::new(filter, std::sync::Arc::new(crate::config::Config::minimal_test_config()));
        state.add_file_with_source(
            files[0].hash,
            files[0].size,
            files[0].filename.clone(),
            ([1u8; 16], std::net::IpAddr::V4(std::net::Ipv4Addr::new(10,0,0,1)), 4662, true),
        );

        let entry = state.file_slab.get_by_hash(&files[0].hash).expect("indexed");
        assert_eq!(entry.size, size_64, "stored size still 5 GiB");
    }
}

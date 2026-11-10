//! End-to-end test: spin up the server, connect a fake client, exercise
//! login → OFFERFILES → SEARCH → GETSOURCES, validate every reply.
//!
//! This is the "real client" integration target — if this passes, an
//! actual eMule should also be able to talk to us.

use bytes::{BufMut, BytesMut};
use ed2k_server::config::Config;
use ed2k_server::filter::ContentFilter;
use ed2k_server::proto::CryptStream;
use ed2k_server::proto::{opcodes::*, Ed2kCodec, Frame};
use ed2k_server::server::connection::handle_connection;
use ed2k_server::state::ServerState;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

/// Build a default test config.
fn test_config(port: u16) -> Config {
    let toml = format!(
        r#"
[server]
name = "Test eD2k"
desc = "integration test"
public = false

[network]
tcp_port = {port}
listen_ip = "127.0.0.1"
max_frame_size = 1000000

[limits]
max_clients = 100
soft_limit_files = 1000
hard_limit_files = 4000
max_clients_per_ip = 10
max_string_size = 250

[content_filter]
publisher_attempt_disconnect_threshold = 3
publisher_blacklist_seconds = 86400

[welcome]
messages = ["Welcome", "Test build"]

[log]
level = "info"
"#
    );
    toml::from_str(&toml).unwrap()
}

async fn spawn_test_server() -> (u16, Arc<ServerState>) {
    // Bind on port 0 to let OS choose a free port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let cfg = Arc::new(test_config(port));
    let filter = Arc::new(ContentFilter::new());
    let state = Arc::new(ServerState::new(filter, Arc::clone(&cfg)));

    let cfg_t = Arc::clone(&cfg);
    let state_t = Arc::clone(&state);
    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            let cfg = Arc::clone(&cfg_t);
            let state = Arc::clone(&state_t);
            tokio::spawn(async move {
                let crypt = CryptStream::plain(stream);
                let _ = handle_connection(cfg, state, crypt, peer).await;
            });
        }
    });

    // Give the server a tick to start accepting
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (port, state)
}

/// Build a LOGINREQUEST payload (SPEC.md §3.1.3).
fn build_login(user_hash: [u8; 16], port: u16, nick: &str) -> Vec<u8> {
    let mut p = BytesMut::new();
    p.put_slice(&user_hash);
    p.put_u32_le(0); // claimed_id, 0.0.0.0
    p.put_u16_le(port);
    p.put_u32_le(2); // tag count

    // CT_NAME tag (newtags + STR1..16 if short)
    p.put_u8(0x82); // newtags + STRING
    p.put_u8(CT_NAME);
    p.put_u16_le(nick.len() as u16);
    p.put_slice(nick.as_bytes());

    // CT_SERVER_FLAGS tag
    p.put_u8(0x83); // newtags + UINT32
    p.put_u8(CT_SERVER_FLAGS);
    p.put_u32_le(CAPABLE_NEWTAGS | CAPABLE_UNICODE | CAPABLE_LARGEFILES | CAPABLE_ZLIB);

    p.to_vec()
}

/// Build an OFFERFILES payload with a single file.
fn build_offerfiles(hash: [u8; 16], filename: &str, size: u64) -> Vec<u8> {
    let mut p = BytesMut::new();
    p.put_u32_le(1); // count

    // file_record
    p.put_slice(&hash);
    p.put_u32_le(SELF_COMPLETE_ID); // self
    p.put_u16_le(SELF_COMPLETE_PORT);

    let size_lo = size as u32;
    let size_hi = (size >> 32) as u32;
    let tag_count: u32 = if size_hi > 0 { 3 } else { 2 };
    p.put_u32_le(tag_count);

    // FT_FILENAME (STRING)
    p.put_u8(0x82);
    p.put_u8(FT_FILENAME);
    p.put_u16_le(filename.len() as u16);
    p.put_slice(filename.as_bytes());

    // FT_FILESIZE (UINT32)
    p.put_u8(0x83);
    p.put_u8(FT_FILESIZE);
    p.put_u32_le(size_lo);

    // FT_FILESIZE_HI (UINT32) only if >4 GiB
    if size_hi > 0 {
        p.put_u8(0x83);
        p.put_u8(FT_FILESIZE_HI);
        p.put_u32_le(size_hi);
    }

    p.to_vec()
}

/// Build a SEARCHREQUEST containing a single Term node.
fn build_search_term(term: &str) -> Vec<u8> {
    let mut p = BytesMut::new();
    p.put_u8(0x01); // NODE_STRING
    p.put_u16_le(term.len() as u16);
    p.put_slice(term.as_bytes());
    p.to_vec()
}

#[tokio::test]
async fn full_client_lifecycle() {
    let (port, state) = spawn_test_server().await;

    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let codec = Ed2kCodec::new(1_000_000);
    let mut framed = Framed::new(stream, codec);

    // 1. LOGIN
    let user_hash = [0xAAu8; 16];
    framed
        .send(Frame::new(
            OP_LOGINREQUEST,
            build_login(user_hash, 4001, "test-client"),
        ))
        .await
        .unwrap();

    // 2. Receive welcome batch (4 frames: IDCHANGE, SERVERSTATUS,
    //    SERVERMESSAGE×1 [welcome[0]], SERVERMESSAGE [welcome[1]]). No
    //    SERVERIDENT for a legacy client: it comes with the server list, as
    //    from Lugdunum (see login::ident_at_login).
    let mut got_idchange = false;
    let mut got_status = false;
    let mut got_message_count = 0;
    let mut got_ident = false;
    for _ in 0..4 {
        let f = tokio::time::timeout(std::time::Duration::from_secs(2), framed.next())
            .await
            .expect("timeout reading welcome frame")
            .expect("connection closed during welcome")
            .expect("frame error");
        match f.opcode {
            OP_IDCHANGE => got_idchange = true,
            OP_SERVERSTATUS => got_status = true,
            OP_SERVERMESSAGE => got_message_count += 1,
            OP_SERVERIDENT => got_ident = true,
            _ => {}
        }
    }
    assert!(got_idchange, "must receive IDCHANGE");
    assert!(got_status, "must receive SERVERSTATUS");
    assert!(
        got_message_count >= 1,
        "must receive at least one SERVERMESSAGE"
    );
    assert!(!got_ident, "no SERVERIDENT at login for a legacy client");

    // 2b. GETSERVERLIST → SERVERLIST, then SERVERIDENT.
    framed.send(Frame::new(0x14, vec![])).await.unwrap();
    let mut order = Vec::new();
    for _ in 0..2 {
        let f = tokio::time::timeout(std::time::Duration::from_secs(2), framed.next())
            .await
            .expect("timeout reading server list answer")
            .expect("connection closed")
            .expect("frame error");
        order.push(f.opcode);
    }
    assert_eq!(order, vec![0x32, OP_SERVERIDENT], "list first, then ident");

    // 3. OFFERFILES — publish a legitimate file
    let file_hash = [0xBBu8; 16];
    framed
        .send(Frame::new(
            OP_OFFERFILES,
            build_offerfiles(file_hash, "Linux Mint 22.iso", 2_000_000_000),
        ))
        .await
        .unwrap();

    // Brief wait for indexing
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // 4. SEARCH for "linux"
    framed
        .send(Frame::new(OP_SEARCHREQUEST, build_search_term("linux")))
        .await
        .unwrap();

    let result = framed.next().await.unwrap().unwrap();
    assert_eq!(result.opcode, OP_SEARCHRESULT);

    // SEARCHRESULT: count(4) + records + more(1)
    let count = u32::from_le_bytes([
        result.payload[0],
        result.payload[1],
        result.payload[2],
        result.payload[3],
    ]);
    assert_eq!(count, 1, "search for 'linux' should match published file");

    // 5. GETSOURCES for the published file
    let mut payload = BytesMut::new();
    payload.put_slice(&file_hash);
    payload.put_u32_le(2_000_000_000u32); // size_lo
    framed
        .send(Frame::new(OP_GETSOURCES, payload.to_vec()))
        .await
        .unwrap();

    let foundsources = framed.next().await.unwrap().unwrap();
    assert_eq!(foundsources.opcode, OP_FOUNDSOURCES);
    // file_hash(16) + count(1) + sources
    assert_eq!(&foundsources.payload[..16], &file_hash);
    let src_count = foundsources.payload[16];
    // The source IS the requester themselves; we filter it out, so 0 expected.
    assert_eq!(
        src_count, 0,
        "self-source must be filtered from FOUNDSOURCES"
    );

    // 6. Verify state
    assert_eq!(state.file_count(), 1);
    assert_eq!(state.client_count(), 1);
}

#[tokio::test]
async fn csam_filename_is_blocked() {
    let (port, state) = spawn_test_server().await;

    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let codec = Ed2kCodec::new(1_000_000);
    let mut framed = Framed::new(stream, codec);

    // Login
    framed
        .send(Frame::new(
            OP_LOGINREQUEST,
            build_login([0xCC; 16], 4001, "test"),
        ))
        .await
        .unwrap();
    // Drain welcome
    for _ in 0..5 {
        let _ = tokio::time::timeout(std::time::Duration::from_millis(200), framed.next()).await;
    }

    // Try to publish a file with Layer 2 trigger pattern
    framed
        .send(Frame::new(
            OP_OFFERFILES,
            build_offerfiles([0xDD; 16], "[xxx] 8yo movie test.mp4", 100_000),
        ))
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Filter must have prevented indexing
    assert_eq!(
        state.file_count(),
        0,
        "CSAM-pattern file must not be indexed"
    );
}

#[tokio::test]
async fn search_with_boolean_tree_works() {
    let (port, state) = spawn_test_server().await;

    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let codec = Ed2kCodec::new(1_000_000);
    let mut framed = Framed::new(stream, codec);

    framed
        .send(Frame::new(
            OP_LOGINREQUEST,
            build_login([0xEE; 16], 4001, "publisher"),
        ))
        .await
        .unwrap();
    for _ in 0..5 {
        let _ = tokio::time::timeout(std::time::Duration::from_millis(200), framed.next()).await;
    }

    // Publish three files
    for (hash, name) in [
        ([0x11u8; 16], "Linux Mint Cinnamon.iso"),
        ([0x22u8; 16], "Linux Debian Server.iso"),
        ([0x33u8; 16], "Windows 11 Pro.iso"),
    ] {
        framed
            .send(Frame::new(
                OP_OFFERFILES,
                build_offerfiles(hash, name, 2_000_000_000),
            ))
            .await
            .unwrap();
    }

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(state.file_count(), 3);

    // Build a boolean tree: linux AND mint
    let mut tree = BytesMut::new();
    tree.put_u8(0x00); // NODE_BOOL
    tree.put_u8(0x00); // OP_AND
    tree.put_u8(0x01); // NODE_STRING
    tree.put_u16_le(5);
    tree.put_slice(b"linux");
    tree.put_u8(0x01); // NODE_STRING
    tree.put_u16_le(4);
    tree.put_slice(b"mint");

    framed
        .send(Frame::new(OP_SEARCHREQUEST, tree.to_vec()))
        .await
        .unwrap();
    let result = framed.next().await.unwrap().unwrap();
    let count = u32::from_le_bytes([
        result.payload[0],
        result.payload[1],
        result.payload[2],
        result.payload[3],
    ]);
    assert_eq!(count, 1, "AND(linux, mint) should match exactly one file");
}

#[tokio::test]
async fn search_finds_indexed_files() {
    use ed2k_server::filter::ContentFilter;
    use ed2k_server::state::ServerState;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    let filter = Arc::new(ContentFilter::new());
    let cfg = Arc::new(test_config(4661));
    let state = Arc::new(ServerState::new(Arc::clone(&filter), Arc::clone(&cfg)));

    let user_hash = [1u8; 16];
    let file_hash = [2u8; 16];
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

    state.add_file_with_source(
        file_hash,
        1_000_000,
        "ubuntu.iso".to_string(),
        (user_hash, ip, 4662, true),
    );

    assert_eq!(state.file_count(), 1, "file should be indexed");

    // Search for "ubuntu"
    let idx = &state.keyword_index;
    let tokens = vec!["ubuntu".to_string()];
    let results = idx.find_intersection(&tokens);
    assert!(
        !results.is_empty(),
        "search should find 'ubuntu' in 'ubuntu.iso'"
    );
    // find_intersection returns FileId (u32) handles, not raw 16-byte hashes —
    // resolve our file's hash to its slab id and check that id is in the set.
    let fid = state
        .file_slab
        .id_of(&file_hash)
        .expect("published file must have a slab id");
    assert!(results.contains(&fid), "should find our file id");

    // Search via handle_search — now returns the full match list.
    use ed2k_server::server::search::{build_search_result_page, handle_search, SearchRequest};
    let payload = {
        let term = b"ubuntu";
        let mut p = vec![0x01u8]; // NODE_STRING
        p.extend_from_slice(&(term.len() as u16).to_le_bytes());
        p.extend_from_slice(term);
        p
    };
    let req = SearchRequest::parse(&payload).expect("parse search");
    let matches = handle_search(&state, req);
    assert_eq!(
        matches.len(),
        1,
        "search should return 1 match, got {}",
        matches.len()
    );

    // The paginated frame builder should encode that one result.
    let frame = build_search_result_page(&state, &matches, false);
    let count = u32::from_le_bytes([
        frame.payload[0],
        frame.payload[1],
        frame.payload[2],
        frame.payload[3],
    ]);
    assert_eq!(
        count, 1,
        "search result frame should encode 1 result, got {}",
        count
    );
}

/// The result cap returns the BEST-sourced matches, not the first-published.
///
/// This is the regression that motivated ranking. The cap used to truncate in
/// FileId order, which is publication order, so for any query with more matches
/// than the cap the oldest files were permanently visible and the newest
/// permanently were not — a silent filter rather than a limit, filtering the
/// wrong way round for a network where people look for new content.
///
/// The files are published in ASCENDING id order and given ASCENDING source
/// counts, so the best-sourced three are the LAST three published and
/// publication order is the exact reverse of ranked order. Anything that
/// quietly falls back to "first N candidates" returns the three weakest files
/// and fails here.
#[tokio::test]
async fn search_cap_returns_best_sourced_not_first_published() {
    use ed2k_server::filter::ContentFilter;
    use ed2k_server::server::search::{handle_search, SearchRequest};
    use ed2k_server::state::ServerState;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    let mut cfg = test_config(4661);
    cfg.limits.max_search_results = 3;
    let cfg = Arc::new(cfg);
    let filter = Arc::new(ContentFilter::new());
    let state = Arc::new(ServerState::new(Arc::clone(&filter), Arc::clone(&cfg)));

    // 10 files, all matching "rankterm". File i gets i+1 sources, so the LAST
    // published is the best-sourced and the first published is the worst.
    const N: u8 = 10;
    for i in 0..N {
        let file_hash = [i + 1; 16];
        let name = format!("rankterm episode{i}.mkv");
        for s in 0..=i {
            let mut user_hash = [0u8; 16];
            user_hash[0] = i;
            user_hash[1] = s;
            state.add_file_with_source(
                file_hash,
                1_000_000 + i as u64,
                name.clone(),
                (
                    user_hash,
                    IpAddr::V4(Ipv4Addr::new(10, 0, i, s + 1)),
                    4662 + s as u16,
                    true,
                ),
            );
        }
    }
    assert_eq!(state.file_count(), N as usize);

    let payload = {
        let term = b"rankterm";
        let mut p = vec![0x01u8]; // NODE_STRING
        p.extend_from_slice(&(term.len() as u16).to_le_bytes());
        p.extend_from_slice(term);
        p
    };
    let req = SearchRequest::parse(&payload).expect("search parses");
    let results = handle_search(&state, req);

    assert_eq!(results.len(), 3, "cap must be limits.max_search_results");

    let counts: Vec<usize> = results.iter().map(|r| r.sources.len()).collect();
    assert_eq!(
        counts,
        vec![10, 9, 8],
        "results must be the best-sourced three, in descending order"
    );
    // Named explicitly, because the counts alone would also be satisfied by a
    // lucky ordering: these are files 9, 8 and 7, the three published LAST.
    let names: Vec<String> = results.iter().map(|r| r.name().to_string()).collect();
    assert_eq!(
        names,
        vec![
            "rankterm episode9.mkv",
            "rankterm episode8.mkv",
            "rankterm episode7.mkv"
        ]
    );

    // And they must be sorted, not merely selected: a caller paginating this
    // list shows page 1 first, so an unsorted top-N would put a weaker file
    // above a stronger one on the screen the user actually looks at.
    for w in results.windows(2) {
        assert!(
            w[0].sources.len() >= w[1].sources.len(),
            "result list must be ordered best first"
        );
    }
}

/// Equal source counts must not make the order depend on the run.
///
/// On a real index most files share a source count — very often exactly one —
/// so the tie-break decides the bulk of the ordering. If it is not total, the
/// same query against an unchanged index answers differently each time, and the
/// cap goes back to hiding an arbitrary subset.
#[tokio::test]
async fn search_ranking_is_deterministic_on_ties() {
    use ed2k_server::filter::ContentFilter;
    use ed2k_server::server::search::{handle_search, SearchRequest};
    use ed2k_server::state::ServerState;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    let mut cfg = test_config(4661);
    cfg.limits.max_search_results = 4;
    let cfg = Arc::new(cfg);
    let filter = Arc::new(ContentFilter::new());
    let state = Arc::new(ServerState::new(Arc::clone(&filter), Arc::clone(&cfg)));

    // 12 files, one source each: every candidate ties on the ranking key.
    for i in 0..12u8 {
        state.add_file_with_source(
            [i + 1; 16],
            5_000_000,
            format!("tieterm part{i}.bin"),
            ([i; 16], IpAddr::V4(Ipv4Addr::new(10, 1, i, 1)), 4662, true),
        );
    }

    let payload = {
        let term = b"tieterm";
        let mut p = vec![0x01u8];
        p.extend_from_slice(&(term.len() as u16).to_le_bytes());
        p.extend_from_slice(term);
        p
    };

    let first: Vec<[u8; 16]> = handle_search(
        &state,
        SearchRequest::parse(&payload).expect("search parses"),
    )
    .iter()
    .map(|r| r.hash)
    .collect();
    assert_eq!(first.len(), 4);

    for _ in 0..5 {
        let again: Vec<[u8; 16]> = handle_search(
            &state,
            SearchRequest::parse(&payload).expect("search parses"),
        )
        .iter()
        .map(|r| r.hash)
        .collect();
        assert_eq!(again, first, "tied ranking must be stable across calls");
    }
}

/// Raising `max_search_results` must actually reach the client, in one frame.
///
/// The page size used to be a constant 200 of its own, so a cap of 300 found
/// 300 records, sent 200, and parked the rest behind eMule's "More" button.
/// From outside that is indistinguishable from the cap not having been applied
/// at all, which is exactly how it was reported. A stock Lugdunum sends its
/// whole answer in one frame — measured at 309 records in one 20399-byte
/// OP_SEARCHRESULT — so one frame is both the reference behaviour and what the
/// client expects.
#[tokio::test]
async fn raising_the_result_cap_changes_what_the_first_page_holds() {
    use ed2k_server::filter::ContentFilter;
    use ed2k_server::server::search::{handle_search, search_page_size, SearchRequest};
    use ed2k_server::state::ServerState;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    let mut cfg = test_config(4661);
    cfg.limits.max_search_results = 300;
    let cfg = Arc::new(cfg);
    let filter = Arc::new(ContentFilter::new());
    let state = Arc::new(ServerState::new(Arc::clone(&filter), Arc::clone(&cfg)));

    // 350 matching files, so the cap binds and the old 200-record page would be
    // a visible truncation rather than the whole answer.
    for i in 0..350u32 {
        let mut file_hash = [0u8; 16];
        file_hash[..4].copy_from_slice(&i.to_le_bytes());
        file_hash[15] = 1;
        let mut user_hash = [0u8; 16];
        user_hash[..4].copy_from_slice(&i.to_le_bytes());
        state.add_file_with_source(
            file_hash,
            2_000_000 + i as u64,
            format!("pagecap item{i}.mkv"),
            (
                user_hash,
                IpAddr::V4(Ipv4Addr::new(10, 2, (i >> 8) as u8, (i & 0xff) as u8)),
                4662,
                true,
            ),
        );
    }
    assert_eq!(state.file_count(), 350);

    let payload = {
        let term = b"pagecap";
        let mut p = vec![0x01u8];
        p.extend_from_slice(&(term.len() as u16).to_le_bytes());
        p.extend_from_slice(term);
        p
    };
    let results = handle_search(
        &state,
        SearchRequest::parse(&payload).expect("search parses"),
    );

    assert_eq!(results.len(), 300, "cap must be limits.max_search_results");
    assert_eq!(
        search_page_size(&state),
        300,
        "the page must hold the whole capped answer, not a separate 200"
    );
    assert!(
        results.len() <= search_page_size(&state),
        "a capped answer must fit in one frame, so no 'More' click is needed"
    );
}

/// Sub-tokens widen what a query can REACH. They must not widen what is SERVED.
///
/// A name that was only findable by typing a whole glued token becomes findable
/// by one of its pieces once sub-tokens are on. The content filter judges the
/// full name at serve time, before `evaluate`, so the path a query took to a
/// record must make no difference to whether that record is withheld.
///
/// Why this holds, not just that it does: the term matcher treats any
/// non-letter as a word boundary on either side, digits included, while
/// sub-tokens are cut only at letter/digit changes. Every point where a
/// sub-token is cut is therefore already a boundary for the filter, so a
/// sub-token cannot expose a piece the filter considers "inside a word".
///
/// The marker is a nonsense string, not a real filter term. Four characters, so
/// it takes the word-bounded rule rather than the substring rule — the stricter
/// of the two, and the one where a boundary disagreement would show.
#[tokio::test]
async fn subtokens_do_not_bypass_the_content_filter() {
    use ed2k_server::filter::ContentFilter;
    use ed2k_server::server::search::{handle_search, SearchRequest};
    use ed2k_server::state::ServerState;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    let mut cfg = test_config(4661);
    cfg.limits.index_subtokens = true;
    let cfg = Arc::new(cfg);
    // Empty at publish time, so both files are indexed. The term is added
    // afterwards: this is the "term added today must withhold what was indexed
    // yesterday" path, i.e. serve-time withholding, which is the one sub-tokens
    // could conceivably route around.
    let filter = Arc::new(ContentFilter::new());
    let state = Arc::new(ServerState::new(Arc::clone(&filter), Arc::clone(&cfg)));

    let marked_hash = [0x51u8; 16];
    let clean_hash = [0x52u8; 16];
    state.add_file_with_source(
        marked_hash,
        3_000_000,
        "subcheck zqmk01 S01E02.mkv".to_string(),
        (
            [0x61; 16],
            IpAddr::V4(Ipv4Addr::new(10, 3, 0, 1)),
            4662,
            true,
        ),
    );
    state.add_file_with_source(
        clean_hash,
        3_000_001,
        "subcheck S01E02 other.mkv".to_string(),
        (
            [0x62; 16],
            IpAddr::V4(Ipv4Addr::new(10, 3, 0, 2)),
            4662,
            true,
        ),
    );

    let search = |term: &[u8]| -> Vec<[u8; 16]> {
        let mut p = vec![0x01u8];
        p.extend_from_slice(&(term.len() as u16).to_le_bytes());
        p.extend_from_slice(term);
        let mut v: Vec<[u8; 16]> =
            handle_search(&state, SearchRequest::parse(&p).expect("search parses"))
                .iter()
                .map(|r| r.hash)
                .collect();
        v.sort();
        v
    };

    // Precondition: BOTH files are reachable through a sub-token only. `s01` is
    // not a whole token of either name. If this failed the test below would pass
    // for the wrong reason.
    assert_eq!(search(b"s01"), vec![marked_hash, clean_hash]);
    // And the marker itself is reachable as a sub-token of `zqmk01`.
    assert_eq!(search(b"zqmk"), vec![marked_hash]);

    filter.reload_extra_terms(vec!["zqmk".to_string()]);

    assert_eq!(
        search(b"s01"),
        vec![clean_hash],
        "a withheld file must not come back through a sub-token"
    );
    assert!(
        search(b"zqmk").is_empty(),
        "nor through the sub-token that is itself the marker"
    );
    assert!(search(b"zqmk01").is_empty(), "nor through the whole token");
}

/// One unknown word no longer empties a search — end to end, through both the
/// candidate lookup and `evaluate`, which is where a half-done version of this
/// change would fail silently.
#[tokio::test]
async fn an_unknown_word_no_longer_empties_the_search() {
    use ed2k_server::filter::ContentFilter;
    use ed2k_server::server::search::{handle_search, SearchRequest};
    use ed2k_server::state::ServerState;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    let run = |drop_unknown: bool| {
        let mut cfg = test_config(4661);
        cfg.limits.search_drop_unknown_words = drop_unknown;
        let cfg = Arc::new(cfg);
        let state = Arc::new(ServerState::new(
            Arc::new(ContentFilter::new()),
            Arc::clone(&cfg),
        ));
        state.add_file_with_source(
            [0x71; 16],
            4_000_000,
            "knownword episode.mkv".to_string(),
            (
                [0x72; 16],
                IpAddr::V4(Ipv4Addr::new(10, 4, 0, 1)),
                4662,
                true,
            ),
        );
        state.add_file_with_source(
            [0x73; 16],
            4_000_001,
            "otherfile thing.mkv".to_string(),
            (
                [0x74; 16],
                IpAddr::V4(Ipv4Addr::new(10, 4, 0, 2)),
                4662,
                true,
            ),
        );
        let search = |term: &str| -> usize {
            let t = term.as_bytes();
            let mut p = vec![0x01u8];
            p.extend_from_slice(&(t.len() as u16).to_le_bytes());
            p.extend_from_slice(t);
            handle_search(&state, SearchRequest::parse(&p).expect("parses")).len()
        };
        (
            // The aMule shape: one string, one known and one unknown word.
            search("knownword zzqtypo"),
            // Only unknown words.
            search("zzqtypo zzqother"),
            state.search_words_dropped_count(),
        )
    };

    let (with_known, all_unknown, dropped) = run(true);
    assert_eq!(with_known, 1, "the unknown word must be ignored, not fatal");
    assert_eq!(
        all_unknown, 0,
        "an all-unknown query must stay empty — never become match-everything"
    );
    assert_eq!(dropped, 1, "exactly one search had a word dropped");

    let (with_known, all_unknown, dropped) = run(false);
    assert_eq!(with_known, 0, "with the flag off, the old behaviour stands");
    assert_eq!(all_unknown, 0);
    assert_eq!(dropped, 0);
}

/// Ties are broken per query, not by file id (issue #14).
///
/// A FileId is `shard << 26 | slot` with the shard chosen by the file hash and
/// slots reused after eviction, so "lower id wins" meant one hash range winning
/// every query. Two different queries over the same tied files must be free to
/// keep different files, while each stays deterministic.
#[tokio::test]
async fn tied_results_are_broken_per_query_not_by_file_id() {
    use ed2k_server::filter::ContentFilter;
    use ed2k_server::server::search::{handle_search, SearchRequest};
    use ed2k_server::state::ServerState;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    let mut cfg = test_config(4661);
    cfg.limits.max_search_results = 5;
    let cfg = Arc::new(cfg);
    let state = Arc::new(ServerState::new(Arc::new(ContentFilter::new()), Arc::clone(&cfg)));
    // 60 files, one source each, all matching both words.
    for i in 0..60u8 {
        state.add_file_with_source(
            [i + 1; 16],
            5_000_000,
            format!("tiealpha tiebravo part{i}.bin"),
            ([i; 16], IpAddr::V4(Ipv4Addr::new(10, 2, i, 1)), 4662, true),
        );
    }
    let run = |term: &str| -> Vec<[u8; 16]> {
        let mut p = vec![0x01u8];
        p.extend_from_slice(&(term.len() as u16).to_le_bytes());
        p.extend_from_slice(term.as_bytes());
        handle_search(&state, SearchRequest::parse(&p).unwrap())
            .iter()
            .map(|r| r.hash)
            .collect()
    };
    let a = run("tiealpha");
    let b = run("tiebravo");
    assert_eq!(a.len(), 5);
    assert_eq!(a, run("tiealpha"), "deterministic per query");
    assert_eq!(b, run("tiebravo"), "deterministic per query");
    assert_ne!(a, b, "different queries break ties over different files");
    // Not the lowest file ids either.
    let mut lowest: Vec<_> = (0..60u8)
        .map(|i| [i + 1; 16])
        .map(|h| (state.file_slab.id_of(&h).unwrap(), h))
        .collect();
    lowest.sort();
    let lowest: Vec<[u8; 16]> = lowest.into_iter().take(5).map(|(_, h)| h).collect();
    assert_ne!(a, lowest);
}

#[path = "support/offerfiles_v1_cases.rs"]
mod offerfiles_v1_cases;

/// A login that replaces a session fences the old socket (issue #46): the old
/// socket's next frame closes it instead of being handled under the user hash
/// it no longer owns.
#[tokio::test]
async fn a_replaced_session_cannot_act_for_the_user() {
    let (port, state) = spawn_test_server().await;
    let hash = [0x46u8; 16];
    let login = |nick: &'static str| async move {
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut f = Framed::new(stream, Ed2kCodec::new(1_000_000));
        f.send(Frame::new(OP_LOGINREQUEST, build_login(hash, 4662, nick)))
            .await
            .unwrap();
        // Drain the welcome batch.
        while let Ok(Some(Ok(_))) =
            tokio::time::timeout(std::time::Duration::from_millis(300), f.next()).await
        {}
        f
    };
    let mut old = login("old").await;
    let _new = login("new").await;
    assert_eq!(state.clients.len(), 1);

    // The old socket publishes: refused, and the socket is closed.
    old.send(Frame::new(OP_OFFERFILES, build_offerfiles([0x47; 16], "x.bin", 1000)))
        .await
        .unwrap();
    let next = tokio::time::timeout(std::time::Duration::from_secs(2), old.next()).await;
    assert!(
        matches!(next, Ok(None) | Ok(Some(Err(_)))),
        "the replaced socket is closed"
    );
    assert!(state.file_slab.get_by_hash(&[0x47; 16]).is_none(), "nothing was published");
    assert_eq!(
        state.block_stats.get("replaced_session_frame_refused").map(|v| *v),
        Some(1)
    );
}

/// ...but not for a shared hash: its sessions are different installs, and
/// closing the displaced one only sends it back to displace the other.
#[tokio::test]
async fn a_replaced_session_of_a_shared_hash_keeps_working() {
    let (port, state) = spawn_test_server().await;
    // Degenerate (12+ zero bytes): shared by definition.
    let mut hash = [0u8; 16];
    hash[5] = 0x0E;
    hash[14] = 0x6F;
    let login = |nick: &'static str| async move {
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut f = Framed::new(stream, Ed2kCodec::new(1_000_000));
        f.send(Frame::new(OP_LOGINREQUEST, build_login(hash, 4662, nick)))
            .await
            .unwrap();
        while let Ok(Some(Ok(_))) =
            tokio::time::timeout(std::time::Duration::from_millis(300), f.next()).await
        {}
        f
    };
    let mut old = login("old").await;
    let _new = login("new").await;
    old.send(Frame::new(OP_OFFERFILES, build_offerfiles([0x48; 16], "y.bin", 1000)))
        .await
        .unwrap();
    let next = tokio::time::timeout(std::time::Duration::from_millis(500), old.next()).await;
    assert!(next.is_err() || matches!(next, Ok(Some(Ok(_)))), "still open");
    assert!(state.block_stats.get("replaced_session_frame_refused").is_none());
}

/// A large OFFERFILES batch with every offer slot busy waits for one off the
/// runtime instead of running on it (issue #56). The test runtime has one
/// thread, so a ticker that keeps running during the wait shows the runtime
/// stayed free; the batch is indexed once a slot opens.
#[tokio::test]
async fn a_large_batch_waits_for_an_offer_slot_off_the_runtime() {
    let (port, state) = spawn_test_server().await;
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut f = Framed::new(stream, Ed2kCodec::new(1_000_000));
    f.send(Frame::new(OP_LOGINREQUEST, build_login([0x56; 16], 4662, "big")))
        .await
        .unwrap();
    while let Ok(Some(Ok(_))) =
        tokio::time::timeout(std::time::Duration::from_millis(300), f.next()).await
    {}

    // Every slot taken.
    let slots = Arc::clone(&state.offer_lane)
        .acquire_many_owned(ed2k_server::state::OFFER_JOBS as u32)
        .await
        .unwrap();
    let ticks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let t = Arc::clone(&ticks);
    let ticker = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            t.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    });

    let n = 40u8;
    let mut p = BytesMut::new();
    p.put_u32_le(n as u32);
    for i in 0..n {
        let one = build_offerfiles([0x60 + i; 16], &format!("batchfile{i}.bin"), 1000 + i as u64);
        p.put_slice(&one[4..]);
    }
    f.send(Frame::new(OP_OFFERFILES, p.to_vec())).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(ticks.load(std::sync::atomic::Ordering::Relaxed) >= 10, "runtime kept running");
    assert_eq!(state.block_stats.get("offer_lane_waited").map(|v| *v), Some(1));
    assert!(state.block_stats.get("offer_inline_overload").is_none());
    assert!(state.file_slab.get_by_hash(&[0x60; 16]).is_none(), "still waiting");
    assert!(state.offer_wait_bytes.load(std::sync::atomic::Ordering::Relaxed) > 0);

    drop(slots);
    let mut indexed = false;
    for _ in 0..100 {
        if state.file_slab.get_by_hash(&[0x60 + n - 1; 16]).is_some() {
            indexed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(indexed, "indexed once a slot opened");
    assert_eq!(state.offer_wait_bytes.load(std::sync::atomic::Ordering::Relaxed), 0);
    // Every slot is back once the job is done.
    for _ in 0..100 {
        if state.offer_lane.available_permits() == ed2k_server::state::OFFER_JOBS {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(state.offer_lane.available_permits(), ed2k_server::state::OFFER_JOBS);
    ticker.abort();
}

/// A shallow but wide search tree is refused while parsing, before it is
/// queued for the search lane (issue #54): an empty result, and counted.
#[tokio::test]
async fn a_wide_search_tree_is_refused_before_the_search_lane() {
    let (port, state) = spawn_test_server().await;
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut f = Framed::new(stream, Ed2kCodec::new(1_000_000));
    f.send(Frame::new(OP_LOGINREQUEST, build_login([0x54; 16], 4662, "wide")))
        .await
        .unwrap();
    while let Ok(Some(Ok(_))) =
        tokio::time::timeout(std::time::Duration::from_millis(300), f.next()).await
    {}
    // 4,096 copies of "alpha" under ANDs: depth 12, 8,191 nodes.
    fn tree(out: &mut Vec<u8>, leaves: u32) {
        if leaves == 1 {
            out.extend_from_slice(&[0x01, 5, 0]);
            out.extend_from_slice(b"alpha");
        } else {
            out.extend_from_slice(&[0x00, 0x00]);
            tree(out, leaves / 2);
            tree(out, leaves / 2);
        }
    }
    let mut p = Vec::new();
    tree(&mut p, 4096);
    f.send(Frame::new(OP_SEARCHREQUEST, p)).await.unwrap();
    let reply = loop {
        let fr = tokio::time::timeout(std::time::Duration::from_secs(2), f.next())
            .await
            .expect("a reply")
            .unwrap()
            .unwrap();
        if fr.opcode == OP_SEARCHRESULT {
            break fr;
        }
    };
    assert_eq!(&reply.payload[..4], &[0, 0, 0, 0], "no results");
    assert_eq!(state.block_stats.get("search_tree_over_budget").map(|v| *v), Some(1));
}

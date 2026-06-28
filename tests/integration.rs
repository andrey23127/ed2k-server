//! End-to-end test: spin up the server, connect a fake client, exercise
//! login → OFFERFILES → SEARCH → GETSOURCES, validate every reply.
//!
//! This is the "real client" integration target — if this passes, an
//! actual eMule should also be able to talk to us.

use bytes::{BufMut, BytesMut};
use ed2k_server::config::Config;
use ed2k_server::filter::ContentFilter;
use ed2k_server::proto::{opcodes::*, Ed2kCodec, Frame};
use ed2k_server::proto::CryptStream;
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

    // 2. Receive welcome batch (5 frames: IDCHANGE, SERVERSTATUS,
    //    SERVERMESSAGE×1 [welcome[0]], SERVERIDENT, SERVERMESSAGE [welcome[1]])
    let mut got_idchange = false;
    let mut got_status = false;
    let mut got_message_count = 0;
    let mut got_ident = false;
    for _ in 0..5 {
        let f = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            framed.next(),
        )
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
    assert!(got_message_count >= 1, "must receive at least one SERVERMESSAGE");
    assert!(got_ident, "must receive SERVERIDENT");

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
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            framed.next(),
        )
        .await;
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
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            framed.next(),
        )
        .await;
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
    assert!(!results.is_empty(), "search should find 'ubuntu' in 'ubuntu.iso'");
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
    assert_eq!(matches.len(), 1, "search should return 1 match, got {}", matches.len());

    // The paginated frame builder should encode that one result.
    let frame = build_search_result_page(&matches, false);
    let count = u32::from_le_bytes([
        frame.payload[0], frame.payload[1], frame.payload[2], frame.payload[3],
    ]);
    assert_eq!(count, 1, "search result frame should encode 1 result, got {}", count);
}

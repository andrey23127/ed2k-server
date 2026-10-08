//! OFFERFILES v1 contract checks against production server code.
//!
//! Normal tests cover today's legacy wire/limit behavior. Ignored tests are
//! executable drafts for issue #19: run them explicitly to expose missing v1
//! support. They must not be counted as passing capability or load validation.

use bytes::{BufMut, BytesMut};
use ed2k_server::config::Config;
use ed2k_server::filter::ContentFilter;
use ed2k_server::proto::tags::{read_tag_list, write_tag_list, Tag, TagName, TagValue};
use ed2k_server::proto::{opcodes::*, CryptStream, Ed2kCodec, Frame};
use ed2k_server::server::connection::handle_connection;
use ed2k_server::server::login::build_welcome_batch;
use ed2k_server::server::offerfiles::{handle_offerfiles, over_hard_limit, parse_offerfiles};
use ed2k_server::state::{ClientHandle, ServerState};
use futures::{SinkExt, StreamExt};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{atomic::AtomicU64, Arc};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_util::codec::{Decoder, Encoder, Framed};

const V1_NAMES: [&str; 3] = [
    "offerfiles_v",
    "offerfiles_batch_max",
    "offerfiles_min_interval_ms",
];
const DEADLINE: Duration = Duration::from_secs(10);

// These configuration spellings are draft test inputs from the server proposal,
// not existing server options. Serde currently ignores them. Every enabled test
// requires a real advertisement first, so ignoring the inputs cannot pass it.
fn config(enabled: bool, soft: u32, hard: u32, batch: u32, interval: u32) -> Config {
    config_with_global_rate(enabled, soft, hard, batch, interval, None)
}

fn config_with_global_rate(
    enabled: bool,
    soft: u32,
    hard: u32,
    batch: u32,
    interval: u32,
    global_rate: Option<u32>,
) -> Config {
    // Proposed test knob, not a finalized protocol/configuration field. Change
    // its spelling to match the implementation when server pacing is added.
    let global = global_rate.map_or(String::new(), |rate| {
        format!("offerfiles_global_records_per_second = {rate}\n")
    });
    toml::from_str(&format!(
        r#"
[server]
name = "OFFERFILES contract test"
desc = "loopback only"
public = false
[network]
tcp_port = 4661
listen_ip = "127.0.0.1"
max_frame_size = 1000000
[limits]
max_clients = 100
max_clients_per_ip = 100
soft_limit_files = {soft}
hard_limit_files = {hard}
offerfiles_capability_enabled = {enabled}
offerfiles_max_batch_files = {batch}
offerfiles_min_interval_ms = {interval}
{global}[content_filter]
hash_banlist = []
hash_filter = []
[welcome]
messages = []
"#
    ))
    .unwrap()
}

fn state(cfg: &Config) -> Arc<ServerState> {
    Arc::new(ServerState::new(
        Arc::new(ContentFilter::new()),
        Arc::new(cfg.clone()),
    ))
}

fn user(n: u32) -> [u8; 16] {
    let mut hash = [0xA5; 16];
    hash[..4].copy_from_slice(&n.to_le_bytes());
    hash
}

fn client(n: u32) -> ClientHandle {
    ClientHandle {
        user_hash: user(n),
        assigned_id: n + 1,
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 0, // Skip external HighID probes.
        udp_port: 0,
        natt_capable: false,
        nick: format!("contract{n}"),
        server_flags: CAPABLE_NEWTAGS | CAPABLE_UNICODE | CAPABLE_LARGEFILES | CAPABLE_ZLIB,
        is_high_id: false,
        ipv6_capable: false,
        ipv6: None,
        connected_at: Instant::now(),
        country: "??".into(),
        software: "test".into(),
        csam_attempts: 0,
        soft_limit_warned: false,
        slot: Default::default(),
        tx: None,
        last_activity_ms: Arc::new(AtomicU64::new(0)),
    }
}

fn ident_tags(frame: &Frame) -> Vec<Tag> {
    assert_eq!(frame.opcode, OP_SERVERIDENT);
    assert!(frame.payload.len() >= 26);
    let count = u32::from_le_bytes(frame.payload[22..26].try_into().unwrap());
    let mut bytes = &frame.payload[26..];
    let tags = read_tag_list(&mut bytes, count);
    assert_eq!(tags.len(), count as usize, "truncated tag list");
    assert!(bytes.is_empty(), "trailing SERVERIDENT bytes");
    tags
}

fn welcome_ident(cfg: &Config, state: &ServerState, client: &ClientHandle) -> Frame {
    let frames = build_welcome_batch(cfg, state, client);
    let ids: Vec<_> = frames
        .into_iter()
        .filter(|f| f.opcode == OP_SERVERIDENT)
        .collect();
    assert_eq!(ids.len(), 1, "one unsolicited post-login SERVERIDENT");
    ids.into_iter().next().unwrap()
}

fn named(name: &str) -> TagName {
    TagName::Str(name.into())
}

fn assert_u32(tags: &[Tag], name: TagName, value: u32) {
    let matching: Vec<_> = tags.iter().filter(|t| t.name == name).collect();
    assert_eq!(
        matching.len(),
        1,
        "required tag {name:?} missing or duplicated"
    );
    assert_eq!(
        matching[0].value,
        TagValue::U32(value),
        "exact uint32 wire encoding"
    );
}

fn require_v1(frame: &Frame, soft: u32, hard: u32, batch: u32, interval: u32) {
    let tags = ident_tags(frame);
    assert_u32(&tags, named(V1_NAMES[0]), 1);
    assert_u32(&tags, named(V1_NAMES[1]), batch);
    assert_u32(&tags, named(V1_NAMES[2]), interval);
    assert_u32(&tags, TagName::Byte(ST_SOFTFILES), soft);
    assert_u32(&tags, TagName::Byte(ST_HARDFILES), hard);
}

fn assert_no_v1(frame: &Frame) {
    for tag in ident_tags(frame) {
        assert!(
            !V1_NAMES.iter().any(|name| tag.name == named(name)),
            "partial capability"
        );
    }
}

fn offer(first: u32, count: u32) -> Vec<u8> {
    let mut p = BytesMut::new();
    p.put_u32_le(count);
    for n in first..first + count {
        p.put_slice(&user(n));
        p.put_u32_le(SELF_COMPLETE_ID);
        p.put_u16_le(SELF_COMPLETE_PORT);
        write_tag_list(
            &mut p,
            &[
                Tag::byte(
                    FT_FILENAME,
                    TagValue::String(format!("linux fixture {n}.iso")),
                ),
                Tag::byte(FT_FILESIZE, TagValue::U32(1000000 + n)),
            ],
        );
    }
    p.to_vec()
}

fn wire(payload: Vec<u8>, packed: bool) -> BytesMut {
    if !packed {
        let mut bytes = BytesMut::new();
        Ed2kCodec::new(1000000)
            .encode(Frame::new(OP_OFFERFILES, payload), &mut bytes)
            .unwrap();
        return bytes;
    }
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(&payload).unwrap();
    let compressed = z.finish().unwrap();
    let mut bytes = BytesMut::new();
    bytes.put_u8(PROTO_PACKED);
    bytes.put_u32_le(1 + compressed.len() as u32);
    bytes.put_u8(OP_OFFERFILES);
    bytes.extend_from_slice(&compressed);
    bytes
}

#[test]
fn legacy_default_and_explicit_off_never_advertise_fast_publication() {
    for mut cfg in [
        Config::minimal_test_config(),
        config(false, 1000000, 1000001, 200, 500),
    ] {
        cfg.limits.soft_limit_files = 1000000;
        let state = state(&cfg);
        for flags in [0, CAPABLE_NEWTAGS | CAPABLE_UNICODE] {
            let mut c = client(1);
            c.server_flags = flags;
            let ident = welcome_ident(&cfg, &state, &c);
            assert_no_v1(&ident);
            assert_u32(&ident_tags(&ident), TagName::Byte(ST_SOFTFILES), 1000000);
        }
    }
}

#[test]
fn plain_and_compressed_packets_share_strict_hard_boundary() {
    for packed in [false, true] {
        for count in [3, 4, 5] {
            let frame = Ed2kCodec::new(1000000)
                .decode(&mut wire(offer(0, count), packed))
                .unwrap()
                .unwrap();
            let declared = u32::from_le_bytes(frame.payload[..4].try_into().unwrap());
            assert_eq!(over_hard_limit(declared, 4), count >= 4);
            if count < 4 {
                assert_eq!(
                    parse_offerfiles(&frame.payload).unwrap().len(),
                    count as usize
                );
            }
        }
    }
}

#[test]
fn fragmented_and_coalesced_frames_preserve_every_offer_in_order() {
    for packed in [false, true] {
        let mut full = wire(offer(10, 2), packed);
        full.extend_from_slice(&wire(offer(12, 2), packed));
        let mut buffer = BytesMut::new();
        let mut codec = Ed2kCodec::new(1000000);
        let mut seen = Vec::new();
        // One-byte fragmentation exercises all header and payload boundaries.
        for byte in full {
            buffer.extend_from_slice(&[byte]);
            while let Some(frame) = codec.decode(&mut buffer).unwrap() {
                seen.extend(
                    parse_offerfiles(&frame.payload)
                        .unwrap()
                        .into_iter()
                        .map(|f| f.hash),
                );
            }
        }
        assert_eq!(seen, (10..14).map(user).collect::<Vec<_>>());
        assert!(buffer.is_empty());
        let mut coalesced = wire(offer(10, 2), packed);
        coalesced.extend_from_slice(&wire(offer(12, 2), packed));
        assert!(codec.decode(&mut coalesced).unwrap().is_some());
        assert!(codec.decode(&mut coalesced).unwrap().is_some());
        assert!(codec.decode(&mut coalesced).unwrap().is_none());
    }
}

#[test]
fn wire_records_consume_distinct_soft_budget_across_batches() {
    let cfg = config(false, 3, 100, 200, 500);
    let state = state(&cfg);
    let mut c = client(7);
    assert_eq!(
        handle_offerfiles(&state, &mut c, parse_offerfiles(&offer(0, 2)).unwrap()),
        (2, 0)
    );
    // One refresh plus two new hashes: exactly one new hash fits.
    assert_eq!(
        handle_offerfiles(&state, &mut c, parse_offerfiles(&offer(1, 3)).unwrap()),
        (2, 0)
    );
    assert_eq!(state.user_files.get(&c.user_hash).unwrap().len(), 3);
    assert_eq!(state.offer_over_soft_stats(), (1, 1));
    state.remove_sources_of(&c.user_hash);
    assert_eq!(
        handle_offerfiles(
            &state,
            &mut client(7),
            parse_offerfiles(&offer(10, 3)).unwrap()
        ),
        (3, 0)
    );
}

#[test]
fn truncated_record_header_does_not_produce_partial_candidates() {
    let payload = offer(0, 1);
    for end in 0..30 {
        assert!(
            parse_offerfiles(&payload[..end]).is_err(),
            "accepted truncation at {end}"
        );
    }
}

#[test]
fn concurrent_handlers_keep_each_publishers_budget_independent() {
    let cfg = config(false, 10, 100, 200, 500);
    let state = state(&cfg);
    std::thread::scope(|scope| {
        for n in 0..8 {
            let state = Arc::clone(&state);
            scope.spawn(move || {
                let mut c = client(100 + n);
                handle_offerfiles(
                    &state,
                    &mut c,
                    parse_offerfiles(&offer(n * 100, 12)).unwrap(),
                );
                assert_eq!(state.user_files.get(&c.user_hash).unwrap().len(), 10);
            });
        }
    });
    assert_eq!(state.file_count(), 80);
    assert_eq!(state.offer_over_soft_stats(), (8, 16));
}

#[test]
#[ignore = "issue #19: OFFERFILES v1 is not implemented"]
fn draft_enabled_advertisement_is_atomic_uint32_and_matches_config() {
    let cfg = config(true, 60000, 1000, 200, 500);
    require_v1(
        &welcome_ident(&cfg, &state(&cfg), &client(1)),
        60000,
        1000,
        200,
        500,
    );
}

#[test]
#[ignore = "issue #19: OFFERFILES v1 is not implemented"]
fn draft_invalid_config_advertises_none_of_the_extension_fields() {
    let valid = config(true, 60000, 1000, 200, 500);
    require_v1(
        &welcome_ident(&valid, &state(&valid), &client(1)),
        60000,
        1000,
        200,
        500,
    );
    for (soft, hard, batch, interval) in [
        (0, 1000, 200, 500),
        (60000, 200, 200, 500),
        (60000, 199, 200, 500),
        (60000, 1000, 0, 500),
        (60000, 1000, 200, 0),
    ] {
        let cfg = config(true, soft, hard, batch, interval);
        assert_no_v1(&welcome_ident(&cfg, &state(&cfg), &client(1)));
    }
}

type Session = Framed<TcpStream, Ed2kCodec>;
struct TestServer {
    port: u16,
    state: Arc<ServerState>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl TestServer {
    async fn start(mut cfg: Config) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        cfg.network.tcp_port = port;
        let state = state(&cfg);
        let cfg = Arc::new(cfg);
        let st = Arc::clone(&state);
        let task = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, peer) = accepted.unwrap();
                        let (cfg, st) = (Arc::clone(&cfg), Arc::clone(&st));
                        sessions.spawn(async move { handle_connection(cfg, st, CryptStream::plain(stream), peer).await });
                    }
                    Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
                }
            }
        });
        Self { port, state, task }
    }
    async fn login(&self, n: u32) -> (Session, Frame) {
        let mut session = Framed::new(
            TcpStream::connect(("127.0.0.1", self.port)).await.unwrap(),
            Ed2kCodec::new(1000000),
        );
        let mut p = BytesMut::new();
        p.extend_from_slice(&user(n));
        p.put_u32_le(0);
        p.put_u16_le(0);
        write_tag_list(
            &mut p,
            &[
                Tag::byte(CT_NAME, TagValue::String(format!("contract{n}"))),
                Tag::byte(
                    CT_SERVER_FLAGS,
                    TagValue::U32(
                        CAPABLE_NEWTAGS | CAPABLE_UNICODE | CAPABLE_LARGEFILES | CAPABLE_ZLIB,
                    ),
                ),
            ],
        );
        session
            .send(Frame::new(OP_LOGINREQUEST, p.to_vec()))
            .await
            .unwrap();
        let ident = tokio::time::timeout(DEADLINE, async {
            loop {
                let f = session.next().await.expect("closed during login").unwrap();
                if f.opcode == OP_SERVERIDENT {
                    break f;
                }
            }
        })
        .await
        .expect("login timeout");
        (session, ident)
    }
}

// A search reply is an ordering barrier: earlier offers on this connection
// have finished processing. No arbitrary sleep and no OFFERFILES ack assumed.
async fn barrier(session: &mut Session) {
    let mut search = BytesMut::new();
    search.put_u8(1);
    search.put_u16_le(5);
    search.extend_from_slice(b"linux");
    session
        .send(Frame::new(OP_SEARCHREQUEST, search.to_vec()))
        .await
        .unwrap();
    tokio::time::timeout(DEADLINE, async {
        loop {
            let frame = session.next().await.expect("connection lost").unwrap();
            if frame.opcode == OP_SEARCHRESULT {
                break;
            }
        }
    })
    .await
    .expect("indexing did not complete");
}

#[tokio::test]
#[ignore = "issue #19: OFFERFILES v1 is not implemented"]
async fn draft_coalesced_batches_are_deferred_without_silent_loss() {
    let server = TestServer::start(config(true, 1000, 1000, 200, 500)).await;
    let (mut session, ident) = server.login(1).await;
    require_v1(&ident, 1000, 1000, 200, 500);
    let mut bytes = wire(offer(0, 200), false);
    bytes.extend_from_slice(&wire(offer(200, 200), true));
    let start = Instant::now();
    session.get_mut().write_all(&bytes).await.unwrap();
    barrier(&mut session).await;
    assert!(
        start.elapsed() >= Duration::from_millis(450),
        "second coalesced batch must wait for record tokens (50ms tolerance)"
    );
    assert_eq!(server.state.user_files.get(&user(1)).unwrap().len(), 400);
    assert_eq!(server.state.offer_over_soft_stats(), (0, 0));
}

#[tokio::test]
#[ignore = "issue #19: OFFERFILES v1 is not implemented"]
async fn draft_oversized_batch_is_not_indexed_and_session_survives() {
    let server = TestServer::start(config(true, 1000, 1000, 200, 500)).await;
    let (mut session, ident) = server.login(1).await;
    require_v1(&ident, 1000, 1000, 200, 500);
    session
        .send(Frame::new(OP_OFFERFILES, offer(0, 201)))
        .await
        .unwrap();
    barrier(&mut session).await;
    assert_eq!(server.state.file_count(), 0);
    session
        .send(Frame::new(OP_OFFERFILES, offer(1000, 1)))
        .await
        .unwrap();
    barrier(&mut session).await;
    assert_eq!(server.state.file_count(), 1);
}

#[tokio::test]
#[ignore = "issue #19: OFFERFILES v1 is not implemented"]
async fn draft_live_reload_preserves_old_budget_and_new_login_gets_new_values() {
    let server = TestServer::start(config(true, 3, 1000, 200, 500)).await;
    let (mut old, ident) = server.login(1).await;
    require_v1(&ident, 3, 1000, 200, 500);
    old.send(Frame::new(OP_OFFERFILES, offer(0, 2)))
        .await
        .unwrap();
    barrier(&mut old).await;
    let mut next = config(true, 1, 1000, 100, 1000);
    next.network.tcp_port = server.port;
    server.state.live_cfg.store(Arc::new(next));
    old.send(Frame::new(OP_OFFERFILES, offer(2, 1)))
        .await
        .unwrap();
    barrier(&mut old).await;
    assert_eq!(
        server.state.user_files.get(&user(1)).unwrap().len(),
        3,
        "reload changed a negotiated connection's budget"
    );
    let (mut new, ident) = server.login(2).await;
    require_v1(&ident, 1, 1000, 100, 1000);
    new.send(Frame::new(OP_OFFERFILES, offer(10, 2)))
        .await
        .unwrap();
    barrier(&mut new).await;
    assert_eq!(server.state.user_files.get(&user(2)).unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "issue #19: OFFERFILES v1 is not implemented"]
async fn draft_concurrent_publishers_and_reconnect_wave_lose_no_compliant_records() {
    let server = TestServer::start(config(true, 1000, 1000, 200, 500)).await;
    for wave in 0..2 {
        let mut sessions = Vec::new();
        for n in 1..=8 {
            let (session, ident) = server.login(n).await;
            require_v1(&ident, 1000, 1000, 200, 500);
            sessions.push((n, session));
        }
        let all =
            futures::future::join_all(sessions.into_iter().map(|(n, mut session)| async move {
                let mut bytes = wire(offer(wave * 10000 + n * 1000, 200), false);
                bytes.extend_from_slice(&wire(offer(wave * 10000 + n * 1000 + 200, 200), true));
                session.get_mut().write_all(&bytes).await.unwrap();
                barrier(&mut session).await;
                (n, session)
            }))
            .await;
        for (n, _) in &all {
            assert_eq!(server.state.user_files.get(&user(*n)).unwrap().len(), 400);
        }
        drop(all);
        tokio::time::timeout(DEADLINE, async {
            while !server.state.clients.is_empty() || !server.state.user_files.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("disconnect did not clean up publishers");
    }
    assert_eq!(server.state.offer_over_soft_stats(), (0, 0));
    assert_eq!(server.state.offer_over_hard_count(), 0);
}

#[tokio::test]
async fn legacy_tcp_login_and_coalesced_publication_keep_connection_usable() {
    let server = TestServer::start(config(false, 1000, 1000, 200, 500)).await;
    let (mut session, ident) = server.login(1).await;
    assert_no_v1(&ident);
    let mut bytes = wire(offer(0, 2), false);
    bytes.extend_from_slice(&wire(offer(2, 2), true));
    session.get_mut().write_all(&bytes).await.unwrap();
    barrier(&mut session).await;
    assert_eq!(server.state.user_files.get(&user(1)).unwrap().len(), 4);
    assert_eq!(server.state.offer_over_soft_stats(), (0, 0));
}

#[tokio::test]
async fn legacy_tcp_rejects_hard_boundary_before_parsing_or_indexing() {
    for packed in [false, true] {
        let server = TestServer::start(config(false, 3, 4, 2, 500)).await;
        let (mut session, _) = server.login(1).await;
        // The count alone is enough to reject: there are deliberately no records.
        let payload = 4u32.to_le_bytes().to_vec();
        session
            .get_mut()
            .write_all(&wire(payload, packed))
            .await
            .unwrap();
        tokio::time::timeout(DEADLINE, async {
            while let Some(frame) = session.next().await {
                frame.expect("valid reply or orderly close");
            }
        })
        .await
        .expect("hard violation did not close the session");
        assert_eq!(server.state.offer_over_hard_count(), 1);
        assert_eq!(
            server.state.file_count(),
            0,
            "partial indexing before rejection"
        );
    }
}

#[tokio::test]
async fn legacy_tcp_reconnect_resets_soft_budget_and_removes_old_sources() {
    let server = TestServer::start(config(false, 2, 1000, 200, 500)).await;
    let (mut session, _) = server.login(1).await;
    session
        .send(Frame::new(OP_OFFERFILES, offer(0, 3)))
        .await
        .unwrap();
    barrier(&mut session).await;
    assert_eq!(server.state.user_files.get(&user(1)).unwrap().len(), 2);
    drop(session);
    tokio::time::timeout(DEADLINE, async {
        while server.state.clients.contains_key(&user(1))
            || server.state.user_files.contains_key(&user(1))
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("disconnect cleanup timeout");
    assert!(!server.state.user_files.contains_key(&user(1)));
    let (mut session, _) = server.login(1).await;
    session
        .send(Frame::new(OP_OFFERFILES, offer(10, 2)))
        .await
        .unwrap();
    barrier(&mut session).await;
    assert_eq!(server.state.user_files.get(&user(1)).unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "issue #19: server-wide OFFERFILES record pacing is not implemented"]
async fn draft_global_ceiling_slows_publishers_without_loss_or_starvation() {
    // Draft fixture: one initial global batch (200 tokens), then 1000 records/s.
    // This bucket capacity is a TEST requirement, not a new wire field. A future
    // implementation with configurable capacity should set that knob explicitly.
    let server = TestServer::start(config_with_global_rate(
        true,
        1000,
        1000,
        200,
        500,
        Some(1000),
    ))
    .await;
    let mut sessions = Vec::new();
    for n in 1..=8 {
        let (session, ident) = server.login(n).await;
        require_v1(&ident, 1000, 1000, 200, 500);
        sessions.push((n, session));
    }
    let start = Instant::now();
    let all = futures::future::join_all(sessions.into_iter().map(|(n, mut session)| async move {
        let mut bytes = wire(offer(n * 1000, 200), false);
        bytes.extend_from_slice(&wire(offer(n * 1000 + 200, 200), true));
        session.get_mut().write_all(&bytes).await.unwrap();
        barrier(&mut session).await; // Each publisher must finish within DEADLINE.
        (n, session)
    }))
    .await;
    // 3200 records, minus 200 initial tokens = at least 3 s at the global ceiling.
    assert!(
        start.elapsed() >= Duration::from_millis(2900),
        "global rate ceiling bypassed (100ms tolerance)"
    );
    for (n, _) in &all {
        assert_eq!(server.state.user_files.get(&user(*n)).unwrap().len(), 400);
    }
    assert_eq!(server.state.offer_over_soft_stats(), (0, 0));
}

#[tokio::test]
#[ignore = "issue #19: per-connection OFFERFILES hard-limit snapshot is not implemented"]
async fn draft_live_reload_does_not_replace_old_hard_boundary() {
    let server = TestServer::start(config(true, 10, 1000, 200, 500)).await;
    let (mut old, ident) = server.login(1).await;
    require_v1(&ident, 10, 1000, 200, 500);
    let mut next = config(true, 10, 2, 1, 1000);
    next.network.tcp_port = server.port;
    server.state.live_cfg.store(Arc::new(next));
    old.send(Frame::new(OP_OFFERFILES, offer(0, 2)))
        .await
        .unwrap();
    barrier(&mut old).await;
    assert_eq!(
        server.state.user_files.get(&user(1)).unwrap().len(),
        2,
        "old connection must retain its advertised hard boundary and batch size"
    );
    let (mut new, ident) = server.login(2).await;
    require_v1(&ident, 10, 2, 1, 1000);
    new.get_mut()
        .write_all(&wire(2u32.to_le_bytes().to_vec(), true))
        .await
        .unwrap();
    tokio::time::timeout(DEADLINE, async {
        while let Some(frame) = new.next().await {
            frame.unwrap();
        }
    })
    .await
    .expect("new connection did not enforce its own hard boundary");
    assert_eq!(server.state.offer_over_hard_count(), 1);
}

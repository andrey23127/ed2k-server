// OFFERFILES v1 (issue #19), against the real connection handler and index.
//
// The first nine cases are the draft contract tests by 3togo (gist
// 81b43dbf74942236c24f0b99741a50aa, companion to aMule PR #1715), adapted to
// the configuration keys the implementation settled on — the draft left the
// adapter to us on purpose — and no longer ignored. The cases after them
// cover the follow-up list in that draft's README.
//
// Fixture values are deliberately tiny boundary inputs, not proposed
// production settings: batch 2, interval 200 ms, soft 5, hard 4.
use super::*;
use ed2k_server::proto::tags::{read_tag, TagName, TagValue};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

type Peer = Framed<TcpStream, Ed2kCodec>;
const BATCH: u32 = 2;
const INTERVAL: u32 = 200;
const SOFT: u32 = 5;
const HARD: u32 = 4;

/// The integration config with v1 on (or off) at the fixture values, and no
/// server-wide ceiling.
fn v1_config(port: u16, enabled: bool) -> Config {
    let mut cfg = test_config(port);
    cfg.limits.offerfiles_v1 = enabled;
    cfg.limits.offerfiles_batch_max = BATCH;
    cfg.limits.offerfiles_min_interval_ms = INTERVAL;
    cfg.limits.offerfiles_global_records_per_sec = 0;
    cfg.limits.soft_limit_files = SOFT;
    cfg.limits.hard_limit_files = HARD;
    cfg
}

async fn server_with(
    make: impl FnOnce(u16) -> Config,
    filter: ContentFilter,
) -> (u16, Arc<ServerState>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cfg = Arc::new(make(port));
    let state = Arc::new(ServerState::new(Arc::new(filter), cfg.clone()));
    let shared = state.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, addr)) = listener.accept().await {
            let cfg = cfg.clone();
            let state = shared.clone();
            tokio::spawn(async move {
                let _ = handle_connection(cfg, state, CryptStream::plain(stream), addr).await;
            });
        }
    });
    (port, state, task)
}

async fn server(enabled: bool) -> (u16, Arc<ServerState>, tokio::task::JoinHandle<()>) {
    server_with(|port| v1_config(port, enabled), ContentFilter::new()).await
}

async fn login(port: u16, id: u8) -> (Peer, Vec<ed2k_server::proto::Tag>) {
    let mut peer = Framed::new(
        TcpStream::connect(("127.0.0.1", port)).await.unwrap(),
        Ed2kCodec::new(1_000_000),
    );
    peer.send(Frame::new(
        OP_LOGINREQUEST,
        build_login([id; 16], 0, "v1-draft"),
    ))
    .await
    .unwrap();
    let mut tags = None;
    // Same five-frame welcome fixture as full_client_lifecycle; no GETSERVERLIST.
    for _ in 0..5 {
        let frame = tokio::time::timeout(Duration::from_secs(3), peer.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if frame.opcode == OP_SERVERIDENT {
            assert!(tags.is_none(), "duplicate SERVERIDENT in welcome");
            assert!(frame.payload.len() >= 26);
            let n = u32::from_le_bytes(frame.payload[22..26].try_into().unwrap());
            let mut rest = &frame.payload[26..];
            let decoded: Vec<_> = (0..n).map(|_| read_tag(&mut rest).unwrap()).collect();
            assert!(rest.is_empty(), "trailing/partially parsed tag bytes");
            tags = Some(decoded);
        }
    }
    (peer, tags.expect("post-login SERVERIDENT missing"))
}

fn assert_policy_values(tags: &[ed2k_server::proto::Tag], batch: u32, interval: u32, soft: u32, hard: u32) {
    for (name, value) in [
        (TagName::Str("offerfiles_v".into()), 1),
        (TagName::Str("offerfiles_batch_max".into()), batch),
        (TagName::Str("offerfiles_min_interval_ms".into()), interval),
        (TagName::Byte(ST_SOFTFILES), soft),
        (TagName::Byte(ST_HARDFILES), hard),
    ] {
        let matching: Vec<_> = tags.iter().filter(|t| t.name == name).collect();
        assert_eq!(
            matching.len(),
            1,
            "required field {name:?} must occur exactly once"
        );
        assert_eq!(
            matching[0].value,
            TagValue::U32(value),
            "exact uint32 wire type required"
        );
    }
    assert!(!tags
        .iter()
        .any(|t| matches!(&t.name, TagName::Str(s) if s == "offer_burst")));
}

fn assert_policy(tags: &[ed2k_server::proto::Tag]) {
    assert_policy_values(tags, BATCH, INTERVAL, SOFT, HARD);
}

fn assert_no_v1(tags: &[ed2k_server::proto::Tag]) {
    assert!(!tags.iter().any(
        |t| matches!(&t.name, TagName::Str(s) if s.starts_with("offerfiles_") || s == "offer_burst")
    ));
}

fn offer(first: u8, count: u32) -> Vec<u8> {
    let mut payload = count.to_le_bytes().to_vec();
    for i in 0..count {
        let record = build_offerfiles([first + i as u8; 16], "Linux test.iso", 123456);
        payload.extend_from_slice(&record[4..]);
    }
    payload
}

// Force the requested wire path: Ed2kCodec's encoder chooses compression itself.
async fn send(peer: &mut Peer, payload: Vec<u8>, packed: bool) {
    use std::io::Write;
    let body = if packed {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&payload).unwrap();
        z.finish().unwrap()
    } else {
        payload
    };
    let mut wire = vec![if packed { PROTO_PACKED } else { PROTO_EDONKEY }];
    wire.extend_from_slice(&((body.len() + 1) as u32).to_le_bytes());
    wire.push(OP_OFFERFILES);
    wire.extend_from_slice(&body);
    peer.get_mut().write_all(&wire).await.unwrap();
}

async fn indexed(state: &ServerState, n: usize) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while state.file_count() != n {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("expected indexed count not reached");
}

/// Same-connection processing barrier: a search sent after an offer is
/// answered only once the offer has been processed. Returns the server
/// messages that arrived before the answer.
async fn alive(peer: &mut Peer) -> Vec<String> {
    peer.send(Frame::new(OP_SEARCHREQUEST, build_search_term("Linux")))
        .await
        .unwrap();
    let mut messages = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = peer.next().await.expect("unexpected disconnect").unwrap();
            if frame.opcode == OP_SERVERMESSAGE {
                messages.push(String::from_utf8_lossy(&frame.payload[2..]).into_owned());
            }
            if frame.opcode == OP_SEARCHRESULT {
                break;
            }
        }
    })
    .await
    .expect("search barrier timed out");
    messages
}

// ── The draft cases ─────────────────────────────────────────────────────────

#[tokio::test]
async fn disabled_advertises_no_v1_tags() {
    let (port, _, task) = server(false).await;
    let (_, tags) = login(port, 1).await;
    assert_no_v1(&tags);
    task.abort();
}

#[tokio::test]
async fn enabled_advertisement_is_atomic_uint32() {
    let (port, state, task) = server(true).await;
    let (_, tags) = login(port, 2).await;
    assert_policy(&tags);
    assert_eq!(state.offer_v1.sessions.load(std::sync::atomic::Ordering::Relaxed), 1);
    task.abort();
}

#[tokio::test]
async fn compliant_pacing_indexes_every_batch() {
    let (port, state, task) = server(true).await;
    let (mut peer, tags) = login(port, 3).await;
    assert_policy(&tags);
    send(&mut peer, offer(10, BATCH), false).await;
    indexed(&state, 2).await;
    tokio::time::sleep(Duration::from_millis(INTERVAL as u64 + 20)).await;
    send(&mut peer, offer(20, BATCH), true).await;
    indexed(&state, 4).await;
    alive(&mut peer).await;
    task.abort();
}

#[tokio::test]
async fn closely_arriving_batches_wait_without_loss() {
    let (port, state, task) = server(true).await;
    let (mut peer, tags) = login(port, 4).await;
    assert_policy(&tags);
    // A bounded arrival-clustering fixture, not an entitlement to send bursts.
    let started = std::time::Instant::now();
    send(&mut peer, offer(30, BATCH), false).await;
    send(&mut peer, offer(40, BATCH), false).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    if started.elapsed() < Duration::from_millis(INTERVAL as u64 - 20) {
        assert!(
            state.file_count() <= 2,
            "second full batch bypassed token refill"
        );
    }
    indexed(&state, 4).await;
    alive(&mut peer).await;
    assert!(state.offer_v1.conn_waits.load(std::sync::atomic::Ordering::Relaxed) >= 1);
    task.abort();
}

#[tokio::test]
async fn oversized_below_hard_is_rejected_without_disconnect() {
    let (port, state, task) = server(true).await;
    let (mut peer, tags) = login(port, 5).await;
    assert_policy(&tags);
    send(&mut peer, offer(50, BATCH + 1), false).await;
    alive(&mut peer).await; // Same-connection processing barrier.
    assert_eq!(state.file_count(), 0);
    assert_eq!(state.offer_v1.oversized.load(std::sync::atomic::Ordering::Relaxed), 1);
    send(&mut peer, offer(60, 1), false).await;
    indexed(&state, 1).await;
    task.abort();
}

#[tokio::test]
async fn soft_budget_counts_distinct_indexed_files() {
    let (port, state, task) = server(true).await;
    let (mut peer, tags) = login(port, 6).await;
    assert_policy(&tags);
    let mut messages = Vec::new();
    for first in [70, 70, 80, 90, 100] {
        // Repeat first batch, then exhaust the budget, then go over it again.
        send(&mut peer, offer(first, BATCH), false).await;
        messages.extend(alive(&mut peer).await);
        tokio::time::sleep(Duration::from_millis(INTERVAL as u64 + 20)).await;
    }
    assert_eq!(state.file_count(), SOFT as usize);
    // Each indexed source is this client, and the sixth distinct file is not.
    for h in [70u8, 71, 80, 81, 90] {
        assert!(state.file_slab.id_of(&[h; 16]).is_some(), "file {h} indexed");
    }
    assert!(state.file_slab.id_of(&[91; 16]).is_none());
    // Two batches went over; the limit message came once.
    let limit_msgs = messages.iter().filter(|m| m.contains("shares per client")).count();
    assert_eq!(limit_msgs, 1, "{messages:?}");
    task.abort();
}

async fn hard_boundary(packed: bool) {
    let (port, state, task) = server(true).await;
    let (mut peer, tags) = login(port, 7).await;
    assert_policy(&tags);
    send(&mut peer, offer(100, HARD), packed).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(Ok(_)) = peer.next().await {}
    })
    .await
    .expect("hard-boundary packet did not close connection");
    assert_eq!(state.file_count(), 0);
    task.abort();
}

#[tokio::test]
async fn plain_hard_equality_disconnects() {
    hard_boundary(false).await;
}

#[tokio::test]
async fn packed_hard_equality_disconnects() {
    hard_boundary(true).await;
}

#[tokio::test]
async fn reconnect_gets_fresh_advertisement() {
    let (port, _, task) = server(true).await;
    let (peer, tags) = login(port, 8).await;
    assert_policy(&tags);
    drop(peer);
    let (_, tags) = login(port, 9).await;
    assert_policy(&tags);
    task.abort();
}

// ── Follow-up cases from the draft's README ─────────────────────────────────

/// Each rule of the contract, broken in the configuration: no offerfiles_*
/// tag, and legacy enforcement (an "oversized" batch is simply indexed).
#[tokio::test]
async fn an_invalid_configuration_advertises_nothing_and_stays_legacy() {
    type Bad = fn(&mut Config);
    let cases: [(&str, Bad); 4] = [
        ("soft 0", |c| c.limits.soft_limit_files = 0),
        ("batch 0", |c| c.limits.offerfiles_batch_max = 0),
        ("interval 0", |c| c.limits.offerfiles_min_interval_ms = 0),
        ("hard <= batch", |c| c.limits.hard_limit_files = BATCH),
    ];
    for (what, bad) in cases {
        let (port, state, task) = server_with(
            |port| {
                let mut c = v1_config(port, true);
                bad(&mut c);
                // Room for a 3-record batch on the legacy path.
                if c.limits.hard_limit_files > BATCH {
                    c.limits.hard_limit_files = 100;
                }
                c
            },
            ContentFilter::new(),
        )
        .await;
        let (mut peer, tags) = login(port, 20).await;
        assert_no_v1(&tags);
        if state.live_cfg.load().limits.hard_limit_files > BATCH + 1
            || state.live_cfg.load().limits.hard_limit_files == 0
        {
            send(&mut peer, offer(1, BATCH + 1), false).await;
            alive(&mut peer).await;
            assert_eq!(state.file_count(), (BATCH + 1) as usize, "{what}");
        }
        assert_eq!(state.offer_v1.sessions.load(std::sync::atomic::Ordering::Relaxed), 0, "{what}");
        task.abort();
    }
}

/// v1 off: back-to-back batches of any size below hard go straight through.
#[tokio::test]
async fn disabled_capability_keeps_legacy_publishing() {
    let (port, state, task) = server_with(
        |port| {
            let mut c = v1_config(port, false);
            c.limits.hard_limit_files = 100;
            c.limits.soft_limit_files = 1000;
            c
        },
        ContentFilter::new(),
    )
    .await;
    let (mut peer, tags) = login(port, 21).await;
    assert_no_v1(&tags);
    let started = std::time::Instant::now();
    send(&mut peer, offer(1, 10), false).await;
    send(&mut peer, offer(20, 10), true).await;
    send(&mut peer, offer(40, 10), false).await;
    alive(&mut peer).await;
    assert_eq!(state.file_count(), 30);
    assert!(started.elapsed() < Duration::from_millis(INTERVAL as u64), "no pacing");
    task.abort();
}

/// A config change while A is connected: A keeps the values it was told, both
/// in what it is held to and in the soft budget; B gets the new ones.
#[tokio::test]
async fn a_live_change_reaches_new_connections_only() {
    let (port, state, task) = server(true).await;
    let (mut a, tags) = login(port, 30).await;
    assert_policy(&tags);

    let mut changed = (**state.live_cfg.load()).clone();
    changed.limits.offerfiles_batch_max = 3;
    changed.limits.offerfiles_min_interval_ms = 300;
    changed.limits.soft_limit_files = 8;
    changed.limits.hard_limit_files = 10;
    state.live_cfg.store(Arc::new(changed));

    // A: its soft budget is still 5, though the live one is now 8.
    for first in [1, 3, 5] {
        send(&mut a, offer(first, BATCH), false).await;
        alive(&mut a).await;
        tokio::time::sleep(Duration::from_millis(INTERVAL as u64 + 20)).await;
    }
    assert_eq!(state.file_count(), SOFT as usize);
    // A: 3 records is above ITS batch_max of 2 — not indexed, session kept.
    send(&mut a, offer(20, 3), false).await;
    alive(&mut a).await;
    assert_eq!(state.file_count(), SOFT as usize);
    // A: 4 records reaches ITS hard limit of 4 — disconnected, though the live
    // hard limit is now 10.
    send(&mut a, offer(30, 4), false).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(Ok(_)) = a.next().await {}
    })
    .await
    .expect("A must be held to its own hard limit");

    // B: told the new values, held to them.
    let (mut b, tags) = login(port, 31).await;
    assert_policy_values(&tags, 3, 300, 8, 10);
    send(&mut b, offer(50, 3), false).await;
    alive(&mut b).await;
    // A's files left with A (single-source files go on disconnect).
    assert!(state.file_slab.id_of(&[50; 16]).is_some());
    assert!(state.file_slab.id_of(&[52; 16]).is_some());
    task.abort();
}

/// Records the content filter blocks use no budget.
#[tokio::test]
async fn filtered_records_use_no_soft_budget() {
    // Two blocked hashes (below the ban threshold of 3 in test_config).
    let filter = ContentFilter::new().with_hash_blocklist([[200u8; 16], [201u8; 16]]);
    let (port, state, task) = server_with(|port| v1_config(port, true), filter).await;
    let (mut peer, tags) = login(port, 40).await;
    assert_policy(&tags);
    send(&mut peer, offer(200, BATCH), false).await; // both blocked
    alive(&mut peer).await;
    assert_eq!(state.file_count(), 0);
    for first in [1, 3] {
        tokio::time::sleep(Duration::from_millis(INTERVAL as u64 + 20)).await;
        send(&mut peer, offer(first, BATCH), false).await;
        alive(&mut peer).await;
    }
    tokio::time::sleep(Duration::from_millis(INTERVAL as u64 + 20)).await;
    send(&mut peer, offer(5, 1), false).await;
    alive(&mut peer).await;
    // The full budget of 5 was still available after the blocked batch.
    assert_eq!(state.file_count(), SOFT as usize);
    task.abort();
}

/// Global overload: two publishers under a ceiling far below what they offer.
/// Every compliant record is indexed, nobody is disconnected, and the waits
/// show up in the counters.
#[tokio::test]
async fn the_global_ceiling_slows_publishers_without_losing_records() {
    let (port, state, task) = server_with(
        |port| {
            let mut c = v1_config(port, true);
            c.limits.soft_limit_files = 100;
            c.limits.offerfiles_global_records_per_sec = 10;
            c
        },
        ContentFilter::new(),
    )
    .await;
    let (mut a, tags_a) = login(port, 50).await;
    let (mut b, tags_b) = login(port, 51).await;
    assert_policy_values(&tags_a, BATCH, INTERVAL, 100, HARD);
    assert_policy_values(&tags_b, BATCH, INTERVAL, 100, HARD);
    let started = std::time::Instant::now();
    // 2 x 6 batches x 2 records = 24 records at 10/s: the ceiling, not the
    // per-connection pace (6 batches per 1 s), decides how long this takes.
    let pa = async {
        for k in 0..6u8 {
            send(&mut a, offer(10 + 2 * k, BATCH), false).await;
            tokio::time::sleep(Duration::from_millis(INTERVAL as u64 + 5)).await;
        }
        alive(&mut a).await;
    };
    let pb = async {
        for k in 0..6u8 {
            send(&mut b, offer(110 + 2 * k, BATCH), false).await;
            tokio::time::sleep(Duration::from_millis(INTERVAL as u64 + 5)).await;
        }
        alive(&mut b).await;
    };
    tokio::join!(pa, pb);
    indexed(&state, 24).await;
    let took = started.elapsed();
    use std::sync::atomic::Ordering::Relaxed;
    assert!(state.offer_v1.global_waits.load(Relaxed) > 0);
    // The first 10 records ride the initial allowance; the other 14 need 1.4 s.
    assert!(took >= Duration::from_millis(1300), "{took:?}");
    assert_eq!(state.offer_v1.records.load(Relaxed), 24);
    assert_eq!(state.offer_v1_pacer.waiting.load(Relaxed), 0);
    task.abort();
}

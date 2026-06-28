//! Per-connection handler (SPEC.md §6.1).
//!
//! Works over `CryptStream` — transparently handles both plain and
//! RC4-encrypted connections. The obfuscation handshake is performed
//! upstream in `make_stream()`; by the time we get here, the stream
//! is already set up correctly.

use crate::config::Config;
use crate::proto::{opcodes::*, CryptStream, Ed2kCodec, Frame};
use crate::server::callback::handle_callback_request;
use crate::server::get_sources::{handle_get_sources, GetSourcesRequest};
use crate::server::login::{build_welcome_batch, handle_login, LoginRequest};
use crate::server::offerfiles::{handle_offerfiles, parse_offerfiles};
use crate::server::search::{handle_search, SearchRequest};
use crate::state::{ClientHandle, ServerState};
use anyhow::Result;
use bytes::{BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::codec::Framed;
use tracing::{debug, info, warn};

pub async fn handle_connection(
    cfg: Arc<Config>,
    state: Arc<ServerState>,
    stream: CryptStream,
    peer: SocketAddr,
) -> Result<()> {
    let codec = Ed2kCodec::new(cfg.network.max_frame_size);
    let mut framed = Framed::new(stream, codec);

    let mut client: Option<ClientHandle> = None;
    // Channel for OTHER tasks to push frames at this client — used by CALLBACK
    // (HighID peer asks the server to tell a LowID peer "please connect to me").
    // The Sender is stored in ClientHandle.tx by the login handler so callers
    // can locate the target by assigned_id and call target.send_frame(frame).
    // Buffer of 32 is plenty: callbacks are infrequent and pushed frames are
    // small. Was previously `(_, rx) = channel(1)` which discarded the Sender
    // entirely — so ClientHandle.tx was always None and callbacks were silent
    // no-ops.
    let (_tx, mut rx): (mpsc::Sender<Frame>, mpsc::Receiver<Frame>) = mpsc::channel(32);

    // Per-connection buffer of search results not yet sent to this client.
    // SEARCHREQUEST fills it; QUERY_MORE_RESULT (0x21) drains it page by page.
    // Lives in the connection task — it is per-connection, not per-identity.
    let mut pending_search: Vec<crate::state::file_id::FileRecord> = Vec::new();

    if cfg.log.connection_trace {
        info!(ip = %peer.ip(), port = peer.port(), "connection accepted");
    }

    // IP filter check — drop blocked addresses before spending any resources.
    if let std::net::IpAddr::V4(v4) = peer.ip() {
        if state.ip_filter.read().await.is_blocked(v4) {
            *state.block_stats.entry("ipfilter".to_string()).or_insert(0) += 1;
            debug!(ip = %v4, "connection dropped — IP filter");
            return Ok(());
        }
    }

    // Timeouts. Without these, scanners and broken clients can leave TCP
    // connections in our task list forever — every one is a live tokio task
    // and a file descriptor. Over hours this drains CPU and memory until the
    // server becomes unresponsive (observed in production after ~12 hours).
    //
    // login_timeout: how long we wait for LOGINREQUEST after TCP accept.
    // idle_timeout:  how long we tolerate silence from a LOGGED-IN client.
    //
    // The idle window must be MUCH larger than ping_delay_seconds (the
    // server's outgoing ping interval). A real eMule client is allowed to
    // sit silent between server pings — it answers our 0x34 SERVERSTATUS
    // by simply continuing to use the connection. If idle_after ≤
    // ping_delay, clients get evicted on every ping cycle. Use 3× ping
    // delay with a 10-minute floor so even very chatty configs keep their
    // clients connected, and a `last_activity` reset on every push from
    // the keepalive task (rx.recv() arm) so server-side traffic also
    // counts as "active".
    let login_deadline = tokio::time::Instant::now()
        + std::time::Duration::from_millis(cfg.network.login_timeout_ms);
    // Idle policy (Lugdunum-style): once a client is LOGGED IN, liveness is
    // determined by the TCP socket, NOT by application silence. A legitimate
    // client behind a carrier-grade NAT may stay completely quiet for hours —
    // it logged in, published its files, and just sits there as a source,
    // never searching or requesting. Such a client is fully alive; evicting it
    // on silence (the old behaviour) is exactly the bug that made the
    // provider-NAT box flap on/off the server while eMule still believed it was
    // connected.
    //
    // The reliable death signal is the socket itself: OS-level TCP keepalive
    // (configured at accept: 60s idle, 30s probe, 8 retries → a dead path is
    // detected and the socket closed within ~5 min) makes `framed.next()`
    // return None/Err when the NAT route is truly gone, which breaks the loop
    // below via the normal disconnect path. On top of that, the server writes
    // OP_SERVERSTATUS to every client each keepalive cycle; a failed write also
    // surfaces a dead socket. So we no longer need a tight application idle
    // timeout to detect death.
    //
    // We keep only a very loose application backstop (hours) for the pathological
    // case where OS keepalive is somehow not honored end-to-end. It is refreshed
    // by ANY activity: an inbound TCP frame, the UDP NAT-T keepalive (shared
    // clock), or a server push on the rx arm. In practice the socket closes long
    // before this fires.
    // Loose backstop for logged-in clients: 6 hours. Only trips if a client is
    // dark on BOTH TCP and UDP for that whole span AND the socket somehow never
    // closed — effectively never, but bounds truly leaked sessions.
    let logged_in_backstop = std::time::Duration::from_secs(6 * 3600);
    let mut last_activity = tokio::time::Instant::now();

    loop {
        // The next deadline depends on whether the client has logged in yet.
        let deadline = if client.is_none() {
            // Not logged in: tight timeout guards against half-open / scanner
            // sockets that complete the crypto handshake but never LOGINREQUEST.
            login_deadline
        } else {
            // Logged in: rely on the socket for liveness. Use the loose backstop,
            // refreshed by the more recent of TCP / UDP activity, so a NAT-T
            // LowID source that only speaks UDP — or a plain client that is
            // simply quiet — is NOT evicted while its TCP link is alive.
            let udp_idle = client
                .as_ref()
                .map(|c| std::time::Duration::from_millis(c.idle_ms()))
                .unwrap_or(logged_in_backstop);
            let tcp_idle = last_activity.elapsed();
            let effective_idle = tcp_idle.min(udp_idle);
            tokio::time::Instant::now()
                + logged_in_backstop.saturating_sub(effective_idle)
        };

        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                if client.is_none() {
                    debug!(ip = %peer.ip(),
                           "login timeout — no LOGINREQUEST received, dropping");
                } else {
                    // DIAGNOSTIC: info-level so the operator can see exactly when
                    // and why a logged-in client is evicted, and which clock was
                    // stale. If udp_idle_s keeps growing past idle_after while the
                    // client is alive, its UDP keepalives are not reaching us /
                    // not bumping the shared clock.
                    let udp_idle_s = client.as_ref().map(|c| c.idle_ms() / 1000).unwrap_or(0);
                    let tcp_idle_s = last_activity.elapsed().as_secs();
                    info!(ip = %peer.ip(),
                          backstop_s = logged_in_backstop.as_secs(),
                          tcp_idle_s, udp_idle_s,
                          "idle backstop reached — dropping logged-in client (socket never closed)");
                }
                break;
            }
            result = framed.next() => {
                last_activity = tokio::time::Instant::now();
                if let Some(c) = client.as_ref() { c.touch_activity(); }
                match result {
                    Some(Ok(frame)) => {
                        if let Err(e) = dispatch(
                            &cfg, &state, &state, &mut client, &mut framed, &mut rx,
                            &mut pending_search, peer, frame
                        ).await {
                            warn!(ip = %peer.ip(), error = %e, "handler error");
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        warn!(ip = %peer.ip(), error = %e, "frame error - dropping");
                        break;
                    }
                    None => {
                        debug!(ip = %peer.ip(), "client closed connection");
                        break;
                    }
                }
            }
            Some(frame) = rx.recv() => {
                if let Err(e) = framed.send(frame).await {
                    debug!(ip = %peer.ip(), error = %e, "send error on pushed frame");
                    break;
                }
                // Pushed frames (server-originated keepalive pings, search
                // results, etc.) are also legitimate connection activity —
                // a quiet client that we just pinged is not idle, it is
                // a working session. Without this reset, the idle timer
                // measures only client-to-server bytes and evicts clients
                // mid-keepalive-cycle.
                last_activity = tokio::time::Instant::now();
            }
        }

        if let Some(c) = &client {
            if c.csam_attempts >= cfg.content_filter.publisher_attempt_disconnect_threshold {
                warn!(ip = %peer.ip(), csam_attempts = c.csam_attempts, "csam threshold — disconnecting");
                break;
            }
        }
    }

    if let Some(c) = client {
        info!(ip = %peer.ip(), nick = %c.nick, id = c.assigned_id, "client disconnected");
        // Only remove from clients if the entry still belongs to OUR session.
        // If a NEW login from the same user_hash already replaced us (NAT-drop
        // scenario), we must NOT touch the map nor the LowID counter — the new
        // session is responsible for both. Without this guard, an old stale task
        // would erroneously evict the live client and decrement the counter
        // again, causing user dropouts and LowID-count drift.
        let should_decrement_lowid = match state.clients.get(&c.user_hash) {
            Some(entry) => entry.assigned_id == c.assigned_id,
            None => false,
        };
        if should_decrement_lowid {
            if !c.is_high_id {
                state.lowid_count_cached
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            }
            state.clients.remove(&c.user_hash);
            state.remove_sources_of(&c.user_hash);
        }
    }

    Ok(())
}

async fn dispatch(
    cfg: &Config,
    state: &ServerState,
    state_arc: &Arc<ServerState>, // same state, owned handle for detached tasks
    client: &mut Option<ClientHandle>,
    framed: &mut Framed<CryptStream, Ed2kCodec>,
    rx: &mut mpsc::Receiver<Frame>,
    pending_search: &mut Vec<crate::state::file_id::FileRecord>,
    peer: SocketAddr,
    frame: Frame,
) -> Result<()> {
    if tracing::enabled!(tracing::Level::DEBUG) {
        debug!(
            ip = %peer.ip(),
            opcode = format!("0x{:02x}", frame.opcode),
            op_name = opcode_name_c2s(frame.opcode),
            len = frame.payload.len(),
            "frame in"
        );
    }

    match frame.opcode {
        OP_LOGINREQUEST => {
            if client.is_some() {
                warn!(ip = %peer.ip(), "duplicate LOGINREQUEST");
                return Ok(());
            }
            let req = LoginRequest::parse(&frame.payload)?;
            // Q1: refuse logins from user_hashes banned for publishing CSAM.
            // Checked by user_hash (stable) not IP (dynamic). Done after parsing
            // since user_hash arrives in the login payload. Ban lasts
            // publisher_blacklist_seconds — banned publisher can't re-enter.
            {
                let ttl = std::time::Duration::from_secs(
                    cfg.content_filter.publisher_blacklist_seconds);
                if state.is_publisher_banned(&req.user_hash, ttl) {
                    warn!(ip = %peer.ip(), user_hash = hex::encode(req.user_hash),
                          "login refused — CSAM publisher is banned");
                    return Err(anyhow::anyhow!("banned CSAM publisher"));
                }
            }
            let mut new_client = handle_login(cfg, state, peer.ip(), req).await;
            *rx = ServerState::create_client_channel(&mut new_client);
            // Detect duplicate user_hash login — happens when a NAT-dropped
            // connection's old task hasn't timed out yet, but the same user
            // reconnects. DashMap::insert silently replaces; without this
            // adjustment our LowID counter would double-count until the old
            // task eventually times out and decrements. eMule then reports
            // a LowID count > total connected clients.
            let prev = state.clients.insert(new_client.user_hash, new_client.clone());
            // Maintain cached lowid count so handle_servstat doesn't do an O(N)
            // iter on every UDP probe (was 2.58% of CPU in v0.9.36 profile).
            if let Some(old) = &prev {
                if !old.is_high_id {
                    state.lowid_count_cached
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            if !new_client.is_high_id {
                state.lowid_count_cached
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            // Track this IP as a recently-seen client for 30 minutes.
            // merge_server_list (gossip) uses this to prevent mldonkey client IPs
            // from entering our peer-server list even after they disconnect.
            if let std::net::IpAddr::V4(client_v4) = new_client.ip {
                state.recent_client_ips.insert(client_v4, std::time::Instant::now());
            }
            // Evict this IP from gossip server_list if it was added there by
            // a previous gossip cycle (mldonkey clients advertise themselves
            // to seeds, which propagate them to us as "servers"). This keeps
            // the Clients and Peer servers admin tabs disjoint.
            if let std::net::IpAddr::V4(client_v4) = new_client.ip {
                let mut sl = state.server_list.write().await;
                sl.retain(|s| s.ip() != &client_v4);
            }
            *client = Some(new_client.clone());
            for f in build_welcome_batch(cfg, state, &new_client) {
                framed.send(f).await?;
            }
        }

        OP_OFFERFILES => {
            let Some(c) = client else {
                return Err(anyhow::anyhow!("OFFERFILES before login"));
            };
            let files = parse_offerfiles(&frame.payload)?;
            handle_offerfiles(state, c, files);
            if let Some(mut entry) = state.clients.get_mut(&c.user_hash) {
                entry.csam_attempts = c.csam_attempts;
            }
        }

        OP_SEARCHREQUEST => {
            let Some(_) = client.as_ref() else {
                return Err(anyhow::anyhow!("SEARCHREQUEST before login"));
            };
            match SearchRequest::parse(&frame.payload) {
                Ok(req) => {
                    use crate::server::search::{build_search_result_page, SEARCH_PAGE_SIZE};
                    // Run the search; keep the full result set in this
                    // connection's pending buffer.
                    let mut all = handle_search(state, req);
                    let first_len = all.len().min(SEARCH_PAGE_SIZE);
                    let first_page: Vec<_> = all.drain(..first_len).collect();
                    let has_more = !all.is_empty();
                    *pending_search = all; // remainder for QUERY_MORE_RESULT
                    framed
                        .send(build_search_result_page(&first_page, has_more))
                        .await?;
                }
                Err(e) => {
                    warn!(ip = %peer.ip(), error = %e, "search parse failed");
                    pending_search.clear();
                    let mut p = BytesMut::new();
                    p.put_u32_le(0u32);
                    p.put_u8(0u8);
                    framed.send(Frame::new(OP_SEARCHRESULT, p.to_vec())).await?;
                }
            }
        }

        OP_GETSOURCES | OP_GETSOURCES_OBFU => {
            let Some(c) = client.as_ref() else {
                return Err(anyhow::anyhow!("GETSOURCES before login"));
            };
            if let Ok(req) = GetSourcesRequest::parse(&frame.payload) {
                framed.send(handle_get_sources(state, c, req)).await?;
            }
        }

        OP_CALLBACKREQUEST => {
            let Some(c) = client.as_ref() else {
                return Err(anyhow::anyhow!("CALLBACKREQUEST before login"));
            };
            if frame.payload.len() >= 4 {
                let target_id = u32::from_le_bytes([
                    frame.payload[0], frame.payload[1],
                    frame.payload[2], frame.payload[3],
                ]);
                handle_callback_request(state, c, target_id, framed).await?;
            }
        }

        OP_LOWID_HOLEPUNCH_REQUEST => {
            let Some(c) = client.as_ref() else {
                return Err(anyhow::anyhow!("HOLEPUNCH_REQUEST before login"));
            };
            // payload: target_id(4) + requester_udp_port(2)
            if frame.payload.len() >= 6 {
                let target_id = u32::from_le_bytes([
                    frame.payload[0], frame.payload[1],
                    frame.payload[2], frame.payload[3],
                ]);
                let requester_udp_port =
                    u16::from_le_bytes([frame.payload[4], frame.payload[5]]);
                crate::server::holepunch::handle_holepunch_request(
                    state,
                    &c.user_hash,
                    c.assigned_id,
                    c.ip,
                    c.port,
                    requester_udp_port,
                    target_id,
                );
                // Best-effort: re-coordinate a couple of times over the next few
                // seconds so a lost/late INFO on the server TCP link doesn't
                // leave the two peers punching at non-overlapping times. Detached
                // task; reuses the same handler, sends nothing new on success.
                crate::server::holepunch::schedule_info_retries(
                    std::sync::Arc::clone(state_arc),
                    c.user_hash,
                    c.assigned_id,
                    c.ip,
                    c.port,
                    requester_udp_port,
                    target_id,
                );
            }
        }

        OP_GETSERVERLIST => {
            let payload = crate::server::gossip::build_tcp_server_list(state).await;
            framed.send(Frame::new(OP_SERVERLIST, payload)).await?;
        }

        OP_DISCONNECT => {
            return Err(anyhow::anyhow!("client disconnect"));
        }

        OP_QUERY_MORE_RESULT => {
            // Client wants the next page of the last search. Drain another
            // page from this connection's pending buffer.
            use crate::server::search::{build_search_result_page, SEARCH_PAGE_SIZE};
            if pending_search.is_empty() {
                // Nothing buffered — reply with an empty, "no more" result
                // so the client's More button settles.
                let mut p = BytesMut::new();
                p.put_u32_le(0u32);
                p.put_u8(0u8);
                framed.send(Frame::new(OP_SEARCHRESULT, p.to_vec())).await?;
            } else {
                let n = pending_search.len().min(SEARCH_PAGE_SIZE);
                let page: Vec<_> = pending_search.drain(..n).collect();
                let has_more = !pending_search.is_empty();
                debug!(ip = %peer.ip(), page = page.len(), has_more,
                       "QUERY_MORE_RESULT — sending next page");
                framed.send(build_search_result_page(&page, has_more)).await?;
            }
        }

        other => {
            debug!(ip = %peer.ip(), opcode = format!("0x{:02x}", other), "unknown opcode");
        }
    }

    Ok(())
}

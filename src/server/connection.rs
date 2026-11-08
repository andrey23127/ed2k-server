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
use crate::server::login::{handle_login, LoginRequest};
/// OFFERFILES batches of up to this many records are handled on the runtime.
const OFFER_INLINE_MAX: usize = 8;

use crate::server::offerfiles::{
    declared_count, handle_offerfiles, over_hard_limit, parse_offerfiles, soft_limit_message,
};
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

/// A session closed on purpose (server full, banned publisher, OFFERFILES over
/// the hard limit). Ends the connection like any handler error, but is logged
/// where it is decided.
#[derive(Debug)]
pub(crate) struct SessionRefused(pub &'static str);

impl std::fmt::Display for SessionRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for SessionRefused {}

/// `limits.max_clients`: reserve a logged-in slot for this user hash, or None
/// if the server is full. `max == 0` = no cap. A user hash already connected
/// is replacing its own session and is always let in.
///
/// A reservation, not a count-then-insert (issue #25): the slot is taken with
/// one compare-and-swap before the login does any work, so concurrent logins
/// cannot all see room. The connection task holds it until it ends.
/// May a login from `ip` with listen port `listen_port` replace `prev`, the
/// live session of the same user hash (issue #41)? User hashes are public:
/// every hello and every source exchange carries them, so a hash alone does
/// not say who is asking. Yes when:
///  1. the old session is already gone (its connection task has ended);
///  2. the same source: the same IPv4, or the same IPv6 prefix — the
///     NAT-dropped reconnect this replacement exists for;
///  3. a dual-stack move: the old session is IPv4, the new one comes from
///     exactly the IPv6 the old one advertised (`CT_MOD_IP_V6`) and has the
///     same listen port. Only that host can connect from that address. Not
///     the other way: that would trust an address the newcomer claims.
pub(crate) fn may_replace_session(
    state: &ServerState,
    prev: &crate::state::ClientHandle,
    ip: std::net::IpAddr,
    listen_port: u16,
) -> bool {
    use std::net::IpAddr;
    if !prev.is_alive() || state.live_cfg.load().limits.hash_takeover_from_any_address {
        return true;
    }
    // A hash many people use identifies no one: there is no owner to protect,
    // and refusing them all but one locks the rest out of the server.
    if is_shared_hash(state, &prev.user_hash) {
        return true;
    }
    let canon = |ip: IpAddr| match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    let (old, new) = (canon(prev.ip), canon(ip));
    if state.source_key(old) == state.source_key(new) {
        return true;
    }
    matches!((old, new), (IpAddr::V4(_), IpAddr::V6(v6))
        if prev.ipv6 == Some(v6) && prev.port == listen_port)
}

/// The takeover probe (issue #41, ModderMule's idea as got3nks refined it).
/// A contested login makes the old session's task set `TCP_USER_TIMEOUT` to
/// `PROBE_USER_TIMEOUT` and write it an `OP_SERVERSTATUS`. When the user has
/// moved, the old path is dead and nothing answers: the kernel aborts the
/// connection once the write has gone unacknowledged that long, the old
/// session ends, and the new login, held meanwhile, goes ahead. An ACK means
/// the old session is alive: the login is refused, and the timeout goes back
/// to `SESSION_TCP_USER_TIMEOUT`. The wait stays inside the 25 s eMule-family
/// clients allow for the login answer, so a real move succeeds on the first
/// attempt instead of after about five minutes.
const PROBE_USER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// The abort fires at the first retransmission after the timeout: up to a
/// few seconds past it with exponential backoff.
const TAKEOVER_PROBE_WAIT: std::time::Duration = std::time::Duration::from_secs(16);
/// A contender refused after a probe is refused without one this long.
const TAKEOVER_CONTENDER_MEMORY: std::time::Duration = std::time::Duration::from_secs(600);
/// After a probe found the session alive, the next one waits this long.
const TAKEOVER_PROBE_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(10);
/// The usual limit on unacknowledged data for client sockets; the same value
/// as `TCP_USER_TIMEOUT` set at accept in main.rs.
const SESSION_TCP_USER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Is the old session gone? Probes it when no probe is running or cooling
/// down; one probe per session at a time, so contested logins cannot be used
/// to keep writing to a live owner. A login that arrives while a probe runs
/// waits for that probe's outcome.
async fn old_session_gone(state: &ServerState, prev: &ClientHandle) -> bool {
    if !prev.is_alive() {
        return true;
    }
    let now = std::time::Instant::now();
    let started = {
        let mut e = state.takeover_probes.entry(prev.user_hash).or_insert(None);
        match *e {
            // Running: wait for it.
            Some(t) if now.duration_since(t) < TAKEOVER_PROBE_WAIT => t,
            // Just found the session alive.
            Some(t) if now.duration_since(t) < TAKEOVER_PROBE_WAIT + TAKEOVER_PROBE_COOLDOWN => {
                return !prev.is_alive();
            }
            _ => {
                *e = Some(now);
                let mut p = BytesMut::with_capacity(8);
                p.put_u32_le(state.client_count() as u32);
                p.put_u32_le(state.file_count() as u32);
                let _ = prev.send_frame(Frame::new(INTERNAL_PROBE, p.to_vec()));
                crate::server::holepunch::count(state, "login_takeover_probe");
                now
            }
        }
    };
    let deadline = tokio::time::Instant::from_std(started + TAKEOVER_PROBE_WAIT);
    while tokio::time::Instant::now() < deadline {
        if !prev.is_alive() {
            crate::server::holepunch::count(state, "login_takeover_after_probe");
            // That session is gone; the next contest is about a new one.
            state.takeover_probes.remove(&prev.user_hash);
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    !prev.is_alive()
}

/// Is this user hash used by many installs at once, so that it identifies no
/// one (issue #41)? Either it is degenerate — 12 or more zero bytes, as the
/// "corrupt" community hash `00000000000E00000000000000006F00` of a leecher
/// mod is; a random hash practically never is — or the operator lists it in
/// `limits.shared_user_hashes` or on the built-in list of DLP's community
/// hashes. For such a
/// hash the old rule applies: the newest login takes the session.
///
/// Not by how many addresses contest it: that is exactly what a hijacker
/// produces — three logins from three proxies would turn any user's hash
/// into a shared one (got3nks). The address count is only reported, in
/// `/api/takeover`.
pub(crate) fn is_shared_hash(state: &ServerState, h: &crate::state::UserHash) -> bool {
    if h.iter().filter(|b| **b == 0).count() >= 12 {
        return true;
    }
    let hex = hex::encode(h);
    crate::config::DLP_SHARED_USER_HASHES
        .iter()
        .any(|s| s.eq_ignore_ascii_case(&hex))
        || state
            .live_cfg
            .load()
            .limits
            .shared_user_hashes
            .iter()
            .any(|s| s.trim().eq_ignore_ascii_case(&hex))
}

/// Refuse a login whose user hash is online from elsewhere (issue #41).
async fn refuse_hash_in_use(
    framed: &mut Framed<CryptStream, Ed2kCodec>,
    state: &ServerState,
    peer: SocketAddr,
    user_hash: &crate::state::UserHash,
) -> anyhow::Error {
    *state
        .block_stats
        .entry("login_hash_in_use".to_string())
        .or_insert(0) += 1;
    let text = b"This user hash is already connected from another address";
    let mut payload = Vec::with_capacity(2 + text.len());
    payload.extend_from_slice(&(text.len() as u16).to_le_bytes());
    payload.extend_from_slice(text);
    let _ = framed.send(Frame::new(OP_SERVERMESSAGE, payload)).await;
    if let Some(sup) = crate::health::throttle().allow(peer.ip(), "login_hash_in_use", crate::health::SUPPRESS_WINDOW) {
        info!(ip = %peer.ip(), user_hash = hex::encode(user_hash), suppressed = sup,
              "login refused — user hash online from another address");
    }
    SessionRefused("user hash online from another address").into()
}

pub(crate) fn reserve_client_slot(
    state: &ServerState,
    user_hash: &crate::state::UserHash,
    max: u32,
) -> Option<crate::admission::ClientSlot> {
    if state.clients.contains_key(user_hash) {
        return Some(state.admission.clients.force_reserve());
    }
    state.admission.clients.try_reserve(max)
}

/// Admission state one connection carries (issue #25). (Its logged-in slot
/// lives in the `ClientHandle`, where a replacing login can release it.)
pub(crate) struct SessionAdmission {
    /// Callback / hole-punch allowance.
    pub relay: crate::admission::RelayBudget,
    /// OFFERFILES v1 bucket of this connection (issue #19); `Some` exactly
    /// when the client was sent the v1 advertisement.
    pub offer_bucket: Option<crate::server::offer_pacing::Gcra>,
    /// OP_SERVERIDENT went out on this connection. It is sent at most once:
    /// at login to a client that needs it there, otherwise with the first
    /// server list (see `login::ident_at_login`). The OFFERFILES v1 contract
    /// promises one advertisement per connection.
    pub ident_sent: bool,
}

pub async fn handle_connection(
    cfg: Arc<Config>,
    state: Arc<ServerState>,
    stream: CryptStream,
    peer: SocketAddr,
) -> Result<()> {
    handle_admitted_connection(cfg, state, stream, peer, None).await
}

/// `handle_connection` for a socket admitted at accept: `pending_login` is its
/// `admission.max_pending_logins` permit, given back as soon as the login
/// completes (or the connection ends before that).
pub async fn handle_admitted_connection(
    cfg: Arc<Config>,
    state: Arc<ServerState>,
    stream: CryptStream,
    peer: SocketAddr,
    mut pending_login: Option<crate::admission::PendingLogin>,
) -> Result<()> {
    // Per-connection snapshot of the hot-reloadable config. Taken once here, so a
    // config change applies to every NEW connection without a restart while an
    // in-flight session keeps a consistent view for its whole lifetime.
    // `load_full()`, not `load()`: the returned value is held across await points
    // for the whole connection, and a fast Guard is tied to thread-local state that
    // tokio may move between worker threads. load_full() hands back a plain Arc,
    // which is safe to keep and costs one refcount bump per connection.
    let live = state.live_cfg.load_full();
    let codec = Ed2kCodec::new(live.network.max_frame_size)
        .with_max_decompressed(live.network.max_decompressed_frame_size);
    // Framed::new would allocate 8 KiB for the read buffer AND 8 KiB for the write
    // buffer — 16 KiB of heap per connection before a single byte arrives. eD2k
    // control frames are small (a login, a search, a keepalive: tens to hundreds of
    // bytes), so that baseline is mostly waste at 50k+ users. Start both buffers
    // small; BytesMut grows geometrically on demand, and the rare big frame (an
    // OFFERFILES publish) is handed back by reclaim_framed_buffers() afterwards.
    let mut framed = Framed::with_capacity(stream, codec, FRESH_BUF);
    // with_capacity only sizes the READ buffer; the write buffer still defaults to
    // 8 KiB. It is empty at this point, so swapping it is safe.
    *framed.write_buffer_mut() = BytesMut::with_capacity(FRESH_BUF);

    // Report this connection's buffer footprint so /api/memsize can show it instead
    // of it landing in "unaccounted". Kept in sync on every reclaim, removed on exit.
    // (codec buffers, CryptStream buffers) this connection has put on the
    // gauges; kept in step and taken off at the end.
    let mut accounted_bufs: (i64, i64) = (0, 0);
    account_framed_buffers(&state, &framed, &mut accounted_bufs);

    let mut client: Option<ClientHandle> = None;
    // Channel for OTHER tasks to push frames at this client — used by CALLBACK
    // (HighID peer asks the server to tell a LowID peer "please connect to me").
    // The Sender is stored in ClientHandle.tx by the login handler so callers
    // can locate the target by assigned_id and call target.send_frame(frame).
    // Buffer of 32 is plenty: callbacks are infrequent and pushed frames are
    // small. Was previously `(_, rx) = channel(1)` which discarded the Sender
    // entirely — so ClientHandle.tx was always None and callbacks were silent
    // no-ops.
    //
    // Until login there is nobody to push to, so this placeholder's sender is
    // dropped at once: login replaces `rx` with the real channel, and with both
    // ends gone the placeholder is freed there. Keeping the sender alive (it was
    // bound to `_tx` for the whole session) kept a second, never-used channel
    // allocated per connection (its shared state and first block of slots).
    // A closed channel's recv() resolves to None at once; the select! arm below
    // only matches Some, so it is simply skipped, not spun on.
    let mut rx: mpsc::Receiver<Frame> = mpsc::channel(1).1;

    // Per-connection buffer of search results not yet sent to this client.
    // SEARCHREQUEST fills it; QUERY_MORE_RESULT (0x21) drains it page by page.
    // Lives in the connection task — it is per-connection, not per-identity.
    let mut pending_search: Vec<crate::state::file_id::FileRecord> = Vec::new();
    let mut sess = SessionAdmission {
        relay: crate::admission::RelayBudget::new(&state.admission.cfg),
        offer_bucket: None,
        ident_sent: false,
    };

    if live.log.connection_trace {
        info!(ip = %peer.ip(), port = peer.port(), "connection accepted");
    }

    // IP filter check — drop blocked addresses before spending any resources.
    //
    // ⚠ IPv4 ONLY, and an operator enabling IPv6 should know it. Both list
    //   formats the filter reads (ipfilter.dat and .p2p) carry v4 ranges and
    //   nothing else, so there is no v6 range to test against — an IPv6 client
    //   is not "allowed through the filter", it is outside its coverage
    //   entirely. The same is true of every published blocklist we know of.
    //
    //   The content filter is unaffected: it works on filenames and runs later,
    //   on the same code path for both families.
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
        + std::time::Duration::from_millis(live.network.login_timeout_ms);
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
    // A session that a newer login of the same user has replaced is no
    // longer in `clients`: it gets no server pings, its files and sources
    // belong to the new session, and it holds nothing but a socket and a
    // per-IP slot. When the peer abandons such a socket without closing it
    // (seen live: one address kept 100 of them open, silent for 3-5 hours,
    // each until the 6 h backstop), only a short silence limit frees it. It
    // is not closed the moment it is replaced: two installs sharing one user
    // hash would then knock each other off as fast as they reconnect. But it
    // is fenced: its first frame closes it (issue #46), unless the hash is a
    // shared one.
    let replaced_idle = std::time::Duration::from_secs(10 * 60);
    // How often a logged-in session re-checks whether it has been replaced.
    let replaced_recheck = std::time::Duration::from_secs(60);
    let mut last_activity = tokio::time::Instant::now();
    // While a takeover probe runs (issue #41): when to put the socket's
    // TCP_USER_TIMEOUT back.
    let mut probe_restore: Option<tokio::time::Instant> = None;
    // A banned bot gets no session for its 24 hours, over TCP as over UDP.
    if state.is_bot_banned(peer.ip()) {
        crate::server::bot_detector::note_banned(&state, peer.ip(), &[]);
        *state.block_stats.entry("bot_tcp_refused".to_string()).or_insert(0) += 1;
        return Ok(());
    }
    // A new IP filter (a bot added to it, the file changed, a reload) or a
    // bot ban wakes this session to check its own address: the filter is otherwise only
    // read at accept, and a scanner added to it stayed connected for hours.
    let mut ipf_gen = state.ip_filter_gen.subscribe();
    let mut ipf_open = true;

    loop {
        // The next deadline depends on whether the client has logged in yet.
        let mut replaced = false;
        let (deadline, wake) = if let Some(c) = &client {
            let now = tokio::time::Instant::now();
            let tcp_idle = last_activity.elapsed();
            replaced = !state
                .clients
                .get(&c.user_hash)
                .is_some_and(|e| e.same_session(c));
            let deadline = if replaced {
                // Only this socket's own traffic counts: the shared UDP clock
                // is bumped through the live session's handle, not this one.
                now + replaced_idle.saturating_sub(tcp_idle)
            } else {
                // Logged in: rely on the socket for liveness. Use the loose
                // backstop, refreshed by the more recent of TCP / UDP activity,
                // so a NAT-T LowID source that only speaks UDP — or a plain
                // client that is simply quiet — is NOT evicted while its TCP
                // link is alive.
                let udp_idle = std::time::Duration::from_millis(c.idle_ms());
                now + logged_in_backstop.saturating_sub(tcp_idle.min(udp_idle))
            };
            let wake = deadline.min(now + replaced_recheck);
            (deadline, probe_restore.map_or(wake, |t| wake.min(t)))
        } else {
            // Not logged in: tight timeout guards against half-open / scanner
            // sockets that complete the crypto handshake but never LOGINREQUEST.
            (login_deadline, login_deadline)
        };

        tokio::select! {
            _ = tokio::time::sleep_until(wake) => {
                if probe_restore.is_some_and(|t| tokio::time::Instant::now() >= t) {
                    // The probe got its ACK in time: back to the usual limit.
                    probe_restore = None;
                    let _ = socket2::SockRef::from(framed.get_ref().tcp())
                        .set_tcp_user_timeout(Some(SESSION_TCP_USER_TIMEOUT));
                    continue;
                }
                if tokio::time::Instant::now() < deadline {
                    // A re-check tick, not a timeout.
                    continue;
                }
                if client.is_none() {
                    debug!(ip = %peer.ip(),
                           "login timeout — no LOGINREQUEST received, dropping");
                } else if replaced {
                    debug!(ip = %peer.ip(), idle_s = replaced_idle.as_secs(),
                           "replaced session silent — closing its socket");
                    state
                        .replaced_sessions_closed
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                        // A replaced session holds no authority (issue #46):
                        // the user's state belongs to the new login, and a
                        // frame from here would publish, search or relay
                        // under an identity this socket no longer owns. Its
                        // first frame closes it, so a client still using it
                        // notices and logs in again; a silent one goes after
                        // `replaced_idle`, as before.
                        //
                        // Not for a shared hash (DLP's list, mldonkey's, the
                        // operator's): it identifies no one, its sessions
                        // are different installs, and closing the displaced
                        // one only sent it straight back to displace the
                        // other. Live, fencing them turned 1.2k shared-hash
                        // takeovers in ten hours into 11k in eight.
                        if let Some(c) = client.as_ref() {
                            let current = state
                                .clients
                                .get(&c.user_hash)
                                .is_some_and(|e| e.same_session(c));
                            if !current && !is_shared_hash(&state, &c.user_hash) {
                                debug!(ip = %peer.ip(),
                                       opcode = format_args!("0x{:02X}", frame.opcode),
                                       "frame on a replaced session — closing it");
                                *state
                                    .block_stats
                                    .entry("replaced_session_frame_refused".to_string())
                                    .or_insert(0) += 1;
                                break;
                            }
                        }
                        // Boxed: the dispatch future (login, search, offer
                        // handling and every await inside them) is several KB.
                        // Inline it was part of this connection's state for the
                        // whole session — one copy per connected client, kept
                        // between frames when nothing runs. Boxed it exists
                        // only while a frame is being handled.
                        let res = Box::pin(dispatch(
                            &cfg, &state, &state, &mut client, &mut framed, &mut rx,
                            &mut pending_search, &mut sess, peer, frame
                        )).await;
                        // Logged in: no longer a pending login.
                        if client.is_some() {
                            pending_login.take();
                        }
                        if let Err(e) = res {
                            // Throttled: a banned publisher's client retries every
                            // ~30 s forever, and each retry lands here.
                            // A refused login has already been logged where it was
                            // decided; logging it again here as a "handler error"
                            // only doubled every refusal in the health tab.
                            if e.downcast_ref::<SessionRefused>().is_some() {
                                break;
                            }
                            if let Some(sup) = crate::health::throttle().allow(
                                peer.ip(), "handler_error", crate::health::SUPPRESS_WINDOW)
                            {
                                warn!(ip = %peer.ip(), error = %e, suppressed = sup,
                                      "handler error");
                            }
                            break;
                        }
                        reclaim_framed_buffers(&mut framed);
                        account_framed_buffers(&state, &framed, &mut accounted_bufs);
                    }
                    Some(Err(e)) => {
                        // Throttled: a peer with a broken path produces a timeout
                        // every ~20 s indefinitely.
                        if let Some(sup) = crate::health::throttle().allow(
                            peer.ip(), "frame_error", crate::health::SUPPRESS_WINDOW)
                        {
                            warn!(ip = %peer.ip(), error = %e, suppressed = sup,
                                  "frame error - dropping");
                        }
                        break;
                    }
                    None => {
                        debug!(ip = %peer.ip(), "client closed connection");
                        break;
                    }
                }
            }
            changed = ipf_gen.changed(), if ipf_open => {
                if changed.is_err() {
                    ipf_open = false;
                    continue;
                }
                if state.ip_filter_blocks(peer.ip()).await {
                    let nick = client.as_ref().map(|c| c.nick.as_str()).unwrap_or("");
                    info!(ip = %peer.ip(), nick = %nick,
                          "address is now in the IP filter — closing its connection");
                    *state.block_stats.entry("ipfilter_kick".to_string()).or_insert(0) += 1;
                    break;
                }
                if state.is_bot_banned(peer.ip()) {
                    let nick = client.as_ref().map(|c| c.nick.as_str()).unwrap_or("");
                    info!(ip = %peer.ip(), nick = %nick,
                          "address banned as a bot — closing its connection");
                    *state.block_stats.entry("bot_kick".to_string()).or_insert(0) += 1;
                    break;
                }
            }
            Some(mut frame) = rx.recv() => {
                if frame.opcode == INTERNAL_PROBE {
                    // Issue #41: data unacknowledged for PROBE_USER_TIMEOUT
                    // now aborts the connection — the read below then ends
                    // the session, and the login waiting on it goes ahead.
                    let _ = socket2::SockRef::from(framed.get_ref().tcp())
                        .set_tcp_user_timeout(Some(PROBE_USER_TIMEOUT));
                    probe_restore = Some(tokio::time::Instant::now() + TAKEOVER_PROBE_WAIT);
                    frame = Frame::new(OP_SERVERSTATUS, std::mem::take(&mut frame.payload));
                }
                if let Err(e) = framed.send(frame).await {
                    debug!(ip = %peer.ip(), error = %e, "send error on pushed frame");
                    break;
                }
                reclaim_framed_buffers(&mut framed);
                account_framed_buffers(&state, &framed, &mut accounted_bufs);
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
            // Strictly greater, matching the ban condition in
            // `record_csam_file_for_user`. The two MUST use the same comparison:
            // when disconnect fired at `>=` while the ban needed `>`, a publisher
            // with exactly `threshold` blocked files was dropped without being
            // banned and reconnected in seconds, looping indefinitely.
            if c.csam_attempts > live.content_filter.publisher_attempt_disconnect_threshold {
                warn!(ip = %peer.ip(), csam_attempts = c.csam_attempts, "csam threshold — disconnecting");
                break;
            }
        }
    }

    // This connection's buffers are about to be dropped — take them off the gauge.
    // Runs on every exit path: the loop above only leaves via `break`.
    if accounted_bufs.0 != 0 {
        state
            .framed_buffer_bytes
            .fetch_sub(accounted_bufs.0, std::sync::atomic::Ordering::Relaxed);
    }
    if accounted_bufs.1 != 0 {
        state
            .crypt_buffer_bytes
            .fetch_sub(accounted_bufs.1, std::sync::atomic::Ordering::Relaxed);
    }

    if let Some(c) = client {
        info!(ip = %peer.ip(), nick = %c.nick, id = c.assigned_id, "client disconnected");
        c.release_slot();
        end_session(&state, &c);
    }

    Ok(())
}

/// Undo what a login registered, for a session that has ended — unless a newer
/// session of the same user has replaced it.
pub(crate) fn end_session(state: &ServerState, c: &ClientHandle) {
    // Only remove from clients if the entry still belongs to OUR session.
    // If a NEW login from the same user_hash already replaced us (NAT-drop
    // scenario), we must NOT touch the map nor the LowID counter — the new
    // session is responsible for both. Without this guard, an old stale task
    // would erroneously evict the live client and decrement the counter
    // again, causing user dropouts and LowID-count drift.
    //
    // "Ours" is decided by session identity, not by assigned_id (issue
    // #23): a HighID's id is its IPv4, so a reconnect from the same
    // address has the same id, and comparing ids let this old task remove
    // the live session's entry, id index, IPv6 entry and every source it
    // had just re-published.
    // Remove the entry only if it is this session — one atomic step, so a
    // login landing between a check and a remove cannot be evicted.
    let removed = state
        .clients
        .remove_if(&c.user_hash, |_, entry| entry.same_session(c))
        .is_some();
    if removed {
        if !c.is_high_id {
            state
                .lowid_count_cached
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
        // Drop the IPv6 side entry with the session. Leaving it would let a
        // departed client's address keep being published as a source, which
        // is the same defect the stale-IPv4 filter exists for — except a
        // stale entry here survives indefinitely because nothing else
        // references it.
        state.client_ipv6.remove(&c.user_hash);
        state.ipv6_probe.remove(&c.user_hash);
        // Its keepalive port goes too: a reconnect from another address
        // must not be handed out with the old mapping (issue #37).
        state.natt_udp_ports.remove(&c.user_hash);
        state.natt_keepalive_seen.remove(&c.user_hash);
        state.natt_token.remove(&c.user_hash);
        state.natt_proof_counter.remove(&c.user_hash);
        state.natt_udp_ip.remove(&c.user_hash);
        // Retract the id→user mapping. Guarded inside by user hash.
        state.unindex_client_id(c.assigned_id, &c.user_hash);
        state.remove_sources_of(&c.user_hash);
    } else {
        // Replaced, or already gone. If the live session holds a different
        // id (it is LowID now, or came from a new address), our old id may
        // still map to this user in the id index: retract that mapping
        // and nothing else. If it holds the same id (a HighID reconnect
        // from the same address), everything belongs to it.
        let live_id = state.clients.get(&c.user_hash).map(|e| e.assigned_id);
        if live_id.is_some_and(|id| id != c.assigned_id) {
            state.unindex_client_id(c.assigned_id, &c.user_hash);
        }
    }
}

/// Starting (and target) size of each codec buffer.
const FRESH_BUF: usize = 2 * 1024;
/// Hand a buffer back once it has grown past this and is drained.
const BUF_HIGH_WATER: usize = 8 * 1024;

/// Give back an oversized-but-empty codec buffer.
///
/// `Framed` grows its read/write buffers to fit the largest frame it ever sees (a
/// big OFFERFILES publish, a large search page) and then NEVER shrinks them, so the
/// capacity sticks for the whole session. Measured live, per-connection heap that
/// /api/memsize could not see tracked the client count at ~33 KiB each — at 54k
/// users that projects to ~1.7 GB, comparable to the entire file index.
///
/// The `is_empty()` guard is what makes this safe: `Framed` keeps partially-received
/// bytes in the read buffer and not-yet-flushed bytes in the write buffer, so
/// replacing a NON-empty buffer would corrupt the stream. When it is drained there
/// is nothing to preserve.
fn reclaim_framed_buffers(framed: &mut Framed<CryptStream, Ed2kCodec>) {
    if framed.read_buffer().is_empty() && framed.read_buffer().capacity() > BUF_HIGH_WATER {
        *framed.read_buffer_mut() = BytesMut::with_capacity(FRESH_BUF);
    }
    if framed.write_buffer().is_empty() && framed.write_buffer().capacity() > BUF_HIGH_WATER {
        *framed.write_buffer_mut() = BytesMut::with_capacity(FRESH_BUF);
    }
}

/// Keep the global Framed-buffer gauge in step with this connection's real capacity.
fn account_framed_buffers(
    state: &Arc<ServerState>,
    framed: &Framed<CryptStream, Ed2kCodec>,
    accounted: &mut (i64, i64),
) {
    use std::sync::atomic::Ordering::Relaxed;
    let codec = (framed.read_buffer().capacity() + framed.write_buffer().capacity()) as i64;
    if codec != accounted.0 {
        state.framed_buffer_bytes.fetch_add(codec - accounted.0, Relaxed);
        accounted.0 = codec;
    }
    let crypt = framed.get_ref().heap_bytes() as i64;
    if crypt != accounted.1 {
        state.crypt_buffer_bytes.fetch_add(crypt - accounted.1, Relaxed);
        accounted.1 = crypt;
    }
}

/// Await `fut` while still delivering frames other tasks push at this client
/// (OFFERFILES v1 waits, issue #19). A closed channel is simply no longer
/// polled; a failed send ends the session as it would anywhere else.
async fn serve_pushes_while<F: std::future::Future>(
    fut: F,
    rx: &mut mpsc::Receiver<Frame>,
    framed: &mut Framed<CryptStream, Ed2kCodec>,
) -> Result<F::Output> {
    tokio::pin!(fut);
    let mut open = true;
    loop {
        tokio::select! {
            out = &mut fut => return Ok(out),
            pushed = rx.recv(), if open => match pushed {
                Some(f) => framed.send(f).await?,
                None => open = false,
            },
        }
    }
}

async fn dispatch(
    cfg: &Config,
    state: &ServerState,
    state_arc: &Arc<ServerState>, // same state, owned handle for detached tasks
    client: &mut Option<ClientHandle>,
    framed: &mut Framed<CryptStream, Ed2kCodec>,
    rx: &mut mpsc::Receiver<Frame>,
    pending_search: &mut Vec<crate::state::file_id::FileRecord>,
    sess: &mut SessionAdmission,
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
                // Read straight from live_cfg: this is a different function from
                // handle_connection, and the temporary guard is dropped at the end
                // of the statement (never held across an .await), so a hot reload
                // takes effect on the next login attempt.
                let ttl = std::time::Duration::from_secs(
                    state
                        .live_cfg
                        .load()
                        .content_filter
                        .publisher_blacklist_seconds,
                );
                // NB: the BAN length, deliberately — not the counting window.
                if state.is_publisher_banned(&req.user_hash, ttl) {
                    // Throttled: the ban lasts 30 days by default while the client
                    // keeps auto-reconnecting on a ~30 s timer, so this single peer
                    // would otherwise write ~5700 warnings a day.
                    if let Some(sup) = crate::health::throttle().allow(
                        peer.ip(),
                        "login_banned",
                        crate::health::SUPPRESS_WINDOW,
                    ) {
                        warn!(ip = %peer.ip(), user_hash = hex::encode(req.user_hash),
                              suppressed = sup, "login refused — CSAM publisher is banned");
                    }
                    return Err(SessionRefused("banned CSAM publisher").into());
                }
            }
            // Issue #41: the hash is online from elsewhere. Checked before the
            // slot and the HighID probe, and again just before the insert.
            let online = state.clients.get(&req.user_hash).map(|c| c.clone());
            if let Some(prev) = online {
                if prev.is_alive() && is_shared_hash(state, &prev.user_hash) {
                    crate::server::holepunch::count(state, "login_takeover_shared_hash");
                } else if prev.is_alive() && may_replace_session(state, &prev, peer.ip(), req.port) {
                    // A live session taken over from its own address (a NAT
                    // reconnect, or two installs behind one NAT): set beside
                    // `replaced_session_frame_refused`, it shows whether the
                    // fence of #46 makes such pairs take turns.
                    crate::server::holepunch::count(state, "login_takeover_same_address");
                }
                if !may_replace_session(state, &prev, peer.ip(), req.port) {
                    // A contender this hash's owner already outlasted: two
                    // installs sharing one user hash retry every few seconds,
                    // and probing the owner for each would keep its socket
                    // on a 10 s fuse. Refused without a probe for a while.
                    let key = (req.user_hash, state.source_key(peer.ip()));
                    let known = state
                        .takeover_lost
                        .get(&key)
                        .is_some_and(|e| e.0.elapsed() < TAKEOVER_CONTENDER_MEMORY);
                    let gone = !known && old_session_gone(state, &prev).await;
                    if !gone {
                        if known {
                            crate::server::holepunch::count(state, "login_hash_in_use_known_contender");
                        }
                        let mut e = state
                            .takeover_lost
                            .entry(key)
                            .or_insert((std::time::Instant::now(), 0));
                        if !known {
                            e.0 = std::time::Instant::now();
                        }
                        e.1 = e.1.saturating_add(1);
                        drop(e);
                        return Err(refuse_hash_in_use(framed, state, peer, &req.user_hash).await);
                    }
                }
            }
            // limits.max_clients (live; 0 = no cap). Reserved before
            // handle_login, which runs the HighID probe — a full server should
            // not spend a connection on a client it is about to turn away. A
            // client whose user hash is already connected is replacing its own
            // stale session, not adding one, and is always let in.
            let max_clients = state.live_cfg.load().limits.max_clients;
            let Some(slot) = reserve_client_slot(state, &req.user_hash, max_clients) else {
                *state
                    .block_stats
                    .entry("server_full".to_string())
                    .or_insert(0) += 1;
                let text = b"Server full, please try again later";
                let mut payload = Vec::with_capacity(2 + text.len());
                payload.extend_from_slice(&(text.len() as u16).to_le_bytes());
                payload.extend_from_slice(text);
                let _ = framed.send(Frame::new(OP_SERVERMESSAGE, payload)).await;
                if let Some(sup) = crate::health::throttle().allow(
                    peer.ip(),
                    "server_full",
                    crate::health::SUPPRESS_WINDOW,
                ) {
                    info!(ip = %peer.ip(), max_clients, suppressed = sup,
                          "login refused — server full");
                }
                return Err(SessionRefused("server full").into());
            };
            // OFFERFILES v1 only for a client that asked for it (issue #19).
            let wants_v1 = crate::server::offer_pacing::client_requests_v1(&req.tags);
            let listen_port = req.port;
            let mut new_client = handle_login(cfg, state, peer.ip(), req).await;
            // The HighID probe took time: another login with this hash may
            // have come in meanwhile. From here to the insert nothing waits.
            let online = state.clients.get(&new_client.user_hash).map(|c| c.clone());
            if let Some(prev) = online {
                if !may_replace_session(state, &prev, peer.ip(), listen_port) {
                    return Err(refuse_hash_in_use(framed, state, peer, &new_client.user_hash).await);
                }
            }
            // OFFERFILES v1 snapshot (issue #19): taken once, here, and both
            // advertised from and enforced from for the life of the connection.
            //
            // A client that did not ask is a legacy client whatever the
            // configuration says: no advertisement, no pacing, no batch limit.
            new_client.offer_policy = if wants_v1 {
                state
                    .offer_v1
                    .requested
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                crate::server::offer_pacing::policy_for_login(&state.live_cfg.load().limits)
            } else {
                None
            };
            sess.offer_bucket = new_client.offer_policy.map(|p| p.bucket());
            if new_client.offer_policy.is_some() {
                state
                    .offer_v1
                    .sessions
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            *new_client.slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(slot);
            *rx = ServerState::create_client_channel(&mut new_client);
            // Detect duplicate user_hash login — happens when a NAT-dropped
            // connection's old task hasn't timed out yet, but the same user
            // reconnects. DashMap::insert silently replaces; without this
            // adjustment our LowID counter would double-count until the old
            // task eventually times out and decrements. eMule then reports
            // a LowID count > total connected clients.
            state.index_client_id(new_client.assigned_id, new_client.user_hash);
            // Side table of publisher IPv6 addresses. Written here, next to the
            // client map, so the two cannot get out of step: a client with no
            // usable v6 must have NO entry rather than a stale one from a
            // previous session at a different address.
            // With the dial-back on (#43) the address waits for its probe,
            // which starts after the welcome batch.
            let probe_v6 = new_client.ipv6.filter(|_| crate::server::ipv6_probe::active(state));
            match (new_client.ipv6, probe_v6) {
                (Some(a), Some(_)) => {
                    state.ipv6_probe.remove(&new_client.user_hash);
                    let _ = crate::server::ipv6_probe::mark_pending(state, new_client.user_hash, a);
                }
                (Some(a), None) => {
                    state.client_ipv6.insert(new_client.user_hash, a);
                    state.ipv6_probe.remove(&new_client.user_hash);
                }
                (None, _) => {
                    state.client_ipv6.remove(&new_client.user_hash);
                    state.ipv6_probe.remove(&new_client.user_hash);
                }
            }
            // A new session proves its 0x9F handling afresh (issue #39).
            state.natt_keepalive_seen.remove(&new_client.user_hash);
            state.natt_udp_ip.remove(&new_client.user_hash);
            // And gets a fresh token for its 0x9F (issue #40), if it does
            // NAT-T; proof counters start again with it.
            state.natt_proof_counter.remove(&new_client.user_hash);
            if crate::server::holepunch::wants_natt_token(&new_client) {
                let mut t = [0u8; 16];
                t.copy_from_slice(&crate::proto::obfuscation::random_bytes(16));
                state.natt_token.insert(new_client.user_hash, t);
            } else {
                state.natt_token.remove(&new_client.user_hash);
            }
            let prev = state
                .clients
                .insert(new_client.user_hash, new_client.clone());
            // The replaced session (a NAT-dropped connection whose task has not
            // noticed yet) gives its logged-in slot back now: one user, one
            // slot, or routine reconnects would fill max_clients with dead
            // sessions until their sockets time out.
            if let Some(old) = &prev {
                old.release_slot();
            }
            // Maintain cached lowid count so handle_servstat doesn't do an O(N)
            // iter on every UDP probe (was 2.58% of CPU in v0.9.36 profile).
            if let Some(old) = &prev {
                if !old.is_high_id {
                    state
                        .lowid_count_cached
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            if !new_client.is_high_id {
                state
                    .lowid_count_cached
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            // Track this IP as a recently-seen client for 30 minutes.
            // merge_server_list (gossip) uses this to prevent mldonkey client IPs
            // from entering our peer-server list even after they disconnect.
            if let std::net::IpAddr::V4(client_v4) = new_client.ip {
                state
                    .recent_client_ips
                    .insert(client_v4, std::time::Instant::now());
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
            let ident = wants_v1 || crate::server::login::ident_at_login(&new_client);
            sess.ident_sent = ident;
            for f in crate::server::login::build_welcome_batch_with(cfg, state, &new_client, ident, peer.port()) {
                framed.send(f).await?;
            }
            if let Some(a) = probe_v6 {
                crate::server::ipv6_probe::start(
                    state_arc,
                    new_client.user_hash,
                    a,
                    new_client.port,
                    new_client.server_flags,
                );
            }
        }

        OP_OFFERFILES => {
            let Some(c) = client else {
                return Err(anyhow::anyhow!("OFFERFILES before login"));
            };
            // OFFERFILES v1 snapshot (issue #19), or None for a legacy session.
            let policy = c.offer_policy;
            // limits.hard_limit_files: a per-packet bound, checked on the
            // declared count before any record is read (Lugdunum semantics).
            // A v1 session is held to the value it was told at login; a legacy
            // one reads it live, as before.
            let hard = match policy {
                Some(p) => p.hard,
                None => state.live_cfg.load().limits.hard_limit_files,
            };
            let declared = declared_count(&frame.payload);
            if let Some(declared) = declared {
                if over_hard_limit(declared, hard) {
                    state.note_offer_over_hard_limit();
                    if let Some(sup) = crate::health::throttle().allow(
                        peer.ip(),
                        "offer_hard_limit",
                        crate::health::SUPPRESS_WINDOW,
                    ) {
                        info!(ip = %peer.ip(), nick = %c.nick, declared, hard_limit = hard,
                              suppressed = sup,
                              "OFFERFILES over the hard limit — packet rejected, connection closed");
                    }
                    return Err(SessionRefused("OFFERFILES over hard limit").into());
                }
            }
            if let (Some(p), Some(bucket)) = (policy, sess.offer_bucket.as_mut()) {
                use std::sync::atomic::Ordering::Relaxed;
                let n = declared.unwrap_or(0);
                // Above the negotiated batch size but below the hard boundary:
                // not indexed, counted, and the session stays up — a client
                // with a wrong idea of the contract should notice "no effect",
                // not be pushed into a reconnect loop. Not charged to the
                // bucket either, since nothing was processed.
                if n > p.batch_max {
                    state.offer_v1.oversized.fetch_add(1, Relaxed);
                    if let Some(sup) = crate::health::throttle().allow(
                        peer.ip(),
                        "offer_v1_oversized",
                        crate::health::SUPPRESS_WINDOW,
                    ) {
                        info!(ip = %peer.ip(), nick = %c.nick, declared = n,
                              batch_max = p.batch_max, suppressed = sup,
                              "OFFERFILES above offerfiles_batch_max — batch not indexed, session kept");
                    }
                    return Ok(());
                }
                if n > 0 {
                    // Early batches wait; nothing compliant is dropped. While
                    // this connection waits it reads nothing more, so the
                    // client is held back by TCP, not by a queue here.
                    //
                    // Frames other tasks push at this client (callbacks,
                    // hole-punch, keepalive) keep flowing while it waits: the
                    // push channel is small and try_send drops on full, so a
                    // long wait without draining it would lose them.
                    let wait = bucket.reserve(n, tokio::time::Instant::now());
                    if !wait.is_zero() {
                        serve_pushes_while(tokio::time::sleep(wait), rx, framed).await?;
                    }
                    state.offer_v1.note_conn_wait(wait);
                    let ceiling = state
                        .live_cfg
                        .load()
                        .limits
                        .offerfiles_global_records_per_sec;
                    let waited = serve_pushes_while(
                        state.offer_v1_pacer.acquire(n, ceiling),
                        rx,
                        framed,
                    )
                    .await?;
                    state.offer_v1.note_global_wait(waited);
                    // A newer login of the same user may have replaced this
                    // session while it waited. Its batch must not be indexed
                    // under this session's id: the replaced session's cleanup
                    // does not remove sources, so they would outlive it.
                    let current = state
                        .clients
                        .get(&c.user_hash)
                        .is_some_and(|e| e.same_session(c));
                    if !current {
                        return Ok(());
                    }
                    state.offer_v1.batches.fetch_add(1, Relaxed);
                    state.offer_v1.records.fetch_add(n as u64, Relaxed);
                }
            }
            let files = parse_offerfiles(&frame.payload)?;
            let warned_before = c.soft_limit_warned;
            // A batch is a content-filter check per record, up to hundreds of
            // records — at the default single runtime thread, all networking
            // stopped while one ran, and a reconnect storm after a restart is
            // tens of thousands of them back to back. A large batch goes to
            // the blocking pool when one of OFFER_JOBS slots is free; this
            // connection waits for its own result (a session's records stay in
            // order) while every other one keeps being served.
            //
            // With no slot free it runs inline, as it always did. It must not
            // WAIT for a slot: every waiting connection would hold its parsed
            // batch, and in a reconnect storm that is tens of thousands of
            // batches in memory at once. Inline, the runtime is busy and other
            // connections are not reading theirs — the same bound as before.
            // Small batches (the incremental offers of a running eMule) are
            // cheaper inline anyway.
            let permit = if files.len() > OFFER_INLINE_MAX {
                Arc::clone(&state.offer_lane).try_acquire_owned().ok()
            } else {
                None
            };
            if let Some(permit) = permit {
                let st = Arc::clone(state_arc);
                let mut handle = c.clone();
                let handle = tokio::task::spawn_blocking(move || {
                    handle_offerfiles(&st, &mut handle, files);
                    drop(permit);
                    handle
                })
                .await
                .map_err(|e| anyhow::anyhow!("offerfiles job failed: {e}"))?;
                // The only fields the handler changes on the session.
                c.csam_attempts = handle.csam_attempts;
                c.soft_limit_warned = handle.soft_limit_warned;
            } else {
                handle_offerfiles(state, c, files);
            }
            if c.soft_limit_warned && !warned_before {
                let soft = match policy {
                    Some(p) => p.soft,
                    None => state.live_cfg.load().limits.soft_limit_files,
                };
                let text = soft_limit_message(soft);
                let mut payload = Vec::with_capacity(2 + text.len());
                payload.extend_from_slice(&(text.len() as u16).to_le_bytes());
                payload.extend_from_slice(text.as_bytes());
                framed.send(Frame::new(OP_SERVERMESSAGE, payload)).await?;
            }
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
                    use crate::server::search::{build_search_result_page, search_page_size};
                    // Run the search off the runtime, in a bounded lane
                    // (admission.max_search_jobs / max_queued_tcp_searches,
                    // issue #25). No job within tcp_search_wait_ms → an empty
                    // result, as for a query that matched nothing.
                    let all = match state.admission.tcp_search_permit().await {
                        Some(permit) => {
                            let st = Arc::clone(state_arc);
                            crate::admission::run_search(permit, move || handle_search(&st, req))
                                .await
                                .unwrap_or_default()
                        }
                        None => Vec::new(),
                    };
                    let mut all = all;
                    state.note_activity(peer.ip(), crate::server::activity::Kind::TcpSearch, &[], true);
                    state.note_activity_results(peer.ip(), all.len());
                    // Keep the full result set in this connection's pending
                    // buffer.
                    let first_len = all.len().min(search_page_size(state));
                    let first_page: Vec<_> = all.drain(..first_len).collect();
                    let has_more = !all.is_empty();
                    *pending_search = all; // remainder for QUERY_MORE_RESULT
                    framed
                        .send(build_search_result_page(state, &first_page, has_more))
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
            if let Ok(mut req) = GetSourcesRequest::parse(&frame.payload) {
                req.obfu = frame.opcode == OP_GETSOURCES_OBFU;
                state.note_activity(
                    peer.ip(),
                    crate::server::activity::Kind::TcpSources,
                    &[req.file_hash],
                    true,
                );
                crate::server::bot_detector::record_sources(state_arc, peer.ip(), &[req.file_hash], true);
                // A throttled source (the hammer rule) gets `bots.throttle_qpm`
                // answers a minute; the rest go unanswered, as over UDP.
                if state.bot_throttle_admit(peer.ip()) == Some(false) {
                    crate::server::bot_detector::note_banned(state_arc, peer.ip(), &[]);
                    return Ok(());
                }
                framed.send(handle_get_sources(state, c, req)).await?;
            }
        }

        OP_CALLBACKREQUEST => {
            let Some(c) = client.as_ref() else {
                return Err(anyhow::anyhow!("CALLBACKREQUEST before login"));
            };
            if frame.payload.len() >= 4 {
                let target_id = u32::from_le_bytes([
                    frame.payload[0],
                    frame.payload[1],
                    frame.payload[2],
                    frame.payload[3],
                ]);
                // admission.session_relay_* (issue #25): each callback makes
                // the server push a frame to another client. Over the session's
                // allowance the requester gets the protocol's own failure reply.
                if !sess.relay.allow() {
                    state.admission.note_relay_rejected();
                    framed.send(Frame::new(OP_CALLBACK_FAIL, vec![])).await?;
                    return Ok(());
                }
                handle_callback_request(state, c, target_id, framed).await?;
            }
        }

        OP_IPV6_UPDATE => {
            // Issue #34: the client's IPv6 changed, or it no longer has one.
            let Some(c) = client.as_mut() else {
                return Err(anyhow::anyhow!("IPV6_UPDATE before login"));
            };
            let session_v6 =
                matches!(peer.ip(), std::net::IpAddr::V6(a) if a.to_ipv4_mapped().is_none());
            let outcome = crate::server::login::apply_ipv6_update(c, &frame.payload, session_v6);
            use crate::server::login::Ipv6Update::*;
            if matches!(outcome, Published(_) | Unusable | Withdrawn) {
                // Side table first, then the client map, as at login: the
                // source encoder reads the table by user hash.
                let mut probe = c.ipv6.filter(|_| crate::server::ipv6_probe::active(state));
                match (c.ipv6, probe) {
                    // A new address is dialled back like the login one (#43).
                    (Some(a), Some(_)) => {
                        if !crate::server::ipv6_probe::mark_pending(state, c.user_hash, a) {
                            // Same address: its verdict stands, no new dial.
                            probe = None;
                        }
                    }
                    (Some(a), None) => {
                        state.client_ipv6.insert(c.user_hash, a);
                    }
                    (None, _) => {
                        state.client_ipv6.remove(&c.user_hash);
                        // Not a remove: the dial count lasts the session (#53).
                        crate::server::ipv6_probe::withdraw(state, c.user_hash);
                    }
                }
                if let Some(mut h) = state.clients.get_mut(&c.user_hash) {
                    h.ipv6 = c.ipv6;
                    h.ipv6_capable = c.ipv6_capable;
                }
                if let Some(a) = probe {
                    crate::server::ipv6_probe::start(state_arc, c.user_hash, a, c.port, c.server_flags);
                }
            }
            debug!(ip = %peer.ip(), ?outcome, "IPv6 update");
        }

        OP_LOWID_HOLEPUNCH_REQUEST => {
            let Some(c) = client.as_ref() else {
                return Err(anyhow::anyhow!("HOLEPUNCH_REQUEST before login"));
            };
            // payload: target_id(4) + requester_udp_port(2)
            if frame.payload.len() >= 6 {
                let target_id = u32::from_le_bytes([
                    frame.payload[0],
                    frame.payload[1],
                    frame.payload[2],
                    frame.payload[3],
                ]);
                let requester_udp_port = u16::from_le_bytes([frame.payload[4], frame.payload[5]]);
                // Same per-session allowance as callbacks. Over it the request
                // is ignored: the client's own timeout handles it.
                if !sess.relay.allow() {
                    state.admission.note_relay_rejected();
                    return Ok(());
                }
                // Today's punch, or the extension when both peers use it,
                // with the resends and the bridge (issue #39).
                crate::server::holepunch::request(
                    state_arc,
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
            // Then SERVERIDENT, as Lugdunum answers 0x14: list first, ident
            // after. This is where most clients get our name and description
            // over TCP; see `ident_at_login` for why not at login.
            if let Some(c) = client.as_ref().filter(|_| !sess.ident_sent) {
                framed
                    .send(crate::server::login::build_server_ident(cfg, state, c))
                    .await?;
                sess.ident_sent = true;
            }
        }

        OP_DISCONNECT => {
            return Err(anyhow::anyhow!("client disconnect"));
        }

        OP_QUERY_MORE_RESULT => {
            // Client wants the next page of the last search. Drain another
            // page from this connection's pending buffer.
            use crate::server::search::{build_search_result_page, search_page_size};
            state.note_activity(peer.ip(), crate::server::activity::Kind::TcpMore, &[], true);
            if pending_search.is_empty() {
                // Nothing buffered — reply with an empty, "no more" result
                // so the client's More button settles.
                let mut p = BytesMut::new();
                p.put_u32_le(0u32);
                p.put_u8(0u8);
                framed.send(Frame::new(OP_SEARCHRESULT, p.to_vec())).await?;
            } else {
                let n = pending_search.len().min(search_page_size(state));
                let page: Vec<_> = pending_search.drain(..n).collect();
                let has_more = !pending_search.is_empty();
                debug!(ip = %peer.ip(), page = page.len(), has_more,
                       "QUERY_MORE_RESULT — sending next page");
                framed
                    .send(build_search_result_page(state, &page, has_more))
                    .await?;
            }
        }

        other => {
            debug!(ip = %peer.ip(), opcode = format!("0x{:02x}", other), "unknown opcode");
        }
    }

    Ok(())
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn state_with(n_clients: u8) -> Arc<ServerState> {
        let st = Arc::new(ServerState::new(
            Arc::new(crate::filter::ContentFilter::new()),
            Arc::new(Config::minimal_test_config()),
        ));
        for i in 0..n_clients {
            st.register_synthetic_client(
                [i + 1; 16],
                100 + i as u32,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, i + 1)),
                "t".into(),
                "??".into(),
                "test".into(),
                0,
            );
        }
        st
    }

    /// Logged-in sessions: their slots, as connection tasks hold them.
    fn hold(st: &ServerState, n: usize) -> Vec<crate::admission::ClientSlot> {
        (0..n)
            .map(|_| st.admission.clients.try_reserve(0).unwrap())
            .collect()
    }

    #[test]
    fn a_new_client_is_admitted_below_max_clients_and_refused_at_it() {
        let st = state_with(3);
        let _held = hold(&st, 3);
        assert!(reserve_client_slot(&st, &[0xEE; 16], 4).is_some());
        assert!(reserve_client_slot(&st, &[0xEE; 16], 3).is_none());
        assert!(reserve_client_slot(&st, &[0xEE; 16], 2).is_none());
    }

    #[test]
    fn a_client_replacing_its_own_session_is_always_admitted() {
        let st = state_with(3);
        let _held = hold(&st, 3);
        // [1;16] is connected: its reconnect is let in even when full.
        assert!(reserve_client_slot(&st, &[1; 16], 3).is_some());
        assert!(reserve_client_slot(&st, &[1; 16], 1).is_some());
    }

    #[test]
    fn zero_max_clients_means_no_cap() {
        let st = state_with(3);
        let _held = hold(&st, 3);
        assert!(reserve_client_slot(&st, &[0xEE; 16], 0).is_some());
    }

    #[test]
    fn a_slot_returns_when_the_session_ends() {
        let st = state_with(0);
        let s1 = reserve_client_slot(&st, &[0xEE; 16], 1).unwrap();
        assert!(reserve_client_slot(&st, &[0xEF; 16], 1).is_none());
        drop(s1);
        assert!(reserve_client_slot(&st, &[0xEF; 16], 1).is_some());
    }
}

#[cfg(test)]
mod session_end_tests {
    //! Issue #23: an ended session must not undo a newer session's login.
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    fn state() -> ServerState {
        ServerState::new(
            Arc::new(crate::filter::ContentFilter::new()),
            Arc::new(Config::minimal_test_config()),
        )
    }

    /// What a login registers, as `dispatch` does it: a fresh handle (fresh
    /// session identity), the id index, the client map, and one published file.
    fn login(st: &ServerState, id: u32, ip: [u8; 4], high: bool, file: u8) -> ClientHandle {
        let h = ClientHandle {
            user_hash: [7; 16],
            assigned_id: id,
            ip: IpAddr::V4(Ipv4Addr::from(ip)),
            port: 4662,
            udp_port: 0,
            natt_capable: false,
            nick: "t".into(),
            server_flags: 0,
            ipv6_capable: false,
            ipv6: None,
            is_high_id: high,
            connected_at: Instant::now(),
            country: "??".into(),
            software: "test".into(),
            software_detail: "test".into(),
            login_fp: String::new(),
            csam_attempts: 0,
            soft_limit_warned: false,
            offer_policy: None,
            slot: Default::default(),
            tx: None,
            last_activity_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };
        st.index_client_id(h.assigned_id, h.user_hash);
        st.clients.insert(h.user_hash, h.clone());
        st.add_file_with_source(
            [file; 16],
            1000,
            format!("clip {file}.avi"),
            (h.user_hash, h.ip, h.port, true),
        );
        h
    }

    fn sources(st: &ServerState) -> usize {
        st.user_files.get(&[7; 16]).map_or(0, |s| s.len())
    }

    #[test]
    fn a_session_that_ends_unreplaced_is_cleaned_up() {
        let st = state();
        let s = login(&st, 0x0A00_0001, [1, 0, 0, 10], true, 1);
        end_session(&st, &s);
        assert!(st.clients.get(&[7; 16]).is_none());
        assert!(st.client_id_index.get(&0x0A00_0001).is_none());
        assert_eq!(sources(&st), 0);
    }

    #[test]
    fn a_highid_reconnect_from_the_same_ip_survives_the_old_sessions_end() {
        let st = state();
        let old = login(&st, 0x0A00_0001, [1, 0, 0, 10], true, 1);
        let new = login(&st, 0x0A00_0001, [1, 0, 0, 10], true, 2);
        // The old task times out after the new login.
        end_session(&st, &old);
        let live = st.clients.get(&[7; 16]).expect("live session evicted");
        assert!(live.same_session(&new));
        drop(live);
        assert_eq!(
            st.client_id_index.get(&0x0A00_0001).map(|e| *e),
            Some([7; 16])
        );
        assert_eq!(sources(&st), 2, "sources the client re-published must stay");
        // The new session's own end then cleans up as usual.
        end_session(&st, &new);
        assert!(st.clients.get(&[7; 16]).is_none());
        assert_eq!(sources(&st), 0);
    }

    #[test]
    fn a_replaced_session_with_another_id_retracts_only_its_old_id() {
        let st = state();
        let old = login(&st, 0x0A00_0001, [1, 0, 0, 10], true, 1);
        let new = login(&st, 0x0A00_0002, [2, 0, 0, 10], true, 2);
        end_session(&st, &old);
        assert!(
            st.client_id_index.get(&0x0A00_0001).is_none(),
            "stale id left mapped"
        );
        assert_eq!(
            st.client_id_index.get(&0x0A00_0002).map(|e| *e),
            Some([7; 16])
        );
        assert!(st.clients.get(&[7; 16]).unwrap().same_session(&new));
        assert_eq!(sources(&st), 2);
    }

    #[test]
    fn handles_of_one_login_are_the_same_session_and_two_logins_are_not() {
        let st = state();
        let a = login(&st, 5, [1, 0, 0, 10], true, 1);
        let a_copy = st.clients.get(&[7; 16]).unwrap().clone();
        assert!(a.same_session(&a_copy));
        let b = login(&st, 5, [1, 0, 0, 10], true, 1);
        assert!(!a.same_session(&b), "same id, same IP, different session");
    }
}

#[cfg(test)]
mod task_size_tests {
    /// The connection future lives on the heap for the whole session — one per
    /// client — so its size is per-client memory. Dispatch runs boxed (see the
    /// call site), which keeps its state out of this.
    #[tokio::test]
    async fn the_connection_future_stays_small() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        let _c = tokio::net::TcpStream::connect(a).await.unwrap();
        let (s, peer) = l.accept().await.unwrap();
        let cfg = std::sync::Arc::new(crate::config::Config::minimal_test_config());
        let st = std::sync::Arc::new(crate::state::ServerState::for_test());
        let fut = super::handle_connection(
            cfg,
            st,
            crate::proto::crypt_stream::CryptStream::plain(s),
            peer,
        );
        // 5352 bytes before dispatch was boxed and the RC4 keys moved to the
        // heap; 1264 after.
        let size = std::mem::size_of_val(&fut);
        assert!(size <= 2048, "connection future grew to {size} bytes");
    }
}

/// Issue #41: who may take over a live session of the same user hash.
#[cfg(test)]
mod takeover_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn live(st: &ServerState, ip: IpAddr, v6: Option<Ipv6Addr>) -> (ClientHandle, mpsc::Receiver<Frame>) {
        let rx = st.register_test_client_at([7; 16], 1, false, 0, ip);
        {
            let mut c = st.clients.get_mut(&[7; 16]).unwrap();
            c.ipv6 = v6;
            c.port = 4662;
        }
        (st.clients.get(&[7; 16]).unwrap().clone(), rx)
    }

    fn v4(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, a))
    }

    #[test]
    fn only_the_same_source_takes_a_live_session_over() {
        let st = ServerState::for_test();
        let (prev, _rx) = live(&st, v4(8), None);
        assert!(may_replace_session(&st, &prev, v4(8), 4662), "a reconnect from the same IPv4");
        assert!(may_replace_session(&st, &prev, v4(8), 1234), "the port doesn't matter there");
        let mapped: IpAddr = "::ffff:5.6.7.8".parse().unwrap();
        assert!(may_replace_session(&st, &prev, mapped, 4662), "the same IPv4, v4-mapped");
        assert!(!may_replace_session(&st, &prev, v4(9), 4662), "another address");
    }

    #[test]
    fn ipv6_compares_by_prefix() {
        let st = ServerState::for_test();
        let a: IpAddr = "2001:db8:1:2::10".parse().unwrap();
        let (prev, _rx) = live(&st, a, None);
        let same_64: IpAddr = "2001:db8:1:2::99".parse().unwrap();
        let other_64: IpAddr = "2001:db8:1:3::10".parse().unwrap();
        assert!(may_replace_session(&st, &prev, same_64, 4662));
        assert!(!may_replace_session(&st, &prev, other_64, 4662));
    }

    #[test]
    fn a_dual_stack_move_goes_one_way_only() {
        let st = ServerState::for_test();
        let six: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let (prev, _rx) = live(&st, v4(8), Some(six));
        assert!(may_replace_session(&st, &prev, IpAddr::V6(six), 4662));
        assert!(!may_replace_session(&st, &prev, IpAddr::V6(six), 4663), "another listen port");
        let other: IpAddr = "2001:db8::6".parse().unwrap();
        assert!(!may_replace_session(&st, &prev, other, 4662), "another IPv6");
        // An IPv6 session is not taken over from IPv4, whatever it claims.
        let st = ServerState::for_test();
        let (prev, _rx) = live(&st, IpAddr::V6(six), Some(six));
        assert!(!may_replace_session(&st, &prev, v4(8), 4662));
    }

    #[test]
    fn a_session_that_is_gone_or_the_old_rule_lets_anyone_in() {
        let st = ServerState::for_test();
        let (prev, rx) = live(&st, v4(8), None);
        assert!(!may_replace_session(&st, &prev, v4(9), 4662));
        drop(rx);
        assert!(may_replace_session(&st, &prev, v4(9), 4662), "its connection task has ended");
        let st = ServerState::for_test();
        let (prev, _rx) = live(&st, v4(8), None);
        let mut cfg = (**st.live_cfg.load()).clone();
        cfg.limits.hash_takeover_from_any_address = true;
        st.live_cfg.store(Arc::new(cfg));
        assert!(may_replace_session(&st, &prev, v4(9), 4662));
    }

    /// A shared hash (degenerate, or listed) is nobody's: the newest login
    /// takes it. Contenders from many addresses do not make one shared.
    #[test]
    fn a_shared_hash_falls_back_to_the_old_rule() {
        let st = ServerState::for_test();
        let (prev, _rx) = live(&st, v4(8), None);
        assert!(!may_replace_session(&st, &prev, v4(9), 4662));
        for a in [20u8, 21, 22, 23] {
            st.takeover_lost.insert(([7; 16], v4(a)), (std::time::Instant::now(), 1));
        }
        assert!(!is_shared_hash(&st, &[7; 16]), "an attacker's three proxies prove nothing");
        assert!(!may_replace_session(&st, &prev, v4(9), 4662));
        let mut cfg = (**st.live_cfg.load()).clone();
        cfg.limits.shared_user_hashes.push(hex::encode([7u8; 16]).to_uppercase());
        st.live_cfg.store(Arc::new(cfg));
        assert!(is_shared_hash(&st, &[7; 16]));
        assert!(may_replace_session(&st, &prev, v4(9), 4662));
        // A degenerate hash is shared without a list.
        let mut zero = [0u8; 16];
        zero[5] = 0x0e;
        zero[14] = 0x6f;
        assert!(is_shared_hash(&st, &zero));
        // The default list holds DLP's community hashes.
        let cb: [u8; 16] = hex::decode("cb42f563ee0ea7907395420cac146ff5").unwrap().try_into().unwrap();
        assert!(is_shared_hash(&ServerState::for_test(), &cb));
    }
}
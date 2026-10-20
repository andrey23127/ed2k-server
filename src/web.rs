//! Minimal admin web interface (read-mostly).
//!
//! By default it binds to 127.0.0.1 and has no login: access control is SSH.
//!     ssh -L 8080:127.0.0.1:8080 your-vps
//! Then open http://localhost:8080 in your browser.
//!
//! With `admin.password_hash` set it requires a login for every request, from
//! any address, and may then bind elsewhere (`admin.bind`): a VPN interface,
//! a LAN address, or 0.0.0.0. See [`crate::admin_auth`] for what that does and
//! does not protect. Regardless of login, a state-changing request whose
//! `Origin` is another site is refused, and the server key is shown only to
//! requests from loopback.
//!
//! Endpoints:
//!   GET  /                    HTML dashboard (Status / Stats / Clients tabs)
//!   GET  /api/status          JSON: uptime, file count, client count, seckey hex
//!   GET  /api/stats           JSON: process CPU/RSS, traffic counters, cache hit
//!   GET  /api/clients         JSON: connected clients (ip, nick, files, dur)
//!   GET  /api/peers           JSON: known peer servers + ServerKey learned?
//!   POST /api/reload          trigger SIGHUP-equivalent config + filter reload

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use serde::Serialize;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::config::Config;
use crate::state::ServerState;

// ── Review helpers ───────────────────────────────────────────────────────────
//
// Shared by the alias table and the /api/review export so both apply the same
// thresholds. Kept at module scope (rather than nested in the handler) for that
// reason, and placed here so they do not sit between a handler's doc comment and
// the handler itself.

/// Words of a filename long enough to identify its subject. Short tokens
/// ("the", "2010", "avi") are shared by unrelated files and would hide the
/// signal.
fn name_tokens(name: &str) -> std::collections::HashSet<String> {
    name.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 4)
        .map(|w| w.to_string())
        .collect()
}

/// How many of `names` share NO significant word with the first one.
///
/// This is what separates the two reasons a file carries several names. A
/// release renamed by different users keeps its subject: "American Beauty (Sam
/// Mendes, 1999).mkv" and "American.Beauty.1999.BDrip.mkv" still share
/// "american"/"beauty"/"1999". A decoy does not — one 698 MB file was published
/// as "Magma Tittenshow", "Marc Dorcel 6 Bourgeoises" AND "Joe Cocker -
/// Discography.rar", which have nothing in common.
///
/// Generic over the string type so it serves both the alias table (which holds
/// interned `Arc<str>`) and the review export (plain `String`).
fn unrelated_name_count<S: AsRef<str>>(names: &[S]) -> usize {
    let Some(first) = names.first() else { return 0 };
    let base = name_tokens(first.as_ref());
    names
        .iter()
        .skip(1)
        .filter(|n| name_tokens(n.as_ref()).is_disjoint(&base))
        .count()
}

/// True when a filename's extension cannot plausibly hold a file this large:
/// a 690 MB ".pdf" is a masquerade, no further investigation needed.
///
/// This is the cheapest signal a reviewer has for telling a genuinely
/// mis-blocklisted file apart from known material republished under an innocent
/// name, and doing it by hand is the slowest part of a review. Shared by the
/// alias table and the CSV export so both agree on the threshold.
fn size_contradicts_extension(name: &str, size: u64) -> bool {
    const DOC_LIKE: &[&str] = &[
        ".pdf", ".txt", ".doc", ".docx", ".epub", ".djvu", ".chm", ".mobi", ".jpg", ".jpeg",
        ".png", ".gif",
    ];
    let l = name.to_ascii_lowercase();
    DOC_LIKE.iter().any(|e| l.ends_with(e)) && size > 50 * 1024 * 1024
}

/// Live-collected counters wired into hot paths. Atomic so they can be
/// touched from any task without locks. The web handler just reads them.
#[derive(Default)]
pub struct Metrics {
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub searches_total: AtomicU64,
    pub get_sources_total: AtomicU64,
    pub get_sources_cache_hits: AtomicU64,
    /// Wallclock instant when the server started.
    pub start: once_cell::sync::OnceCell<Instant>,
}

impl Metrics {
    pub fn new() -> Self {
        let m = Self::default();
        let _ = m.start.set(Instant::now());
        m
    }

    pub fn uptime_secs(&self) -> u64 {
        self.start.get().map(|s| s.elapsed().as_secs()).unwrap_or(0)
    }
}

/// Snapshot of `/proc/self/stat` and `/proc/self/status` for CPU/RAM metrics.
/// Linux-only; on other OSes returns zeros. Cheap enough to read per-request.
fn read_proc_stats() -> ProcStats {
    let mut s = ProcStats::default();

    // RSS from /proc/self/status (line: "VmRSS:  <kB> kB")
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                if let Some(n) = rest.split_whitespace().next() {
                    s.rss_kib = n.parse().unwrap_or(0);
                }
            } else if let Some(rest) = line.strip_prefix("VmPeak:") {
                if let Some(n) = rest.split_whitespace().next() {
                    s.peak_kib = n.parse().unwrap_or(0);
                }
            } else if let Some(rest) = line.strip_prefix("Threads:") {
                if let Some(n) = rest.split_whitespace().next() {
                    s.threads = n.parse().unwrap_or(0);
                }
            }
        }
    }

    // CPU jiffies from /proc/self/stat (fields 14, 15: utime, stime; 22: starttime)
    if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
        // The comm field can contain spaces, so split after the last ')'.
        if let Some(after_comm) = stat.rsplit_once(')') {
            let fields: Vec<&str> = after_comm.1.split_whitespace().collect();
            // fields[0]=state, ..., fields[11]=utime, fields[12]=stime, fields[19]=starttime
            // (all 0-indexed after the ')' split; matches /proc/[pid]/stat column offsets minus 3)
            if fields.len() > 19 {
                s.utime_jiffies = fields[11].parse().unwrap_or(0);
                s.stime_jiffies = fields[12].parse().unwrap_or(0);
                s.starttime_jiffy = fields[19].parse().unwrap_or(0);
            }
        }
    }

    s
}

#[derive(Default, Clone, Copy)]
struct ProcStats {
    rss_kib: u64,
    peak_kib: u64,
    utime_jiffies: u64,
    stime_jiffies: u64,
    starttime_jiffy: u64, // ticks since system boot when process started
    threads: u64,
}

/// Shared state for the web layer.
#[derive(Clone)]
pub struct WebState {
    pub server: Arc<ServerState>,
    pub config: Arc<Config>,
    pub metrics: Arc<Metrics>,
    pub seckey_hex: String,
    /// Path to the TOML config file (for the Settings tab read/write).
    /// Empty string disables the Settings editor.
    pub config_path: String,
    /// Triggered to request a hot reload of the content filter and other
    /// safely-reloadable config. Read by the main task's reload watcher.
    pub reload_flag: Arc<std::sync::atomic::AtomicBool>,
    /// Cached public IPv4 string. Computed once at startup so /api/status
    /// doesn't re-parse /proc/net/fib_trie on every 5s poll.
    pub cached_public_ip: String,
    /// Password login; `None` when `admin.password_hash` is empty.
    pub auth: Option<Arc<crate::admin_auth::Auth>>,
    /// HTTPS; `None` when `admin.tls = "off"`.
    pub tls: Option<Arc<crate::admin_tls::AdminTls>>,
}

// ── Access control ───────────────────────────────────────────────────────────

/// Is this state-changing request from another site?
///
/// `Sec-Fetch-Site`, when the browser sends it (HTTPS and loopback only),
/// decides: `same-origin` and `none` (typed or bookmarked) pass, anything
/// else is refused. Otherwise `Origin` must name this host; `null` is refused.
/// The panel sends `Referrer-Policy: same-origin`, under which a browser puts
/// the real origin on its own same-origin POSTs and `null` on cross-origin
/// ones. (Under `no-referrer` it would send `null` for both, and no form
/// could be submitted.) Requests with neither header (curl, scripts) are let
/// through: they do not carry a victim's cookie.
fn cross_site(headers: &HeaderMap) -> bool {
    if let Some(v) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        return !matches!(v.trim(), "same-origin" | "none");
    }
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    let origin_host = origin.split_once("://").map(|(_, h)| h).unwrap_or(origin);
    !origin_host.trim().eq_ignore_ascii_case(host.trim())
}

/// Is the `Host` header one this panel answers to?
///
/// This stops DNS rebinding: a page on `evil.example` re-points its own name
/// at 127.0.0.1 and then talks to the panel through the SSH tunnel as a
/// same-origin page, so `Origin` and `Host` agree and no login stands in the
/// way when none is configured. Its requests still say `Host: evil.example`.
/// An IP literal, `localhost` and the configured `admin.tls_names` are
/// accepted; any other name is refused.
fn host_allowed(headers: &HeaderMap, admin: &crate::config::AdminConfig) -> bool {
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let host = host.trim();
    // "[v6]:port", "[v6]", "v4:port", "name:port", "name"
    let name = if let Some(rest) = host.strip_prefix('[') {
        match rest.split_once(']') {
            Some((inside, _)) => inside,
            None => return false,
        }
    } else {
        host.rsplit_once(':').map_or(host, |(h, _)| h)
    };
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    name.parse::<std::net::IpAddr>().is_ok()
        || name == "localhost"
        || admin
            .tls_names
            .iter()
            .any(|n| n.trim().trim_end_matches('.').eq_ignore_ascii_case(&name))
}

/// Every request passes here: Host check, CSRF check, login check, security
/// headers.
async fn guard(
    State(s): State<WebState>,
    ConnectInfo(_peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    if !host_allowed(req.headers(), &s.config.admin) {
        return (
            StatusCode::MISDIRECTED_REQUEST,
            "unknown Host: open the panel by IP address, localhost, or a name in \
             admin.tls_names\n",
        )
            .into_response();
    }
    let state_changing = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if state_changing && cross_site(req.headers()) {
        return (StatusCode::FORBIDDEN, "cross-site request refused\n").into_response();
    }
    if let Some(auth) = &s.auth {
        let path = req.uri().path();
        let open = path == "/login";
        let token = req
            .headers()
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|c| crate::admin_auth::cookie_token(c, crate::admin_auth::cookie_name(s.tls.is_some())));
        let ok = token.is_some_and(|t| auth.session_valid(t, std::time::Instant::now()));
        if !open && !ok {
            return if path.starts_with("/api/") {
                (StatusCode::UNAUTHORIZED, "login required\n").into_response()
            } else {
                (StatusCode::SEE_OTHER, [(header::LOCATION, "/login")]).into_response()
            };
        }
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    // The panel never needs to be framed, sniffed or to leak its URLs to
    // other sites. `same-origin`, not `no-referrer`: see `cross_site`.
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    resp
}

fn session_cookie(value: &str, max_age: u64, secure: bool) -> HeaderValue {
    // `Secure` over HTTPS: the browser then never sends the cookie in clear.
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}",
        crate::admin_auth::cookie_name(!secure.is_empty())
    ))
    .expect("cookie is ASCII")
}

fn login_html(message: &str) -> Html<String> {
    Html(LOGIN_HTML.replace("{{MESSAGE}}", message))
}

async fn login_page(State(s): State<WebState>) -> Response {
    if s.auth.is_none() {
        return (StatusCode::SEE_OTHER, [(header::LOCATION, "/")]).into_response();
    }
    login_html("").into_response()
}

async fn login_submit(
    State(s): State<WebState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: axum::body::Body,
) -> Response {
    use crate::admin_auth::Login;
    let Some(auth) = &s.auth else {
        return (StatusCode::SEE_OTHER, [(header::LOCATION, "/")]).into_response();
    };
    // Anyone can reach this handler. A form with one password field fits in a
    // few hundred bytes; a body that is larger, or arrives slowly, is someone
    // trying to hold a connection open.
    let bytes = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        axum::body::to_bytes(body, 4096),
    )
    .await
    {
        Ok(Ok(b)) => b,
        _ => return (StatusCode::PAYLOAD_TOO_LARGE, "login form too large or too slow\n").into_response(),
    };
    let body = String::from_utf8_lossy(&bytes);
    let password = crate::admin_auth::form_password(&body).unwrap_or_default();
    match auth.login(peer.ip(), password).await {
        Login::Ok(token) => {
            info!(ip = %peer.ip(), "admin login");
            let ttl = crate::admin_auth::SESSION_TTL.as_secs();
            (
                StatusCode::SEE_OTHER,
                [
                    (header::LOCATION, HeaderValue::from_static("/")),
                    (header::SET_COOKIE, session_cookie(&token, ttl, s.tls.is_some())),
                ],
            )
                .into_response()
        }
        Login::Wrong => {
            warn!(ip = %peer.ip(), "admin login: wrong password");
            (StatusCode::UNAUTHORIZED, login_html("Wrong password.")).into_response()
        }
        Login::Busy => (
            StatusCode::TOO_MANY_REQUESTS,
            login_html("Too many logins at once. Try again in a few seconds."),
        )
            .into_response(),
        Login::Locked(wait) => {
            let mins = wait.as_secs().div_ceil(60);
            (
                StatusCode::TOO_MANY_REQUESTS,
                login_html(&format!(
                    "Too many wrong passwords from this address. Try again in {mins} min."
                )),
            )
                .into_response()
        }
    }
}

async fn logout(State(s): State<WebState>, headers: HeaderMap) -> Response {
    if let (Some(auth), Some(tok)) = (
        &s.auth,
        headers
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|c| crate::admin_auth::cookie_token(c, crate::admin_auth::cookie_name(s.tls.is_some()))),
    ) {
        auth.logout(tok);
    }
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, HeaderValue::from_static("/login")),
            (header::SET_COOKIE, session_cookie("", 0, s.tls.is_some())),
        ],
    )
        .into_response()
}

const LOGIN_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ed2k-server admin — log in</title>
<style>
body{background:#111827;color:#e5e7eb;font-family:system-ui,sans-serif;display:flex;
     align-items:center;justify-content:center;min-height:100vh;margin:0}
form{background:#1f2937;padding:28px 32px;border-radius:8px;min-width:280px}
h1{font-size:1.1rem;margin:0 0 16px}
input{width:100%;box-sizing:border-box;padding:8px;margin:6px 0 14px;border-radius:4px;
      border:1px solid #374151;background:#111827;color:#e5e7eb}
button{width:100%;padding:8px;border:0;border-radius:4px;background:#2563eb;color:#fff;cursor:pointer}
.msg{color:#f87171;font-size:.85rem;min-height:1.2em}
</style></head><body>
<form method="post" action="/login">
  <h1>ed2k-server admin</h1>
  <label for="pw">Password</label>
  <input id="pw" name="password" type="password" autocomplete="current-password" autofocus required>
  <div class="msg">{{MESSAGE}}</div>
  <button type="submit">Log in</button>
</form>
</body></html>
"#;

/// Most connections the panel holds at once, and per client address (IPv6:
/// per /64). A browser opens about six to one host.
const ADMIN_MAX_CONNS: usize = 64;
const ADMIN_MAX_CONNS_PER_IP: u32 = 16;

/// Serve the panel, over HTTPS when `tls` is set.
///
/// This is the accept loop `axum::serve` would run, written out so that every
/// connection, with or without TLS, gets the same limits: a cap overall and
/// per address, a TLS handshake deadline, a deadline for each request's
/// headers, and a lifetime after which the browser simply reconnects. Without
/// them a few dozen slow connections would lock the operator out of a panel
/// that anyone can reach.
async fn serve_admin(
    listener: TcpListener,
    app: Router,
    tls: Option<Arc<crate::admin_tls::AdminTls>>,
    admin: Arc<crate::config::AdminConfig>,
) {
    use std::collections::HashMap;
    use std::time::Duration;
    let slots = Arc::new(tokio::sync::Semaphore::new(ADMIN_MAX_CONNS));
    let per_ip: Arc<std::sync::Mutex<HashMap<std::net::IpAddr, u32>>> = Arc::default();
    struct Held(Arc<std::sync::Mutex<HashMap<std::net::IpAddr, u32>>>, std::net::IpAddr);
    impl Drop for Held {
        fn drop(&mut self) {
            let mut m = self.0.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(n) = m.get_mut(&self.1) {
                *n -= 1;
                if *n == 0 {
                    m.remove(&self.1);
                }
            }
        }
    }
    let key = |ip: std::net::IpAddr| match ip {
        std::net::IpAddr::V6(v6) if v6.to_ipv4_mapped().is_none() => {
            let s = v6.segments();
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        other => other,
    };
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "admin accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue; // dropped: closes the socket
        };
        let k = key(peer.ip());
        {
            let mut m = per_ip.lock().unwrap_or_else(|e| e.into_inner());
            let n = m.entry(k).or_insert(0);
            if *n >= ADMIN_MAX_CONNS_PER_IP {
                continue;
            }
            *n += 1;
        }
        let held = Held(per_ip.clone(), k);
        let app = app.clone();
        let tls = tls.clone();
        let admin = admin.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _held = held;
            let life = Duration::from_secs(300);
            match tls {
                Some(tls) => {
                    // A TLS connection opens with a handshake record (0x16).
                    // Anything else on this port is a browser that was given
                    // http://: send it to https:// on the same port.
                    let mut first = [0u8; 1];
                    let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_secs(10), tcp.peek(&mut first)).await
                    else {
                        return;
                    };
                    if n == 1 && first[0] != 0x16 {
                        let _ = tokio::time::timeout(
                            Duration::from_secs(10),
                            redirect_plain_http(tcp, &admin),
                        )
                        .await;
                        return;
                    }
                    let accept = tls.acceptor.accept(tcp);
                    let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(10), accept).await
                    else {
                        // Plain HTTP on the HTTPS port, a scanner, a browser that
                        // refused the certificate: nothing worth a log line each.
                        return;
                    };
                    let _ = tokio::time::timeout(life, serve_conn(stream, app, peer)).await;
                }
                None => {
                    let _ = tokio::time::timeout(life, serve_conn(tcp, app, peer)).await;
                }
            }
        });
    }
}

/// Answer a plain-HTTP request on the HTTPS port with a redirect to
/// `https://<Host><path>`. Only a `Host` the panel answers to is used (the
/// same check as for every request), so the redirect cannot be pointed
/// elsewhere. 302, not 301: a browser would cache a 301 for good and keep
/// trying https:// after `admin.tls` is turned off again.
async fn redirect_plain_http(mut tcp: tokio::net::TcpStream, admin: &crate::config::AdminConfig) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 4096 {
        match tcp.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    const BODY: &str = "This panel is served over HTTPS.\n";
    let resp = match redirect_target(&buf, admin) {
        Some(loc) => format!(
            "HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Type: text/plain\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
            BODY.len()
        ),
        None => format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
            BODY.len()
        ),
    };
    let _ = tcp.write_all(resp.as_bytes()).await;
    let _ = tcp.shutdown().await;
}

/// The `https://` URL for a plain-HTTP request head, or `None` when the
/// request is not one we redirect (no or unknown `Host`, not origin-form).
fn redirect_target(head: &[u8], admin: &crate::config::AdminConfig) -> Option<String> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let mut parts = lines.next()?.split(' ');
    let method = parts.next()?;
    let target = parts.next()?;
    if !matches!(method, "GET" | "HEAD") {
        return None;
    }
    // Origin-form only: "/path?query". Not "//host" or an absolute URL.
    let path = if target.starts_with('/') && !target.starts_with("//") {
        target
    } else {
        "/"
    };
    if !path.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    let host = lines
        .take_while(|l| !l.is_empty())
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("host").then(|| v.trim())
        })?;
    if host.is_empty() || !host.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    let mut h = HeaderMap::new();
    h.insert(header::HOST, HeaderValue::from_str(host).ok()?);
    if !host_allowed(&h, admin) {
        return None;
    }
    Some(format!("https://{host}{path}"))
}

/// One HTTP/1.1 connection, with the peer address where `ConnectInfo` finds it.
async fn serve_conn<I>(io: I, app: Router, peer: SocketAddr)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use hyper_util::rt::{TokioIo, TokioTimer};
    use tower::Service;
    let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
        req.extensions_mut().insert(ConnectInfo(peer));
        let mut app = app.clone();
        async move { app.call(req.map(axum::body::Body::new)).await }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(std::time::Duration::from_secs(30))
        .serve_connection(TokioIo::new(io), svc)
        .await;
}

/// Spawn the admin HTTP server on `admin.bind:admin.port`. `Config::validate`
/// has already refused a non-loopback address without a password.
pub fn spawn_admin(state: WebState, admin: crate::config::AdminConfig) {
    let port = admin.port;
    let ip = admin.bind_addr();
    let admin_cfg = Arc::new(admin);
    tokio::spawn(async move {
        let app = Router::new()
            .route("/", get(dashboard))
            .route("/api/status", get(api_status))
            .route("/api/stats", get(api_stats))
            .route("/api/highid_mismatches", get(api_highid_mismatches))
            .route("/api/clients", get(api_clients))
            .route("/api/clients/search", get(api_clients_search))
            .route("/assets/flags.woff2", get(asset_flags_font))
            .route("/api/peers", get(api_peers))
            .route("/api/reload", post(api_reload))
            .route("/api/client_stats", get(api_client_stats))
            .route("/api/country_stats", get(api_country_stats))
            .route("/api/filter_info", get(api_filter_info))
            .route("/api/ipfilter_hits", get(api_ipfilter_hits))
            .route("/api/config", get(api_config_get))
            .route("/api/config", post(api_config_set))
            .route("/api/bots", get(api_bots))
            .route("/api/media_stats", get(api_media_stats))
            .route("/api/bots/detail", get(api_bot_detail))
            .route("/api/bots/export", get(api_bots_export))
            .route("/api/bots/log", get(api_bots_log))
            .route("/api/bots/files", get(api_bots_files))
            .route("/api/activity", get(api_activity))
            .route("/api/activity/sources", get(api_activity_sources))
            .route("/api/activity/reset", post(api_activity_reset))
            .route("/api/block_stats", get(api_block_stats))
            .route("/api/memdebug", get(api_memdebug))
            .route("/api/memsize", get(api_memsize))
            .route("/api/publishers", get(api_publishers))
            .route("/api/health", get(api_health))
            .route("/api/admission", get(api_admission))
            .route("/api/ready", get(api_ready))
            .route("/api/review", get(api_review))
            .route("/api/updates", get(api_updates_status))
            .route("/api/update", post(api_update_run))
            .route("/login", get(login_page).post(login_submit))
            .route("/logout", post(logout))
            .layer(middleware::from_fn_with_state(state.clone(), guard))
            .with_state(state.clone());

        let bind = SocketAddr::new(ip, port);
        if let Some(tls) = state.tls.clone() {
            match TcpListener::bind(bind).await {
                Ok(listener) => {
                    info!(addr = %bind, login = state.auth.is_some(),
                          fingerprint = %tls.fingerprint(),
                          "admin web UI listening over HTTPS. Before accepting the certificate \
                           in a browser, check that it shows this SHA-256 fingerprint");
                    serve_admin(listener, app, Some(tls), admin_cfg.clone()).await;
                }
                Err(e) => warn!(addr = %bind, error = %e, "admin web bind failed — UI disabled"),
            }
            return;
        }
        match TcpListener::bind(bind).await {
            Ok(listener) => {
                if ip.is_loopback() {
                    info!(addr = %bind, login = state.auth.is_some(),
                          "admin web UI listening (loopback only)");
                } else {
                    warn!(
                        addr = %bind,
                        "admin web UI listening on an address other machines can reach, \
                         over plain HTTP: the password (at login) and the session cookie \
                         travel unencrypted. Set admin.tls = \"self-signed\", or use a VPN."
                    );
                }
                serve_admin(listener, app, None, admin_cfg.clone()).await;
            }
            Err(e) => {
                warn!(addr = %bind, error = %e, "admin web bind failed — UI disabled");
            }
        }
    });
}

#[derive(Serialize)]
struct StatusResp {
    server_name: String,
    description: String,
    version: String,
    public_ip: String,
    tcp_port: u16,
    udp_port: u16,
    uptime_seconds: u64,
    client_count: u64,
    low_id_count: u64,
    file_count: u64,
    keyword_count: u64,
    seckey_hex: String,
    /// The panel asks for a password; the page then shows a log-out button.
    login_required: bool,
    /// SHA-256 of the HTTPS certificate in use, when the panel serves HTTPS.
    tls_fingerprint: Option<String>,
    /// Diagnostics: sizes of the previously-unbounded IP-keyed caches, plus the
    /// current flood-bot ban count. Surfaced so RAM growth can be watched live.
    obf_decode_cache_entries: u64,
    incoming_seed_challenges_entries: u64,
    banned_bots: u64,
    /// Number of currently-connected clients that advertised NAT-traversal
    /// capability (sent CT_EMULE_UDPPORTS at login = our client mod). Lets the
    /// operator watch adoption of the NAT-traversal client mod.
    natt_capable_clients: u64,
    ipv6_clients: u64,
    ipv6_sources: u64,
    /// How many LowID↔LowID hole punches the server has coordinated since start.
    natt_coordinated: u64,
}

async fn api_status(
    State(s): State<WebState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Json<StatusResp> {
    Json(StatusResp {
        server_name: s.config.server.name.clone(),
        description: s.config.server.desc.clone(),
        version: format!(
            "{}.{} (ed2k-server {})",
            s.config.server.version_major,
            s.config.server.version_minor,
            env!("CARGO_PKG_VERSION")
        ),
        public_ip: s.cached_public_ip.clone(),
        tcp_port: s.config.network.tcp_port,
        udp_port: s.config.network.udp_port(),
        uptime_seconds: s.metrics.uptime_secs(),
        client_count: s.server.clients.len() as u64,
        low_id_count: s
            .server
            .lowid_count_cached
            .load(std::sync::atomic::Ordering::Relaxed) as u64,
        file_count: s.server.file_slab.live_count() as u64,
        keyword_count: s.server.keyword_index.keyword_count() as u64,
        // The server key identifies this server in obfuscated gossip and is
        // what the update service's access key is derived from. Shown only on
        // the machine itself (an SSH tunnel arrives from loopback).
        seckey_hex: if peer.ip().is_loopback() {
            s.seckey_hex.clone()
        } else {
            "(shown only on loopback)".into()
        },
        login_required: s.auth.is_some(),
        tls_fingerprint: s.tls.as_ref().map(|t| t.fingerprint()),
        obf_decode_cache_entries: s.server.obf_decode_cache.len() as u64,
        incoming_seed_challenges_entries: s.server.incoming_seed_challenges.len() as u64,
        banned_bots: s.server.banned_bots.len() as u64,
        natt_capable_clients: s.server.clients.iter().filter(|c| c.natt_capable).count() as u64,
        // Two different questions, and both are worth watching while this is new:
        // how many sessions could receive an inline IPv6 source record, and how
        // many publishers actually have an address to put in one.
        ipv6_clients: s.server.clients.iter().filter(|c| c.ipv6_capable).count() as u64,
        ipv6_sources: s.server.client_ipv6.len() as u64,
        natt_coordinated: s
            .server
            .block_stats
            .get("holepunch_coordinated")
            .map(|v| *v)
            .unwrap_or(0),
    })
}

#[derive(Serialize)]
struct StatsResp {
    // Process
    rss_kib: u64,
    peak_kib: u64,
    threads: u64,
    cpu_user_jiffies: u64,
    cpu_sys_jiffies: u64,
    // Application traffic counters (self-counted in hot paths)
    bytes_in: u64,
    bytes_out: u64,
    // Operation counters
    searches_total: u64,
    /// Searches served since start, counted by the search path itself.
    /// `searches_total` above comes from a Metrics atomic that was never wired
    /// to the hot path; this one is the real figure.
    searches_served: u64,
    /// Of those, how many exhausted `limits.search_rank_scan` and were ranked
    /// over a prefix of the candidate set rather than over all of it.
    searches_rank_capped: u64,
    /// The same as a percentage, which is the number worth watching: a large
    /// share means the scan cap is deciding results often enough that keeping
    /// source counts in the posting lists starts to pay for itself.
    searches_rank_capped_pct: f64,
    /// Searches that had at least one unknown word dropped rather than
    /// returning nothing.
    searches_words_dropped: u64,
    /// OFFERFILES batches cut at `limits.soft_limit_files`, and records dropped.
    offer_over_soft_batches: u64,
    offer_over_soft_records: u64,
    soft_limit_files: u32,
    /// OFFERFILES packets rejected at `limits.hard_limit_files` (connection closed).
    offer_over_hard_packets: u64,
    /// OFFERFILES v1 (issue #19): whether new logins get the advertisement,
    /// why not if it is on but invalid, and its counters.
    offerfiles_v1: bool,
    offerfiles_v1_error: Option<String>,
    offerfiles_v1_policy: Option<String>,
    offer_v1: serde_json::Value,
    replaced_sessions_closed: u64,
    /// Admission gauges and counters (issue #25), as /api/admission.
    admission: serde_json::Value,
    hard_limit_files: u32,
    /// The source with the most logged-in clients now (see
    /// `ServerState::busiest_ip_by_clients`): its open TCP connections, and
    /// `limits.max_clients_per_ip` below.
    busiest_ip_connections: u32,
    /// That source: "1.2.3.4" or "2001:db8::/64", with its country and how
    /// many clients from it are logged in. Admin page is localhost-only.
    busiest_ip: Option<String>,
    busiest_ip_country: Option<String>,
    busiest_ip_logged_in: u32,
    /// "AS3269 Telecom Italia S.p.A." when the GeoIP database carries it.
    busiest_ip_provider: Option<String>,
    max_clients_per_ip: u32,
    /// `network.highid_verify_observe`: whether the counters below are live.
    highid_observe_enabled: bool,
    highid_observe_verified: u64,
    /// Of the verified: same client, different type marker in login vs hello.
    highid_observe_verified_marker: u64,
    highid_observe_mismatch: u64,
    highid_observe_no_answer: u64,
    highid_observe_skipped: u64,
    /// `network.highid_downgrade_on_wrong_hash`: the check is a verdict.
    highid_downgrade_enabled: bool,
    /// Logins given LowID because a wrong-hash mark was active for them.
    highid_downgraded: u64,
    /// Wrong-hash marks live now.
    highid_marks_active: u64,
    /// Marks dropped because the client's own hash answered again.
    highid_marks_cleared: u64,
    /// "reason: count" pairs, most frequent first.
    highid_observe_reasons: String,
    /// Of the recent wrong-hash cases (bounded buffer), how many answering
    /// clients are connected to us RIGHT NOW from the same address — a second
    /// client behind the same NAT, the case where HighID provably misleads.
    highid_mismatch_same_ip: u64,
    /// Answering client connected, but from a different address. Suggests a
    /// client that presents different hashes, not a shared NAT.
    highid_mismatch_other_ip: u64,
    /// Answering client not connected to this server at all.
    highid_mismatch_not_here: u64,
    /// How many cases the three figures above were computed over.
    highid_mismatch_recent: u64,
    get_sources_total: u64,
    get_sources_cache_hits: u64,
    get_sources_cache_hit_rate: f32,
    smart_sources_cache_entries: u64,
    // Friendly computed fields referenced by the dashboard JS
    cpu_pct: f64,
    rss_mb: f64,
    /// jemalloc `allocated` in MB — the non-evictable working set (in-use bytes,
    /// no reusable free pages). 0.0 if jemalloc isn't the allocator.
    allocated_mb: f64,
    /// Bytes per indexed file computed from `allocated` (not RSS), so it tracks
    /// real structural cost without lazy-page noise. 0.0 if no files / no jemalloc.
    bytes_per_file: f64,
    cache_hit_pct: f64,
}

async fn api_stats(State(s): State<WebState>) -> Json<StatsResp> {
    let proc = read_proc_stats();
    let busiest = s.server.busiest_ip_by_clients();
    let m = &s.metrics;
    // GETSOURCES cache hit rate comes from the SmartSources cache's own
    // hit/miss counters. (The Metrics::get_sources_* atomics were never wired
    // to the hot path, which is why this used to read a constant 0.0%.)
    let (search_capped, search_served) = s.server.search_rank_stats();
    let (mm_same, mm_other, mm_none, mm_total) = s
        .server
        .highid_observe
        .classify_mismatches(&s.server.clients);
    let (gs_hits, gs_misses) = s.server.smart_sources.stats();
    let gs_total = gs_hits + gs_misses;
    let hit_rate = if gs_total > 0 {
        (gs_hits as f32) / (gs_total as f32)
    } else {
        0.0
    };
    Json(StatsResp {
        rss_kib: proc.rss_kib,
        peak_kib: proc.peak_kib,
        threads: proc.threads,
        cpu_user_jiffies: proc.utime_jiffies,
        cpu_sys_jiffies: proc.stime_jiffies,
        bytes_in: m.bytes_in.load(Ordering::Relaxed),
        bytes_out: m.bytes_out.load(Ordering::Relaxed),
        searches_total: m.searches_total.load(Ordering::Relaxed),
        searches_served: search_served,
        searches_rank_capped: search_capped,
        searches_words_dropped: s.server.search_words_dropped_count(),
        offer_over_soft_batches: s.server.offer_over_soft_stats().0,
        offer_over_soft_records: s.server.offer_over_soft_stats().1,
        soft_limit_files: s.server.live_cfg.load().limits.soft_limit_files,
        offer_over_hard_packets: s.server.offer_over_hard_count(),
        offerfiles_v1: s.server.live_cfg.load().limits.offerfiles_v1,
        offerfiles_v1_error: crate::server::offer_pacing::OfferPolicy::from_limits(
            &s.server.live_cfg.load().limits,
        )
        .err(),
        offerfiles_v1_policy: {
            let live = s.server.live_cfg.load();
            crate::server::offer_pacing::OfferPolicy::from_limits(&live.limits)
                .ok()
                .flatten()
                .map(|p| {
                    let ceiling = live.limits.offerfiles_global_records_per_sec;
                    format!(
                        "{} files per batch, one batch per {} ms; soft {}, hard {}; server-wide {}",
                        p.batch_max,
                        p.min_interval_ms,
                        p.soft,
                        p.hard,
                        if ceiling == 0 {
                            "no ceiling".to_string()
                        } else {
                            format!("{ceiling} records/s")
                        }
                    )
                })
        },
        offer_v1: s.server.offer_v1.to_json(&s.server.offer_v1_pacer),
        replaced_sessions_closed: s
            .server
            .replaced_sessions_closed
            .load(std::sync::atomic::Ordering::Relaxed),
        admission: s.server.admission.metrics(),
        hard_limit_files: s.server.live_cfg.load().limits.hard_limit_files,
        busiest_ip_connections: busiest.map_or(0, |(_, _, conns)| conns),
        busiest_ip: busiest.map(|(ip, _, _)| match ip {
            std::net::IpAddr::V6(_) => {
                format!("{ip}/{}", s.server.admission.cfg.ipv6_source_prefix_bits)
            }
            v4 => v4.to_string(),
        }),
        busiest_ip_country: busiest.and_then(|(ip, _, _)| {
            s.server
                .country_db
                .try_read()
                .ok()
                .and_then(|db| db.lookup(ip).map(|(c, _)| c))
        }),
        busiest_ip_provider: busiest.and_then(|(ip, _, _)| {
            s.server.country_db.try_read().ok().and_then(|db| db.provider(ip))
        }),
        busiest_ip_logged_in: busiest.map_or(0, |(_, n, _)| n),
        max_clients_per_ip: s.server.live_cfg.load().limits.max_clients_per_ip,
        highid_observe_enabled: {
            let n = &s.server.live_cfg.load().network;
            n.highid_verify_observe || n.highid_downgrade_on_wrong_hash
        },
        highid_downgrade_enabled: s
            .server
            .live_cfg
            .load()
            .network
            .highid_downgrade_on_wrong_hash,
        highid_downgraded: s.server.highid_observe.downgraded.load(Ordering::Relaxed),
        highid_marks_active: s.server.highid_observe.marks_active() as u64,
        highid_marks_cleared: s
            .server
            .highid_observe
            .marks_cleared
            .load(Ordering::Relaxed),
        highid_observe_verified: s.server.highid_observe.verified.load(Ordering::Relaxed),
        highid_observe_verified_marker: s
            .server
            .highid_observe
            .verified_marker_variant
            .load(Ordering::Relaxed),
        highid_observe_mismatch: s.server.highid_observe.mismatch.load(Ordering::Relaxed),
        highid_observe_no_answer: s.server.highid_observe.no_answer.load(Ordering::Relaxed),
        highid_observe_skipped: s.server.highid_observe.skipped_busy.load(Ordering::Relaxed),
        highid_mismatch_same_ip: mm_same,
        highid_mismatch_other_ip: mm_other,
        highid_mismatch_not_here: mm_none,
        highid_mismatch_recent: mm_total,
        highid_observe_reasons: {
            let mut v: Vec<(&'static str, u64)> = s
                .server
                .highid_observe
                .reasons
                .iter()
                .map(|e| (*e.key(), *e.value()))
                .collect();
            v.sort_by(|a, b| b.1.cmp(&a.1));
            v.iter()
                .map(|(r, n)| format!("{r}: {n}"))
                .collect::<Vec<_>>()
                .join("; ")
        },
        searches_rank_capped_pct: if search_served > 0 {
            (search_capped as f64) * 100.0 / (search_served as f64)
        } else {
            0.0
        },
        get_sources_total: gs_total,
        get_sources_cache_hits: gs_hits,
        get_sources_cache_hit_rate: hit_rate,
        smart_sources_cache_entries: s.server.smart_sources.len() as u64,
        cpu_pct: {
            // Accurate CPU% = (utime+stime) / process_uptime_jiffies * 100
            // where process_uptime = system_uptime_secs * CLK_TCK - starttime_jiffies
            // CLK_TCK = 100 on virtually all Linux systems.
            // /proc/uptime gives system uptime in seconds.
            let sys_uptime_secs = std::fs::read_to_string("/proc/uptime")
                .ok()
                .and_then(|s| {
                    s.split_whitespace()
                        .next()
                        .and_then(|v| v.parse::<f64>().ok())
                })
                .unwrap_or(0.0);
            const CLK_TCK: f64 = 100.0;
            let sys_uptime_ticks = sys_uptime_secs * CLK_TCK;
            let proc_uptime_ticks = (sys_uptime_ticks - proc.starttime_jiffy as f64).max(1.0);
            let cpu_ticks = (proc.utime_jiffies + proc.stime_jiffies) as f64;
            (cpu_ticks / proc_uptime_ticks * 100.0).min(100.0 * proc.threads.max(1) as f64)
        },
        rss_mb: proc.rss_kib as f64 / 1024.0,
        allocated_mb: {
            jemalloc_allocated()
                .map(|b| b as f64 / 1_048_576.0)
                .unwrap_or(0.0)
        },
        bytes_per_file: {
            let files = s.server.file_slab.live_count() as f64;
            match jemalloc_allocated() {
                Some(b) if files > 0.0 => b as f64 / files,
                _ => 0.0,
            }
        },
        cache_hit_pct: hit_rate as f64 * 100.0,
    })
}

#[derive(Serialize)]
struct ClientRow {
    ip: String,
    nick: String,
    country: String,
    software: String,
    /// With version and mod: "eMule v0.70b [AI v1.6.0]".
    software_detail: String,
    /// The login's shape (see `ClientHandle::login_fp`), shown as a tooltip.
    login_fp: String,
    shared_files: u32,
    high_id: bool,
    connected_seconds: u64,
    /// This session can parse an inline IPv6 source record.
    ipv6_capable: bool,
    /// The client's own IPv6, when it has one we would publish.
    ///
    /// Shown because there is no other way to tell WHICH clients these are: a
    /// client speaking the IPv6 extension is indistinguishable from a plain
    /// eMule at login — same CT_EMULE_VERSION, no mod tag, no compatible-client
    /// tag. The only distinguishing signal is the address itself, so that is
    /// what gets shown rather than a guess at a product name.
    ipv6: Option<String>,
    /// The network's provider ("AS3269 Telecom Italia S.p.A."), filled for
    /// the rows of a search page when the GeoIP database carries it.
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
}

fn client_row(s: &WebState, c: &crate::state::ClientHandle, now: Instant) -> ClientRow {
    ClientRow {
        ip: c.ip.to_string(),
        nick: c.nick.clone(),
        country: c.country.clone(),
        software: c.software.clone(),
        software_detail: c.software_detail.clone(),
        login_fp: c.login_fp.clone(),
        // Counted from the source index, the same count the soft limit uses.
        // The handle had its own counter that nothing ever incremented, so
        // this column read 0 for everyone.
        shared_files: shared_files_of(s, c),
        high_id: c.is_high_id,
        connected_seconds: now.saturating_duration_since(c.connected_at).as_secs(),
        ipv6_capable: c.ipv6_capable,
        ipv6: c.ipv6.map(|a| a.to_string()),
        provider: None,
    }
}

fn shared_files_of(s: &WebState, c: &crate::state::ClientHandle) -> u32 {
    s.server
        .user_files
        .get(&c.user_hash)
        .map_or(0, |f| f.len() as u32)
}

/// Every connected client, unfiltered. Kept for scripts; the admin page uses
/// /api/clients/search, which pages on the server.
async fn api_clients(State(s): State<WebState>) -> Json<Vec<ClientRow>> {
    // Take a snapshot of current clients. DashMap iteration is consistent
    // enough for an admin view — we accept a touch of staleness.
    let now = Instant::now();
    let rows: Vec<ClientRow> = s
        .server
        .clients
        .iter()
        .map(|entry| client_row(&s, entry.value(), now))
        .collect();
    Json(rows)
}

/// Decode one query-string value: `+` is a space, `%XX` a byte; invalid
/// escapes are kept as written. Lossy UTF-8.
fn url_decode(v: &str) -> String {
    fn hex(c: u8) -> Option<u8> {
        (c as char).to_digit(16).map(|d| d as u8)
    }
    let b = v.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => match (b.get(i + 1).and_then(|&c| hex(c)), b.get(i + 2).and_then(|&c| hex(c))) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            x => out.push(x),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// What the Clients tab asks for. Every field is optional; an empty query
/// matches everyone.
#[derive(Debug, Default, PartialEq)]
struct ClientQuery {
    /// Free text, lowercased: a substring of the IPv4/IPv6 address or the
    /// nick, or — when it parses as one — an IPv4 CIDR such as 82.48.0.0/16.
    text: String,
    cidr: Option<(u32, u32)>,
    /// Exact country code, upper case.
    country: String,
    /// Exact software name, as in the Software chart.
    software: String,
    /// Some(true) HighID only, Some(false) LowID only.
    high_id: Option<bool>,
    ipv6_only: bool,
    sort: ClientSort,
    descending: bool,
    offset: usize,
    limit: usize,
}

#[derive(Debug, Default, PartialEq, Clone, Copy)]
enum ClientSort {
    #[default]
    Connected,
    Files,
    Ip,
    Nick,
    Country,
    Software,
}

impl ClientQuery {
    const MAX_LIMIT: usize = 500;

    fn parse(qs: &str) -> Self {
        let mut q = ClientQuery {
            descending: true,
            limit: 100,
            ..Default::default()
        };
        for kv in qs.split('&') {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            let v = url_decode(v);
            let v = v.trim();
            match k {
                "q" => {
                    q.text = v.to_lowercase();
                    q.cidr = parse_cidr_v4(v);
                }
                "country" => q.country = v.to_uppercase(),
                "software" => q.software = v.to_string(),
                "id" => {
                    q.high_id = match v {
                        "high" => Some(true),
                        "low" => Some(false),
                        _ => None,
                    }
                }
                "ipv6" => q.ipv6_only = v == "1",
                "sort" => {
                    q.sort = match v {
                        "files" => ClientSort::Files,
                        "ip" => ClientSort::Ip,
                        "nick" => ClientSort::Nick,
                        "country" => ClientSort::Country,
                        "software" => ClientSort::Software,
                        _ => ClientSort::Connected,
                    }
                }
                "dir" => q.descending = v != "asc",
                "offset" => q.offset = v.parse().unwrap_or(0),
                "limit" => q.limit = v.parse().unwrap_or(100).clamp(1, Self::MAX_LIMIT),
                _ => {}
            }
        }
        q
    }

    fn matches(&self, c: &crate::state::ClientHandle) -> bool {
        if !self.country.is_empty() && !c.country.eq_ignore_ascii_case(&self.country) {
            return false;
        }
        if !self.software.is_empty() && c.software != self.software {
            return false;
        }
        if self.high_id.is_some_and(|h| h != c.is_high_id) {
            return false;
        }
        if self.ipv6_only && !c.ipv6_capable {
            return false;
        }
        if self.text.is_empty() {
            return true;
        }
        if let Some((net, mask)) = self.cidr {
            return match c.ip {
                std::net::IpAddr::V4(v4) => u32::from(v4) & mask == net,
                _ => false,
            };
        }
        c.ip.to_string().contains(&self.text)
            || c.nick.to_lowercase().contains(&self.text)
            || c.software_detail.to_lowercase().contains(&self.text)
            || c.ipv6.is_some_and(|a| a.to_string().contains(&self.text))
    }
}

/// `a.b.c.d/n` → (network, mask). Anything else → None.
fn parse_cidr_v4(v: &str) -> Option<(u32, u32)> {
    let (ip, bits) = v.split_once('/')?;
    let ip: std::net::Ipv4Addr = ip.trim().parse().ok()?;
    let bits: u32 = bits.trim().parse().ok()?;
    if bits > 32 {
        return None;
    }
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    Some((u32::from(ip) & mask, mask))
}

/// The Clients tab: filtered, sorted and paged on the server, so the page
/// receives one screen of rows instead of every connected client.
async fn api_clients_search(
    State(s): State<WebState>,
    axum::extract::RawQuery(qs): axum::extract::RawQuery,
) -> Json<serde_json::Value> {
    let q = ClientQuery::parse(qs.as_deref().unwrap_or(""));
    let now = Instant::now();
    let total = s.server.clients.len();
    // Sort and page on a light key per client, and build full rows only for
    // the page. Building a ClientRow for every match first meant five string
    // allocations and a reverse-index lookup per client — 50k of each for a
    // page of 100, on every refresh of the Clients tab.
    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    enum Key {
        N(u64),
        Ip(std::net::IpAddr),
        S(String),
    }
    let mut keys: Vec<(Key, crate::state::UserHash)> = s
        .server
        .clients
        .iter()
        .filter(|e| q.matches(e.value()))
        .map(|e| {
            let c = e.value();
            let k = match q.sort {
                ClientSort::Connected => {
                    Key::N(now.saturating_duration_since(c.connected_at).as_secs())
                }
                ClientSort::Files => Key::N(u64::from(shared_files_of(&s, c))),
                ClientSort::Ip => Key::Ip(c.ip),
                ClientSort::Nick => Key::S(c.nick.to_lowercase()),
                ClientSort::Country => Key::S(c.country.clone()),
                ClientSort::Software => Key::S(c.software.clone()),
            };
            (k, *e.key())
        })
        .collect();
    let matched = keys.len();
    // Stable, then reversed — the order the full-row version produced.
    keys.sort_by(|a, b| a.0.cmp(&b.0));
    if q.descending {
        keys.reverse();
    }
    // A client that left since the scan is simply not on the page.
    let mut page: Vec<ClientRow> = keys
        .iter()
        .skip(q.offset)
        .take(q.limit)
        .filter_map(|(_, uh)| s.server.clients.get(uh).map(|c| client_row(&s, c.value(), now)))
        .collect();
    {
        let geo = s.server.country_db.read().await;
        for r in &mut page {
            if let Ok(ip) = r.ip.parse::<std::net::IpAddr>() {
                r.provider = geo.provider(ip);
            }
        }
    }
    Json(serde_json::json!({
        "total": total,
        "matched": matched,
        "offset": q.offset,
        "limit": q.limit,
        "rows": page,
    }))
}

#[derive(Serialize)]
struct PeerRow {
    ip: String,
    port: u16,
    has_server_key: bool,
    /// True if this server answered our 0x96 ping (and is thus handed out to
    /// clients). Unverified entries are kept here for the operator to see but
    /// are NOT propagated — the mldonkey filter.
    verified: bool,
    country: Option<String>,
    /// The network's provider ("AS24940 Hetzner Online GmbH"), when the GeoIP
    /// database carries it.
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    /// From the peer's own OP_SERVER_DESC_RES, once it has answered.
    name: Option<String>,
    desc: Option<String>,
    version: Option<String>,
    /// From the peer's 0x97 ping reply.
    users: Option<u32>,
    files: Option<u32>,
    /// We have asked it at least once (name/desc missing after that = it does
    /// not answer plain UDP on TCP+4).
    asked: bool,
}

async fn api_peers(State(s): State<WebState>) -> Json<Vec<PeerRow>> {
    let list = s.server.server_list.read().await;
    let geo = s.server.country_db.read().await;
    let rows: Vec<PeerRow> = list
        .iter()
        .map(|addr| {
            let info = s.server.peer_info.get(addr).map(|e| e.value().clone());
            let info = info.unwrap_or_default();
            PeerRow {
                ip: addr.ip().to_string(),
                port: addr.port(),
                // Per server (ip:port), not per IP: with several servers behind
                // one address, one answering must not mark the others.
                has_server_key: s.server.seed_server_keys.contains_key(addr),
                verified: s.server.verified_sockets.contains_key(addr)
                    || s.server.seed_server_keys.contains_key(addr),
                country: geo.lookup(*addr.ip()).map(|(c, _)| c),
                provider: geo.provider(*addr.ip()),
                name: info.name,
                desc: info.desc,
                version: info.version,
                users: info.users,
                files: info.files,
                asked: info.asked_at.is_some(),
            }
        })
        .collect();
    Json(rows)
}

/// The country-flag font for the admin page. Windows has no flag glyphs, so
/// Chrome, Edge and Opera there showed two letters instead of a flag. The
/// font is a 78 KB subset of Twemoji (CC-BY 4.0, see
/// assets/TwemojiCountryFlags-LICENSE.md), built into the binary so the
/// admin page never loads anything from another host.
async fn asset_flags_font() -> impl IntoResponse {
    (
        [
            (axum::http::header::CONTENT_TYPE, "font/woff2"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=604800"),
        ],
        &include_bytes!("../assets/TwemojiCountryFlags.woff2")[..],
    )
}

/// What the Updates panel needs to draw itself: per-file URL, whether it can be
/// merged, and what is on disk right now.
async fn api_updates_status(
    State(s): State<WebState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Json<serde_json::Value> {
    use crate::updates::Target;
    let u = &s.config.updates;

    let mut files = Vec::new();
    for t in Target::ALL {
        let url = u.url_for(t);
        let path = std::path::Path::new(&u.dest_dir).join(t.filename());
        let meta = std::fs::metadata(&path).ok();
        files.push(serde_json::json!({
            "id": t.id(),
            "label": t.label(),
            "filename": t.filename(),
            "path": path.display().to_string(),
            "url": url,
            "configured": !url.is_empty(),
            "supports_merge": t.supports_merge(),
            "needs_credentials": t.needs_credentials(),
            "exists": meta.is_some(),
            "size_bytes": meta.as_ref().map(|m| m.len()),
        }));
    }

    // The access key is derived, not stored, so it can be shown: it is the same
    // number this server already hands the reference peer during the obfuscated
    // handshake. Seeing it is what makes a 403 diagnosable from this page.
    //
    // Only on loopback, like the server key it is derived from: it is the
    // credential the update service accepts from this address.
    let key = if peer.ip().is_loopback() {
        access_key_hex(&s)
    } else {
        Some("(shown only on loopback)".into())
    };

    Json(serde_json::json!({
        "enabled": u.enabled,
        "dest_dir": u.dest_dir,
        "require_signature": u.require_signature,
        "has_public_key": !u.public_key.trim().is_empty(),
        "key_reference_ip": u.key_reference_ip,
        "access_key": key,
        "backups": u.backups,
        "min_keep_ratio": u.min_keep_ratio,
        "export_url": u.export_url,
        "export_interval_secs": u.export_interval_secs,
        "files": files,
    }))
}

/// Derive the credential this server presents to the update service.
///
/// Returns `None` when no reference IP is configured — the key is meaningless
/// without one, since it is derived against that address.
fn access_key_hex(s: &WebState) -> Option<String> {
    let ip: std::net::Ipv4Addr = s.config.updates.key_reference_ip.trim().parse().ok()?;
    let raw = hex::decode(&s.seckey_hex).ok()?;
    if raw.len() != 16 {
        return None;
    }
    let mut seckey = [0u8; 16];
    seckey.copy_from_slice(&raw);
    Some(format!(
        "{:08x}",
        crate::updates::derive_access_key(&seckey, ip)
    ))
}

#[derive(serde::Deserialize)]
struct UpdateReq {
    target: String,
    /// "replace" or "merge"; absent means replace.
    #[serde(default)]
    mode: String,
}

/// Run one update, then trip the existing reload flag.
///
/// The reload is the part that makes this useful: the same flag the SIGHUP
/// handler and /api/reload set is picked up by the watcher in main.rs within two
/// seconds, and it re-reads EVERY list — blocklist, poison list, whitelist, both
/// term files, the vocabulary, the IP filter and the country database. So a file
/// installed here is in force before the operator can click the next button. The
/// per-file mtime watchers would also catch it, but on a 30 s poll.
async fn api_update_run(
    State(s): State<WebState>,
    Json(req): Json<UpdateReq>,
) -> impl IntoResponse {
    use crate::updates::{self, Mode, Target};

    let u = s.config.updates.clone();
    if !u.enabled {
        return Json(serde_json::json!({
            "ok": false,
            "message": "updates are disabled — set updates.enabled = true"
        }));
    }

    let Some(target) = Target::ALL.into_iter().find(|t| t.id() == req.target) else {
        return Json(serde_json::json!({
            "ok": false,
            "message": format!("unknown target {:?}", req.target)
        }));
    };
    let mode = if req.mode == "merge" {
        Mode::Merge
    } else {
        Mode::Replace
    };

    let credential = if target.needs_credentials() {
        match access_key_hex(&s) {
            Some(k) => Some((u.key_header.clone(), k)),
            None => {
                return Json(serde_json::json!({
                    "ok": false,
                    "message": "this file needs credentials but updates.key_reference_ip is unset                                 or the seckey is unreadable"
                }));
            }
        }
    } else {
        None
    };

    let request = updates::UpdateRequest {
        target,
        mode,
        url: u.url_for(target),
        dest_dir: u.dest_dir.clone(),
        public_key_hex: u.public_key.clone(),
        require_signature: u.require_signature,
        credential,
        backups: u.backups,
        timeout: std::time::Duration::from_secs(u.timeout_secs),
        max_bytes: u.max_bytes,
        min_keep_ratio: u.min_keep_ratio,
    };

    // Blocking HTTP and blocking file IO — off the runtime, or a large download
    // stalls every client on this worker.
    let outcome = tokio::task::spawn_blocking(move || updates::run(&request)).await;

    match outcome {
        Ok(Ok(report)) => {
            tracing::info!(
                target = %report.target,
                entries = report.entries_after.unwrap_or(0),
                signed = report.signature_verified,
                "data file updated — requesting live reload"
            );
            s.reload_flag
                .store(true, std::sync::atomic::Ordering::Relaxed);
            Json(serde_json::json!({
                "ok": true,
                "message": report.message,
                "downloaded": report.downloaded,
                "entries_before": report.entries_before,
                "entries_after": report.entries_after,
                "signature_verified": report.signature_verified,
                "path": report.path,
            }))
        }
        Ok(Err(e)) => {
            // Every failure path leaves the file on disk untouched, which is
            // worth saying in the message: the operator needs to know the server
            // is still filtering with the old list, not with nothing.
            tracing::warn!(target = %req.target, error = %e, "data file update refused");
            Json(serde_json::json!({
                "ok": false,
                "message": format!("{e} (existing file left in place)")
            }))
        }
        Err(e) => Json(serde_json::json!({
            "ok": false,
            "message": format!("update task panicked: {e}")
        })),
    }
}

async fn api_reload(State(s): State<WebState>) -> impl IntoResponse {
    s.reload_flag
        .store(true, std::sync::atomic::Ordering::Relaxed);
    (StatusCode::OK, "reload requested")
}

#[derive(Serialize)]
struct ClientStatEntry {
    software: String,
    count: u64,
    /// The versions within the family (`software_detail`), most common
    /// first, at most `VERSIONS_SHOWN`; the rest are summed in `other_versions`.
    versions: Vec<(String, u64)>,
    other_versions: u64,
}

async fn api_client_stats(State(s): State<WebState>) -> Json<Vec<ClientStatEntry>> {
    const VERSIONS_SHOWN: usize = 12;
    // Compute from CURRENTLY connected clients (not cumulative history).
    use std::collections::HashMap;
    let mut map: HashMap<String, (u64, HashMap<String, u64>)> = HashMap::new();
    for entry in s.server.clients.iter() {
        let c = entry.value();
        let e = map.entry(c.software.clone()).or_default();
        e.0 += 1;
        *e.1.entry(c.software_detail.clone()).or_insert(0) += 1;
    }
    let mut entries: Vec<ClientStatEntry> = map
        .into_iter()
        .map(|(software, (count, versions))| {
            let mut versions: Vec<(String, u64)> = versions.into_iter().collect();
            versions.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            let other_versions = versions.iter().skip(VERSIONS_SHOWN).map(|v| v.1).sum();
            versions.truncate(VERSIONS_SHOWN);
            ClientStatEntry { software, count, versions, other_versions }
        })
        .collect();
    entries.sort_by(|a, b| b.count.cmp(&a.count));
    Json(entries)
}

/// How often offered files carry media tags (`MediaOfferStats`): the numbers
/// that decide whether storing length, bitrate and codec is worth the memory.
async fn api_media_stats(State(s): State<WebState>) -> Json<serde_json::Value> {
    use std::sync::atomic::Ordering::Relaxed;
    let m = &s.server.media_offer_stats;
    let mut codecs: Vec<(String, u64)> = m
        .codecs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    codecs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let distinct = codecs.len();
    codecs.truncate(40);
    let (stored, stored_bytes) = s.server.file_slab.media_report();
    Json(serde_json::json!({
        "files": m.files.load(Relaxed),
        "with_any": m.with_any.load(Relaxed),
        "length": m.length.load(Relaxed),
        "bitrate": m.bitrate.load(Relaxed),
        "codec": m.codec.load(Relaxed),
        "artist_album_title": m.artist_album_title.load(Relaxed),
        "codec_bytes": m.codec_bytes.load(Relaxed),
        "distinct_codecs": distinct,
        "codecs_overflow": m.codecs_overflow.load(Relaxed),
        "top_codecs": codecs,
        // What is held now, in the index (not counted per offer).
        "stored_files": stored,
        "stored_bytes": stored_bytes,
        "codec_table": s.server.file_slab.codecs.len(),
    }))
}

#[derive(Serialize)]
struct CountryStatEntry {
    code: String,
    count: u64,
}

async fn api_country_stats(State(s): State<WebState>) -> Json<Vec<CountryStatEntry>> {
    // Compute from CURRENTLY connected clients.
    let mut map: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for entry in s.server.clients.iter() {
        *map.entry(entry.value().country.clone()).or_insert(0) += 1;
    }
    let mut entries: Vec<CountryStatEntry> = map
        .into_iter()
        .map(|(code, count)| CountryStatEntry { code, count })
        .collect();
    entries.sort_by(|a, b| b.count.cmp(&a.count));
    Json(entries)
}

#[derive(Serialize)]
struct FilterInfoResp {
    ipfilter_ranges: usize,
    country_db_loaded: bool,
    /// Which GeoIP source is loaded and what it covers.
    country_db: String,
    country_db_ipv6: bool,
}

async fn api_filter_info(State(s): State<WebState>) -> Json<FilterInfoResp> {
    let ipfilter_ranges = s.server.ip_filter.read().await.len();
    let geo = s.server.country_db.read().await;
    Json(FilterInfoResp {
        ipfilter_ranges,
        country_db_loaded: geo.is_loaded(),
        country_db: geo.describe(),
        country_db_ipv6: geo.supports_ipv6(),
    })
}

#[derive(Serialize)]
struct IpFilterHitRow {
    range: String,
    count: u32,
    description: String,
}

/// Per-range guarding.p2p block statistics: only ranges that have actually
/// blocked an IP, sorted by hit count. Descriptions are resolved from the source
/// file on demand (not held in RAM), so this reads the file — fine for an
/// occasional admin view. Capped to the top rows to keep the response small.
async fn api_ipfilter_hits(State(s): State<WebState>) -> Json<Vec<IpFilterHitRow>> {
    let path = std::path::PathBuf::from(&s.config.storage.ipfilter_path);
    let rows = {
        let filter = s.server.ip_filter.read().await;
        filter.hit_report(&path)
    };
    let out: Vec<IpFilterHitRow> = rows
        .into_iter()
        .take(500)
        .map(|r| IpFilterHitRow {
            range: format!(
                "{} - {}",
                std::net::Ipv4Addr::from(r.start),
                std::net::Ipv4Addr::from(r.end)
            ),
            count: r.count,
            description: r.desc,
        })
        .collect();
    Json(out)
}

// ─── CONFIG TAB — read/write config.toml from the web UI ─────────────────

#[derive(Serialize)]
struct ConfigGetResp {
    path: String,
    content: String,
    read_only: bool,
    error: Option<String>,
}

async fn api_config_get(State(s): State<WebState>) -> Json<ConfigGetResp> {
    if s.config_path.is_empty() {
        return Json(ConfigGetResp {
            path: String::new(),
            content: String::new(),
            read_only: true,
            error: Some("config_path not set (server was launched without a config file)".into()),
        });
    }
    match std::fs::read_to_string(&s.config_path) {
        Ok(content) => Json(ConfigGetResp {
            path: s.config_path.clone(),
            content,
            read_only: false,
            error: None,
        }),
        Err(e) => Json(ConfigGetResp {
            path: s.config_path.clone(),
            content: String::new(),
            read_only: true,
            error: Some(format!("cannot read {}: {}", s.config_path, e)),
        }),
    }
}

#[derive(serde::Deserialize)]
struct ConfigSetReq {
    content: String,
}

#[derive(Serialize)]
struct ConfigSetResp {
    ok: bool,
    error: Option<String>,
    hint: Option<String>,
}

async fn api_config_set(
    State(s): State<WebState>,
    Json(req): Json<ConfigSetReq>,
) -> Json<ConfigSetResp> {
    if s.config_path.is_empty() {
        return Json(ConfigSetResp {
            ok: false,
            error: Some("config_path not set".into()),
            hint: None,
        });
    }
    // 1. Parse the new TOML into a proper Config struct.
    let new_cfg: crate::config::Config = match toml::from_str(&req.content) {
        Ok(c) => c,
        Err(e) => {
            return Json(ConfigSetResp {
                ok: false,
                error: Some(format!("config parse error: {}", e)),
                hint: Some("config file was not modified".into()),
            })
        }
    };

    // 1b. The same checks as at startup. Without this a config the server would
    // refuse to start with (e.g. a zero network.max_decompressed_frame_size)
    // could be applied live.
    if let Err(e) = new_cfg.validate() {
        return Json(ConfigSetResp {
            ok: false,
            error: Some(format!("config invalid: {}", e)),
            hint: Some("config file was not modified".into()),
        });
    }

    // 2. Detect non-hot-reloadable changes (require restart) for the user message.
    let old = s.server.live_cfg.load();
    let mut restart_needed: Vec<String> = Vec::new();
    if old.network.tcp_port != new_cfg.network.tcp_port {
        restart_needed.push("network.tcp_port".into());
    }
    if old.admin.port != new_cfg.admin.port
        || old.admin.enabled != new_cfg.admin.enabled
        || old.admin.bind != new_cfg.admin.bind
        || old.admin.password_hash != new_cfg.admin.password_hash
        || old.admin.tls != new_cfg.admin.tls
        || old.admin.tls_cert != new_cfg.admin.tls_cert
        || old.admin.tls_key != new_cfg.admin.tls_key
        || old.admin.tls_ca_cert != new_cfg.admin.tls_ca_cert
        || old.admin.tls_ca_key != new_cfg.admin.tls_ca_key
        || old.admin.tls_names != new_cfg.admin.tls_names
    {
        restart_needed.push("admin.port / enabled / bind / password_hash / tls*".into());
    }
    // [admission] is restart-only (issue #25). The open-socket ceiling also
    // derives from limits.max_clients when it is not set, so raising
    // max_clients live does not raise it until a restart.
    if old.admission != new_cfg.admission
        || old.admission.effective_open_tcp(&old) != new_cfg.admission.effective_open_tcp(&new_cfg)
    {
        restart_needed.push(
            "admission (incl. the open-socket ceiling derived from limits.max_clients)".into(),
        );
    }

    // 3. Write to tempfile + atomic rename.
    let tmp_path = format!("{}.tmp", s.config_path);
    // Keep the original file's permissions: config.toml may hold the admin
    // password hash and the update export token, and a fresh file would get
    // the process umask (typically world-readable).
    let mode = std::fs::metadata(&s.config_path).ok().map(|m| m.permissions());
    let _ = std::fs::remove_file(&tmp_path);
    let write = (|| -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        f.write_all(req.content.as_bytes())?;
        if let Some(m) = &mode {
            f.set_permissions(m.clone())?;
        }
        f.sync_all()
    })();
    if let Err(e) = write {
        return Json(ConfigSetResp {
            ok: false,
            error: Some(format!("write tempfile failed: {}", e)),
            hint: None,
        });
    }
    if let Err(e) = std::fs::rename(&tmp_path, &s.config_path) {
        return Json(ConfigSetResp {
            ok: false,
            error: Some(format!("rename failed: {}", e)),
            hint: None,
        });
    }

    // 4. Atomically swap live_cfg. Hot paths reading state.live_cfg.load()
    //    will immediately see the new values for limits, name, desc, version,
    //    this_ip, storage paths, etc. (Fields requiring re-bind like ports
    //    are stored but not effective until restart.)
    s.server.live_cfg.store(Arc::new(new_cfg));

    // 5. Trigger filter/ipfilter/country-db reload via the existing flag.
    //    The reload watcher in main.rs reads paths from live_cfg.
    s.reload_flag
        .store(true, std::sync::atomic::Ordering::Relaxed);

    let hint = if restart_needed.is_empty() {
        "saved & applied live. Hot-reloadable settings updated immediately.".to_string()
    } else {
        format!(
            "saved. Hot-reloadable settings applied immediately. \
             Restart required to apply changes to: {}",
            restart_needed.join(", ")
        )
    };
    Json(ConfigSetResp {
        ok: true,
        error: None,
        hint: Some(hint),
    })
}

// ─── BOT DETECTION + BLOCK STATS API ─────────────────────────────────────

#[derive(Serialize)]
struct BotRow {
    ip: String,
    country: String,
    query_count: u64,
    queries_per_minute: f64,
    interval_stddev_ms: f64,
    reason: String,
    first_seen_secs_ago: u64,
    last_seen_secs_ago: u64,
    /// True if this IP is currently within its 24h flood-ban window (its UDP
    /// traffic is being dropped at the recv loop).
    banned: bool,
    /// Throttled to `bots.throttle_qpm` instead of banned, now.
    throttled: bool,
    /// Written to the IP filter file for good (server::bot_ipfilter).
    ipfilter_added: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    /// What it sent, counted from its first query (see `BotMix`).
    searches: u64,
    source_requests: u64,
    source_hashes: u64,
    obfuscated: u64,
    src_port: u16,
    our_port: u16,
    src_port_changes: u64,
    /// A TCP client logged in from the same address: at detection time, or
    /// now if there was none then.
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_client: Option<String>,
    /// File hashes it asked sources for: distinct, and in total.
    hashes_distinct: usize,
    hashes_total: u64,
    /// Datagrams dropped since the ban, and how long ago the last one came.
    dropped_after_ban: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_dropped_secs_ago: Option<u64>,
}

/// "eMule v0.50a (nick)" for every address in `ips` that has a TCP client
/// logged in now. One pass over the clients for the whole table.
fn tcp_clients_on(
    s: &WebState,
    ips: &std::collections::HashSet<std::net::IpAddr>,
) -> std::collections::HashMap<std::net::IpAddr, String> {
    let mut out = std::collections::HashMap::new();
    let ips: std::collections::HashSet<_> =
        ips.iter().filter(|ip| s.server.conn_per_ip.contains_key(ip)).copied().collect();
    if ips.is_empty() {
        return out;
    }
    for c in s.server.clients.iter() {
        if ips.contains(&c.ip) && !out.contains_key(&c.ip) {
            let nick: String = c.nick.chars().take(40).collect();
            out.insert(c.ip, format!("{} ({nick})", c.software_detail));
        }
    }
    out
}

async fn api_bots(State(s): State<WebState>) -> Json<Vec<BotRow>> {
    let now = std::time::SystemTime::now();
    let geo = s.server.country_db.read().await;
    // Only IPv4 keys are addresses; an IPv6 key is a prefix with no client.
    let wanted: std::collections::HashSet<std::net::IpAddr> = s
        .server
        .bot_detections
        .iter()
        .filter(|e| e.value().tcp_client.is_none() && e.key().is_ipv4())
        .map(|e| *e.key())
        .collect();
    let live = tcp_clients_on(&s, &wanted);
    let mut rows: Vec<BotRow> = s
        .server
        .bot_detections
        .iter()
        .map(|e| {
            let d = e.value();
            // Sanitize floats so JSON serialization never sees NaN/INFINITY.
            // (serde_json represents them as null, but JS code expects numbers.)
            let qpm = if d.queries_per_minute.is_finite() {
                d.queries_per_minute
            } else {
                0.0
            };
            let stddev = if d.interval_stddev_ms.is_finite() {
                d.interval_stddev_ms
            } else {
                -1.0
            }; // sentinel: "not measured"
            BotRow {
                // An IPv6 bot is a prefix (its source key), shown as such.
                ip: match e.key() {
                    std::net::IpAddr::V6(v6) => {
                        format!("{v6}/{}", s.server.admission.cfg.ipv6_source_prefix_bits)
                    }
                    v4 => v4.to_string(),
                },
                country: d.country.clone(),
                query_count: d.query_count,
                queries_per_minute: qpm,
                interval_stddev_ms: stddev,
                reason: d.reason.clone(),
                first_seen_secs_ago: now
                    .duration_since(d.first_seen)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                last_seen_secs_ago: now
                    .duration_since(d.last_seen)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                banned: s.server.is_bot_banned(*e.key()),
                throttled: s.server.is_bot_throttled(*e.key()),
                ipfilter_added: d.ipfilter_added,
                provider: geo.provider(*e.key()),
                searches: d.mix.searches,
                source_requests: d.mix.source_requests,
                source_hashes: d.mix.source_hashes,
                obfuscated: d.mix.obfuscated,
                src_port: d.mix.src_port,
                our_port: d.mix.our_port,
                src_port_changes: d.mix.src_port_changes,
                tcp_client: d.tcp_client.clone().or_else(|| live.get(e.key()).cloned()),
                hashes_distinct: d.hashes.distinct.len(),
                hashes_total: d.hashes.total,
                dropped_after_ban: d.dropped_after_ban,
                last_dropped_secs_ago: d
                    .last_dropped
                    .and_then(|t| now.duration_since(t).ok())
                    .map(|d| d.as_secs()),
            }
        })
        .collect();
    // total_cmp gives a total order on f64 (no panic on NaN). Sort by qpm desc.
    rows.sort_by(|a, b| b.queries_per_minute.total_cmp(&a.queries_per_minute));
    Json(rows)
}

/// `a=1&b=x%20y` → map, values URL-decoded.
fn query_map(qs: Option<&str>) -> std::collections::HashMap<String, String> {
    qs.unwrap_or("")
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (k.to_string(), url_decode(v))
        })
        .collect()
}

/// Search activity, server-wide and its spread over sources (temporary; see
/// `server::activity`).
async fn api_activity(State(s): State<WebState>) -> impl IntoResponse {
    let rows = s.server.activity.snapshot();
    let mut v = s.server.activity.summary(&rows);
    let cfg = s.server.live_cfg.load();
    v["enabled"] = serde_json::json!(cfg.bots.activity_stats);
    v["max_sources"] = serde_json::json!(cfg.bots.activity_max_sources);
    Json(v)
}

/// Start a new period: every record and total dropped.
async fn api_activity_reset(State(s): State<WebState>) -> impl IntoResponse {
    s.server.activity.reset();
    (StatusCode::OK, "activity statistics reset")
}

/// One row per source. `sort` = requests (default) | searches | sources |
/// files | distinct | peak | per_hour | repeats; `limit` (default 200, 0 =
/// all); `min` = least requests; `format=csv`.
async fn api_activity_sources(
    State(s): State<WebState>,
    axum::extract::RawQuery(qs): axum::extract::RawQuery,
) -> impl IntoResponse {
    use crate::server::activity::{GAP_BUCKETS, PER_REQ_BUCKETS};
    let q = query_map(qs.as_deref());
    let limit: usize = q.get("limit").and_then(|v| v.parse().ok()).unwrap_or(200);
    let min: u64 = q.get("min").and_then(|v| v.parse().ok()).unwrap_or(1);
    let sort = q.get("sort").map(String::as_str).unwrap_or("requests").to_string();
    let mut rows: Vec<_> = s
        .server
        .activity
        .snapshot()
        .into_iter()
        .filter(|(_, r)| r.requests() >= min)
        .collect();
    let key = |r: &crate::server::activity::Rec| -> f64 {
        match sort.as_str() {
            "searches" => r.searches() as f64,
            "sources" => r.source_requests() as f64,
            "files" => r.hashes as f64,
            "distinct" => r.distinct_est(),
            "peak" => r.peak_per_min as f64,
            "per_hour" => r.per_hour(),
            "repeats" => r.hashes as f64 / r.distinct_est().max(1.0),
            _ => r.requests() as f64,
        }
    };
    rows.sort_by(|a, b| key(&b.1).partial_cmp(&key(&a.1)).unwrap_or(std::cmp::Ordering::Equal));
    if limit > 0 {
        rows.truncate(limit);
    }
    let wanted: std::collections::HashSet<std::net::IpAddr> =
        rows.iter().filter(|(ip, r)| r.tcp && ip.is_ipv4()).map(|(ip, _)| *ip).collect();
    let live = tcp_clients_on(&s, &wanted);
    let geo = s.server.country_db.read().await;
    let start = s.server.activity.started_at();
    let at = |secs: u32| -> String {
        chrono::DateTime::<chrono::Utc>::from(start + std::time::Duration::from_secs(secs as u64))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    };
    let prefix = s.server.admission.cfg.ipv6_source_prefix_bits;
    let round2 = |x: f64| (x * 100.0).round() / 100.0;
    let out: Vec<serde_json::Value> = rows
        .iter()
        .map(|(ip, r)| {
            let mut o = serde_json::json!({
                "ip": match ip {
                    std::net::IpAddr::V6(v6) => format!("{v6}/{prefix}"),
                    v4 => v4.to_string(),
                },
                "country": geo.lookup(*ip).map(|(c, _)| c).unwrap_or_default(),
                "provider": geo.provider(*ip).unwrap_or_default(),
                "tcp_client": live.get(ip).cloned().unwrap_or_default(),
                "logged_in": r.tcp,
                "first_seen": at(r.first_s),
                "last_seen": at(r.last_s),
                "active_secs": r.active_secs(),
                "requests": r.requests(),
                "tcp_searches": r.n[0],
                "udp_searches": r.n[1],
                "more_results": r.n[2],
                "tcp_source_requests": r.n[3],
                "udp_source_requests": r.n[4],
                "files_asked": r.hashes,
                "files_per_request": round2(r.hashes as f64 / r.source_requests().max(1) as f64),
                "distinct_files": r.distinct_est().round() as u64,
                "repeats_per_file": round2(r.hashes as f64 / r.distinct_est().max(1.0)),
                "results": r.results,
                "zero_result_searches": r.zero_result,
                "peak_per_min": r.peak_per_min,
                "requests_per_hour": round2(r.per_hour()),
            });
            for (name, n) in PER_REQ_BUCKETS.iter().zip(r.per_req) {
                o[format!("req_files_{name}")] = n.into();
            }
            for (name, n) in GAP_BUCKETS.iter().zip(r.gaps) {
                o[format!("gap_{name}")] = n.into();
            }
            o
        })
        .collect();
    drop(geo);
    if q.get("format").map(String::as_str) == Some("csv") {
        // In this order; a JSON object has its keys sorted.
        let mut cols: Vec<String> = [
            "ip", "country", "provider", "tcp_client", "logged_in", "first_seen", "last_seen",
            "active_secs", "requests", "tcp_searches", "udp_searches", "more_results",
            "tcp_source_requests", "udp_source_requests", "files_asked", "files_per_request",
            "distinct_files", "repeats_per_file", "results", "zero_result_searches",
            "peak_per_min", "requests_per_hour",
        ]
        .iter()
        .map(|c| c.to_string())
        .collect();
        cols.extend(PER_REQ_BUCKETS.iter().map(|n| format!("req_files_{n}")));
        cols.extend(GAP_BUCKETS.iter().map(|n| format!("gap_{n}")));
        let cell = |v: &serde_json::Value| -> String {
            let t = match v {
                serde_json::Value::Null => String::new(),
                serde_json::Value::String(s) => s.clone(),
                o => o.to_string(),
            };
            if t.contains([',', '"', '\n']) {
                format!("\"{}\"", t.replace('"', "\"\""))
            } else {
                t
            }
        };
        let mut body = cols.join(",");
        body.push('\n');
        for o in &out {
            body.push_str(&cols.iter().map(|c| cell(&o[c.as_str()])).collect::<Vec<_>>().join(","));
            body.push('\n');
        }
        return ([(axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8")], body).into_response();
    }
    Json(out).into_response()
}

/// The bot key for an `ip` query parameter: an address, or an IPv6 prefix as
/// the Bots table shows it ("2001:db8::/64").
fn bot_key(s: &WebState, q: &str) -> Option<std::net::IpAddr> {
    let ip: std::net::IpAddr = q.split('/').next()?.trim().parse().ok()?;
    Some(s.server.source_key(ip))
}

/// One bot in detail: the hashes it asked for, newest first, with the name,
/// size and source count of each one we index, and the other bots that asked
/// for the same files.
async fn api_bot_detail(
    State(s): State<WebState>,
    axum::extract::RawQuery(qs): axum::extract::RawQuery,
) -> impl IntoResponse {
    let q = query_map(qs.as_deref());
    let Some(key) = q.get("ip").and_then(|v| bot_key(&s, v)) else {
        return (StatusCode::BAD_REQUEST, "ip= missing or not an address").into_response();
    };
    let Some(d) = s.server.bot_detections.get(&key) else {
        return (StatusCode::NOT_FOUND, "no such bot").into_response();
    };
    let recent: Vec<serde_json::Value> = d
        .hashes
        .recent
        .iter()
        .rev()
        .map(|h| {
            let rec = s.server.file_slab.with_record_by_hash(h, |_, r| {
                (r.name().to_string(), r.size, r.sources.len() as u32)
            });
            match rec {
                Some((name, size, sources)) => serde_json::json!({
                    "hash": hex::encode(h), "name": name, "size": size, "sources": sources,
                }),
                None => serde_json::json!({ "hash": hex::encode(h), "indexed": false }),
            }
        })
        .collect();
    let mine = d.hashes.distinct.clone();
    let (distinct, total, overflow) =
        (d.hashes.distinct.len(), d.hashes.total, d.hashes.distinct_overflow);
    drop(d);
    // Overlap with every other bot. Detections are few and the sets are
    // capped, so this is a few thousand set lookups at most.
    let mut overlap: Vec<(String, usize)> = s
        .server
        .bot_detections
        .iter()
        .filter(|e| *e.key() != key)
        .filter_map(|e| {
            let (small, big) = if e.hashes.distinct.len() < mine.len() {
                (&e.hashes.distinct, &mine)
            } else {
                (&mine, &e.hashes.distinct)
            };
            let n = small.iter().filter(|h| big.contains(*h)).count();
            (n > 0).then(|| (e.key().to_string(), n))
        })
        .collect();
    overlap.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    overlap.truncate(50);
    Json(serde_json::json!({
        "ip": key.to_string(),
        "hashes_distinct": distinct,
        "hashes_total": total,
        "hashes_distinct_capped": overflow,
        "recent": recent,
        "shares_hashes_with": overlap.iter().map(|(ip, n)| serde_json::json!({"ip": ip, "common": n})).collect::<Vec<_>>(),
    }))
    .into_response()
}

/// Every bot detection in memory (since start), as CSV or JSON lines for
/// keeping. No file names: hashes only, so the export can be shared.
async fn api_bots_export(
    State(s): State<WebState>,
    axum::extract::RawQuery(qs): axum::extract::RawQuery,
) -> impl IntoResponse {
    let q = query_map(qs.as_deref());
    let mut rows: Vec<serde_json::Value> = s
        .server
        .bot_detections
        .iter()
        .map(|e| crate::server::bot_detector::ledger_entry("snapshot", *e.key(), e.value()))
        .collect();
    rows.sort_by(|a, b| a["ip"].as_str().cmp(&b["ip"].as_str()));
    if q.get("format").map(String::as_str) == Some("csv") {
        let cols = [
            "ip", "country", "provider", "reason", "qpm", "stddev_ms", "tcp_client", "searches",
            "source_requests", "obfuscated", "src_port", "src_port_changes", "our_port",
            "hashes_total", "hashes_distinct", "dropped_after_ban",
        ];
        let cell = |v: &serde_json::Value| -> String {
            let t = match v {
                serde_json::Value::Null => String::new(),
                serde_json::Value::String(s) => s.clone(),
                o => o.to_string(),
            };
            if t.contains([',', '"', '\n']) {
                format!("\"{}\"", t.replace('"', "\"\""))
            } else {
                t
            }
        };
        let mut out = cols.join(",");
        out.push('\n');
        for r in &rows {
            out.push_str(&cols.iter().map(|c| cell(&r[*c])).collect::<Vec<_>>().join(","));
            out.push('\n');
        }
        return ([(axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8")], out).into_response();
    }
    let body: String = rows.iter().map(|r| format!("{r}\n")).collect();
    ([(axum::http::header::CONTENT_TYPE, "application/x-ndjson")], body).into_response()
}

/// Every file the detected bots asked sources for, one row per hash: name,
/// size and sources from the index (empty when we do not index it), and
/// which bots asked. `?ip=` keeps one bot's files, `?indexed=1` only the ones
/// we index, `?format=json` gives JSON lines instead of CSV.
///
/// Built from each bot's distinct set (up to `BotHashes::MAX_DISTINCT`), so
/// it covers what was asked since start, before and after the ban.
async fn api_bots_files(
    State(s): State<WebState>,
    axum::extract::RawQuery(qs): axum::extract::RawQuery,
) -> impl IntoResponse {
    let q = query_map(qs.as_deref());
    let only = match q.get("ip").filter(|v| !v.is_empty()) {
        Some(v) => match bot_key(&s, v) {
            Some(k) => Some(k),
            None => return (StatusCode::BAD_REQUEST, "ip= is not an address").into_response(),
        },
        None => None,
    };
    let indexed_only = q.get("indexed").is_some_and(|v| v == "1");
    // hash → the bots that asked for it.
    let mut by_hash: std::collections::BTreeMap<crate::state::FileHash, Vec<String>> =
        Default::default();
    for e in s.server.bot_detections.iter() {
        if only.is_some_and(|k| k != *e.key()) {
            continue;
        }
        let ip = e.key().to_string();
        for h in &e.hashes.distinct {
            by_hash.entry(*h).or_default().push(ip.clone());
        }
    }
    struct Row {
        hash: String,
        name: Option<String>,
        size: Option<u64>,
        sources: Option<u32>,
        bots: Vec<String>,
    }
    let mut rows: Vec<Row> = by_hash
        .into_iter()
        .filter_map(|(h, mut bots)| {
            bots.sort();
            let rec = s.server.file_slab.with_record_by_hash(&h, |_, r| {
                (r.name().to_string(), r.size, r.sources.len() as u32)
            });
            if indexed_only && rec.is_none() {
                return None;
            }
            Some(Row {
                hash: hex::encode(h),
                name: rec.as_ref().map(|r| r.0.clone()),
                size: rec.as_ref().map(|r| r.1),
                sources: rec.map(|r| r.2),
                bots,
            })
        })
        .collect();
    // Most-asked first (by how many bots), then by name.
    rows.sort_by(|a, b| {
        b.bots.len().cmp(&a.bots.len()).then_with(|| a.name.cmp(&b.name)).then_with(|| a.hash.cmp(&b.hash))
    });
    if q.get("format").map(String::as_str) == Some("json") {
        let body: String = rows
            .iter()
            .map(|r| {
                format!(
                    "{}\n",
                    serde_json::json!({
                        "hash": r.hash, "indexed": r.name.is_some(), "name": r.name,
                        "size": r.size, "sources": r.sources, "bots": r.bots,
                    })
                )
            })
            .collect();
        return ([(axum::http::header::CONTENT_TYPE, "application/x-ndjson")], body).into_response();
    }
    let cell = |t: &str| -> String {
        if t.contains([',', '"', '\n', '\r']) {
            format!("\"{}\"", t.replace('"', "\"\""))
        } else {
            t.to_string()
        }
    };
    // UTF-8 with a BOM, so Excel shows non-Latin names correctly.
    let mut out = String::from("\u{feff}hash,indexed,name,size,sources,bot_count,bots\n");
    for r in &rows {
        out.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            r.hash,
            if r.name.is_some() { "yes" } else { "no" },
            cell(r.name.as_deref().unwrap_or("")),
            r.size.map_or(String::new(), |v| v.to_string()),
            r.sources.map_or(String::new(), |v| v.to_string()),
            r.bots.len(),
            cell(&r.bots.join(" ")),
        ));
    }
    (
        [
            (axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (axum::http::header::CONTENT_DISPOSITION, "attachment; filename=\"bot-files.csv\""),
        ],
        out,
    )
        .into_response()
}

/// The ledger file (`storage.bot_log_path`), which survives restarts.
/// `?tail=N` returns the last N lines.
async fn api_bots_log(
    State(s): State<WebState>,
    axum::extract::RawQuery(qs): axum::extract::RawQuery,
) -> impl IntoResponse {
    let q = query_map(qs.as_deref());
    let Some(Some(path)) = s.server.bot_log_path.get().cloned() else {
        return (StatusCode::NOT_FOUND, "bot ledger is off (storage.bot_log_path = \"off\")")
            .into_response();
    };
    let text = match tokio::fs::read_to_string(&path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}: {e}", path.display()))
                .into_response()
        }
    };
    let text = match q.get("tail").and_then(|v| v.parse::<usize>().ok()) {
        Some(n) => {
            let lines: Vec<&str> = text.lines().collect();
            lines[lines.len().saturating_sub(n)..].iter().map(|l| format!("{l}\n")).collect()
        }
        None => text,
    };
    ([(axum::http::header::CONTENT_TYPE, "application/x-ndjson")], text).into_response()
}

#[derive(Serialize)]
struct BlockStatRow {
    reason: String,
    count: u64,
    /// Optional: distinct IPs that hit this filter (e.g. CSAM block_stats counts
    /// file publishes but a single user can publish many files).
    unique_ips: Option<u64>,
}

/// Publisher graph: every user the content filter has ever flagged, together with
/// EVERYTHING else they currently publish.
///
/// The point is to reach the files a name-based filter can never catch. A CSAM
/// filename filter only catches publishers who advertise their content; the same
/// account almost always also shares files named `VID_20230116_224252.mp4` or
/// `00050.m2ts`, which no term list can judge. But the *publisher* is a strong
/// signal: if an account tripped the filter on N distinct files, the rest of its
/// library deserves human review.
///
/// Output is intended for MANUAL REVIEW and for building an MD4 hash blocklist
/// (Layer 3, the authoritative layer) — it is not an automatic ban list. Sorted by
/// flagged-file count, worst first.
///
/// GET /api/publishers?min_flagged=1&max_files=200
/// Health surface: listening ports, filter data files, recent warnings.
///
/// Exists because the server is normally run with logging turned down or off
/// (the volume is large and disk is not), which otherwise leaves no way to see
/// that a UDP socket never bound or that a blocklist failed to parse. Everything
/// here is computed on demand — nothing is tracked in the hot path.
/// Filter review export — the input for a human/AI false-positive audit.
///
/// Two design choices make this cheap to read where /api/publishers was not:
///
/// * **Grouped by CAUSE, not by publisher.** A false-positive verdict is a
///   property of the term that fired, not of each file it caught: judging
///   "brosis" once settles all 32 of its hits. A few dozen causes replace
///   thousands of filenames.
/// * **L3 hits are counted, not listed.** A hash-blocklist hit is a decision made
///   earlier; re-reading the filename proves nothing and actively misleads —
///   known material is routinely republished under innocent names (a blocked hash
///   turned up as "Tchaikovsky 1813 Overture" and as an MS-Office archive). Those
///   names must not be mistaken for filter mistakes.
///
/// Window: everything caught since the previous export (watermark), falling back
/// to 24h on the first call. `?hours=N` overrides, `?all=1` ignores the window,
/// `?peek=1` reports without advancing the watermark.
///
/// `?format=csv` dumps every entry with no example caps — that is the
/// machine-readable side, used to turn per-cause verdicts into blocklist /
/// whitelist / poison hash files. Columns:
/// `hash;layer;reason;size;sizeflag;names;unrelated;name`, where `sizeflag` is
/// "!" when the extension cannot hold a file that large, `names` counts the
/// distinct names the hash was offered under, and `unrelated` how many of those
/// share no significant word with the first. `name` is last because it is the
/// only field that can contain arbitrary bytes.
async fn api_review(State(s): State<WebState>, uri: axum::http::Uri) -> impl IntoResponse {
    let qs = uri.query().unwrap_or("");
    let param = |key: &str| -> Option<&str> {
        qs.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            if k == key {
                Some(v)
            } else {
                None
            }
        })
    };
    let flag = |key: &str| matches!(param(key), Some("1") | Some("true"));
    let csv = matches!(param("format"), Some("csv"));
    let max_examples: usize = param("max_examples")
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);

    // Resolve the window.
    let now = std::time::Instant::now();
    let since: Option<std::time::Instant> = if flag("all") {
        None
    } else if let Some(h) = param("hours").and_then(|v| v.parse::<u64>().ok()) {
        now.checked_sub(std::time::Duration::from_secs(h * 3600))
    } else {
        let wm = s.server.review_watermark.lock().ok().and_then(|g| *g);
        match wm {
            Some(t) => Some(t),
            // First ever call: default to 24h rather than the whole retention
            // period, so the first export is not disproportionately large.
            None => now.checked_sub(std::time::Duration::from_secs(24 * 3600)),
        }
    };
    let window_desc = if flag("all") {
        "all retained".to_string()
    } else if let Some(h) = param("hours") {
        format!("last {h}h")
    } else if s
        .server
        .review_watermark
        .lock()
        .ok()
        .and_then(|g| *g)
        .is_some()
    {
        "since previous export".to_string()
    } else {
        "last 24h (first export)".to_string()
    };

    // Collect, de-duplicated by file hash: the same file caught from several
    // publishers is ONE decision to review.
    // Value is the first catch PLUS every distinct name the hash was offered
    // under. The names were always there — one record per publisher — and were
    // being thrown away by keeping only the first. Collecting them costs nothing
    // on the publish path and is the only view of decoys we can have: a blocked
    // file never reaches `add_file_with_source`, so the alias table is
    // structurally blind to exactly the hashes under review here.
    let mut by_hash: std::collections::HashMap<[u8; 16], (crate::state::CsamCatch, Vec<String>)> =
        std::collections::HashMap::new();
    for e in s.server.csam_files_by_user.iter() {
        for (h, c) in e.value().0.iter() {
            if let Some(cutoff) = since {
                if c.at < cutoff {
                    continue;
                }
            }
            let slot = by_hash.entry(*h).or_insert_with(|| (c.clone(), Vec::new()));
            if !slot.1.iter().any(|n| n == &c.name) {
                slot.1.push(c.name.clone());
            }
        }
    }

    if csv {
        // `size` and `sizeflag` exist so the masquerade test can be done by
        // sorting a column instead of opening each file in a client. `sizeflag`
        // is "!" when the extension cannot hold a file that large. `name` stays
        // LAST: it is the only field that can contain arbitrary bytes, so a
        // stray separator can never shift another column.
        let mut out = String::from("hash;layer;reason;size;sizeflag;names;unrelated;name\n");
        for (h, (c, names)) in &by_hash {
            // ';' cannot appear in the fields we emit except possibly the name.
            let name = c.name.replace(';', ",");
            let flag = if size_contradicts_extension(&c.name, c.size) {
                "!"
            } else {
                ""
            };
            out.push_str(&format!(
                "{};{:?};{};{};{};{};{};{}\n",
                hex::encode(h),
                c.layer,
                c.reason,
                c.size,
                flag,
                names.len(),
                unrelated_name_count(names),
                name
            ));
        }
        if !flag("peek") {
            if let Ok(mut g) = s.server.review_watermark.lock() {
                *g = Some(now);
            }
        }
        return ([("content-type", "text/plain; charset=utf-8")], out);
    }

    // Group by (layer, reason). L3 is tallied separately.
    let mut groups: std::collections::HashMap<(String, String), Vec<([u8; 16], String, u64)>> =
        std::collections::HashMap::new();
    let mut l3_count = 0usize;
    // Blocklisted hashes that look like decoys rather than material: several
    // names with nothing in common, or a size the extension cannot hold. These
    // are the candidates to MOVE from the CSAM list to the poisoned-index list.
    let mut decoys: Vec<([u8; 16], String, u64, usize, usize)> = Vec::new();
    for (h, (c, names)) in &by_hash {
        if c.layer == crate::filter::Layer::L3HashBlock {
            l3_count += 1;
            let unrelated = unrelated_name_count(names);
            if unrelated > 0 || size_contradicts_extension(&c.name, c.size) {
                decoys.push((*h, c.name.clone(), c.size, names.len(), unrelated));
            }
            continue;
        }
        groups
            .entry((format!("{:?}", c.layer), c.reason.clone()))
            .or_default()
            .push((*h, c.name.clone(), c.size));
    }

    let mut keys: Vec<_> = groups.keys().cloned().collect();
    // Largest groups first: those decide the most files per verdict.
    keys.sort_by_key(|k| std::cmp::Reverse(groups[k].len()));

    let mut out = String::new();
    out.push_str(&format!(
        "# ed2k-server filter review\n# window: {}\n# blocks in window: {} unique hashes\n",
        window_desc,
        by_hash.len()
    ));
    out.push_str(&format!(
        "# L3 hash-blocklist hits: {l3_count} (already-decided; NOT listed — known \
         material is republished under innocent names, so these filenames must not \
         be read as filter mistakes)\n"
    ));
    out.push_str(&format!(
        "# causes to review: {} (verdict per cause applies to all its files)\n\
         # names truncated to 120 chars; up to {} examples per cause\n\
         # per file: size in MB, then [!] if the extension cannot hold that size\n\n",
        keys.len(),
        max_examples
    ));

    for k in keys {
        let items = &groups[&k];
        out.push_str(&format!(
            "=== {} | {} | {} files ===\n",
            k.0,
            k.1,
            items.len()
        ));
        for (h, name, size) in items.iter().take(max_examples) {
            let short: String = name.chars().take(120).collect();
            // Size inline, and "[!]" when the extension cannot hold it. A cause
            // whose files are all the same implausible size is a decoy swarm, not
            // a filter question — visible at a glance, without opening the CSV.
            let flag = if size_contradicts_extension(name, *size) {
                " [!]"
            } else {
                ""
            };
            out.push_str(&format!(
                "{} {:>6} MB{} {}\n",
                &hex::encode(h)[..8],
                *size / 1048576,
                flag,
                short
            ));
        }
        if items.len() > max_examples {
            out.push_str(&format!("... +{} more\n", items.len() - max_examples));
        }
        out.push('\n');
    }

    // ── Blocklisted hashes that look like decoys ─────────────────────────
    //
    // The hash blocklist accumulates by hand, and a decoy caught once under a
    // CSAM-flavoured name ends up in it permanently. From then on it is blocked
    // as CSAM under every innocent name it also carries, and — worse — every
    // ordinary user who downloaded the decoy is counted toward a publisher ban.
    //
    // The two tells here are the ones a human uses: names that share no word,
    // and a size the extension cannot hold. Neither is a verdict. Both are
    // reasons to look, and a confirmed decoy belongs in the poisoned-index list,
    // where it is still blocked but no longer accuses anyone.
    if !decoys.is_empty() {
        decoys.sort_by_key(|d| std::cmp::Reverse((d.4, d.3)));
        out.push_str(&format!(
            "=== BLOCKLISTED HASHES THAT LOOK LIKE DECOYS ({} of {} L3 hits) ===\n\
             # Candidates to MOVE from hash_banlist.txt to hash_filter.txt.\n\
             # Verify before moving: a real file republished under a cover name\n\
             # produces the same signature.\n\n",
            decoys.len(),
            l3_count
        ));
        for (h, name, size, total, unrelated) in decoys.iter().take(60) {
            let short: String = name.chars().take(120).collect();
            let flag = if size_contradicts_extension(name, *size) {
                " [!]"
            } else {
                ""
            };
            out.push_str(&format!(
                "{} {} names ({} unrelated), {} MB{}\n    {}\n",
                hex::encode(h),
                total,
                unrelated,
                size / 1048576,
                flag,
                short
            ));
        }
        if decoys.len() > 60 {
            out.push_str(&format!("... +{} more\n", decoys.len() - 60));
        }
        out.push('\n');
    }

    // ── Files circulating under several names ────────────────────────────
    //
    // Independent of the filters: this catches material that no term list can
    // see, because the giveaway is not in any single name but in the fact that
    // one file carries many unrelated ones. Sorted by name count — the more
    // names, the stronger the signal.
    // How many of the names share NO word with the first one.
    //
    // This is what separates the two reasons a file carries several names. A
    // release renamed by different users keeps its subject: "American Beauty
    // (Sam Mendes, 1999).mkv" and "American.Beauty.1999.BDrip.mkv" still share
    // "american"/"beauty"/"1999". Masquerading does not: one 698 MB file was
    // published as "Magma Tittenshow", "Marc Dorcel 6 Bourgeoises" AND "Joe
    // Cocker - Discography.rar", which have nothing in common.
    //
    // Computed here rather than on the publish path — it only runs over the
    // tracked set when a report is requested.
    let mut aliases: Vec<_> = s
        .server
        .file_aliases
        .iter()
        .map(|e| {
            let a = e.value().clone();
            let unrelated = unrelated_name_count(&a.names);
            (*e.key(), a, unrelated)
        })
        .collect();
    // Unrelated names first, then size: the strongest evidence at the top.
    aliases.sort_by_key(|(_, a, u)| (std::cmp::Reverse(*u), std::cmp::Reverse(a.size)));

    if !aliases.is_empty() {
        out.push_str(&format!(
            "\n=== FILES PUBLISHED UNDER MULTIPLE NAMES ({} tracked) ===\n\
             # Not a filter verdict — a lead. A file is only tracked once it appears\n\
             # under two names sharing NO word: a renamed release keeps its subject,\n\
             # a masqueraded file does not. Sorted by how many names are unrelated\n\
             # to the first. [!] marks a size that contradicts the extension (a\n\
             # 690 MB \"PDF\"). Size is given in exact bytes as well as MB — the\n\
             # rounded figure hides which files came from one generator; see the\n\
             # size-collision section that follows. Files under 2 MB are not\n\
             # tracked.\n\n",
            aliases.len()
        ));
        for (h, a, unrelated) in aliases.iter().take(60) {
            // A document/image extension on a huge file is its own red flag.
            let flag = if a
                .names
                .iter()
                .any(|n| size_contradicts_extension(n, a.size))
            {
                " [!]"
            } else {
                ""
            };
            // Exact byte count alongside the rounded MB. Rounding is what hides
            // the campaign signal: nine entries all printing "700 MB" may be
            // nine different files or one generator's output, and only the exact
            // figure tells them apart. See the size-collision section below.
            out.push_str(&format!(
                "{} {} names ({} unrelated), {:.0} MB / {} B{}\n",
                hex::encode(h),
                a.names.len(),
                unrelated,
                a.size as f64 / 1048576.0,
                a.size,
                flag
            ));
            for n in a.names.iter().take(6) {
                let short: String = n.chars().take(110).collect();
                out.push_str(&format!("    {short}\n"));
            }
            if a.names.len() > 6 {
                out.push_str(&format!("    ... +{} more\n", a.names.len() - 6));
            }
            out.push('\n');
        }

        // ── Distinct hashes of the SAME EXACT size ───────────────────────
        //
        // A decoy generator pads its output to a fixed target, so one campaign
        // produces many different hashes that are byte-for-byte the same length.
        // Genuine files do not collide that way: two unrelated rips landing on
        // the same byte count is a coincidence, a dozen of them is not.
        //
        // This is the discriminator that a SIZE BAND is not. Roughly 40% of the
        // tracked set sits between 680 and 714 MB, but that is just the CD era —
        // a real 700 MB rip is the most ordinary object on this network, so a
        // band flags mostly honest files. Exact equality does not.
        //
        // Grouping runs over every tracked alias, not the 60 printed above:
        // members of a campaign are individually unremarkable and would rank
        // nowhere near the top by unrelated-name count.
        let mut by_size: std::collections::HashMap<u64, Vec<([u8; 16], usize, usize)>> =
            std::collections::HashMap::new();
        for (h, a, unrelated) in &aliases {
            by_size
                .entry(a.size)
                .or_default()
                .push((*h, a.names.len(), *unrelated));
        }
        let mut campaigns: Vec<(u64, Vec<([u8; 16], usize, usize)>)> =
            by_size.into_iter().filter(|(_, v)| v.len() >= 2).collect();
        // Biggest cluster first — that is the one worth a bulk decision.
        campaigns.sort_by_key(|(size, v)| (std::cmp::Reverse(v.len()), std::cmp::Reverse(*size)));

        if !campaigns.is_empty() {
            let total: usize = campaigns.iter().map(|(_, v)| v.len()).sum();
            out.push_str(&format!(
                "=== SIZE COLLISIONS AMONG TRACKED FILES ({} hashes in {} groups) ===\n\
                 # Distinct hashes with an IDENTICAL byte count, each already\n\
                 # carrying unrelated names. That combination is a decoy campaign:\n\
                 # one generator, one padded target size, many fake hashes.\n\
                 # A whole group is normally one decision — candidates for the\n\
                 # poisoned-index list, NOT for the CSAM hash list.\n\
                 # Two members is weak evidence; ten is not. Judge by group size.\n\n",
                total,
                campaigns.len()
            ));
            for (size, members) in campaigns.iter().take(20) {
                out.push_str(&format!(
                    "--- {} B ({:.1} MB) — {} hashes ---\n",
                    size,
                    *size as f64 / 1048576.0,
                    members.len()
                ));
                for (h, names, unrelated) in members.iter().take(12) {
                    out.push_str(&format!(
                        "    {} {} names ({} unrelated)\n",
                        hex::encode(h),
                        names,
                        unrelated
                    ));
                }
                if members.len() > 12 {
                    out.push_str(&format!("    ... +{} more\n", members.len() - 12));
                }
                out.push('\n');
            }
            if campaigns.len() > 20 {
                out.push_str(&format!("... +{} more groups\n\n", campaigns.len() - 20));
            }
        }
    }

    // Advance the watermark only after a successful build, and only if the caller
    // did not ask to peek — otherwise a failed download would silently skip a
    // day's worth of blocks.
    if !flag("peek") {
        if let Ok(mut g) = s.server.review_watermark.lock() {
            *g = Some(now);
        }
    }
    ([("content-type", "text/plain; charset=utf-8")], out)
}

/// Admission gauges and counters (issue #25).
async fn api_admission(State(s): State<WebState>) -> Json<serde_json::Value> {
    Json(s.server.admission.metrics())
}

/// Readiness, distinct from /api/health: 503 once a critical admission pool
/// has stayed full for `admission.readiness_window_secs`. Liveness is simply
/// that this answers at all.
async fn api_ready(State(s): State<WebState>) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    let (ready, saturated) = s.server.admission.readiness();
    let code = if ready {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        Json(serde_json::json!({ "ready": ready, "saturated": saturated })),
    )
}

async fn api_health(State(s): State<WebState>) -> Json<serde_json::Value> {
    let tcp = s.config.network.tcp_port;

    // ── ports ────────────────────────────────────────────────────────────
    // UDP: a socket that bound successfully is registered in `udp_sockets`, so
    // presence there IS the health signal. The expected set is protocol-fixed
    // relative to the TCP port.
    let expected_udp = [
        (tcp.wrapping_add(4), "main UDP (TCP+4)"),
        (tcp.wrapping_add(8), "aux UDP (TCP+8)"),
        (tcp.wrapping_add(12), "server-to-server obf ping (TCP+12)"),
        (tcp.wrapping_add(14), "portUDPobf (TCP+14)"),
    ];
    let mut ports: Vec<serde_json::Value> = Vec::new();

    // TCP: probe it for real. A bound-but-wedged listener would still accept,
    // which is exactly what we want to verify from the outside.
    let tcp_ok = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        tokio::net::TcpStream::connect(("127.0.0.1", tcp)),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false);
    ports.push(serde_json::json!({
        "proto": "tcp", "port": tcp, "role": "client TCP", "ok": tcp_ok,
        "detail": if tcp_ok { "accepting connections" } else { "connect failed" },
    }));

    for (port, role) in expected_udp {
        let bound = s.server.udp_sockets.contains_key(&port);
        ports.push(serde_json::json!({
            "proto": "udp", "port": port, "role": role, "ok": bound,
            "detail": if bound { "bound" } else { "NOT bound — check for a port conflict at startup" },
        }));
    }

    // ── filter data files ────────────────────────────────────────────────
    // `entries` is the count actually held in memory after parsing, so a file
    // that exists but parsed to nothing is visible as entries = 0. Per-line
    // parse errors are reported through the log ring below (the loaders already
    // warn! with file and line number).
    fn file_stat(path: &str) -> (bool, u64, u64) {
        match std::fs::metadata(path) {
            Ok(m) => {
                let age = m
                    .modified()
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                (true, m.len(), age)
            }
            Err(_) => (false, 0, 0),
        }
    }

    let mut files: Vec<serde_json::Value> = Vec::new();
    let push_file =
        |label: &str, path: &str, entries: Option<u64>, files: &mut Vec<serde_json::Value>| {
            if path.is_empty() {
                return;
            }
            let (exists, size, age) = file_stat(path);
            files.push(serde_json::json!({
                "label": label,
                "path": path,
                "exists": exists,
                "entries": entries,
                "size_bytes": size,
                "modified_secs_ago": age,
                "ok": exists && entries.map(|e| e > 0).unwrap_or(true),
            }));
        };

    let cf = &s.config.content_filter;
    let blocklist_total = s.server.filter.blocklist_size() as u64;
    for (i, p) in cf.hash_banlist.iter().enumerate() {
        // The loader merges every blocklist into one set, so the count is
        // reported once (on the first file) rather than duplicated per file.
        let n = if i == 0 { Some(blocklist_total) } else { None };
        push_file("hash banlist (L3)", p, n, &mut files);
    }
    let filter_total = s.server.filter.hash_filter_size() as u64;
    for (i, p) in cf.hash_filter.iter().enumerate() {
        // Same merge-into-one-set reporting as the blocklist above.
        let n = if i == 0 { Some(filter_total) } else { None };
        push_file("filter list (L5)", p, n, &mut files);
    }
    if let Some(p) = &cf.extra_terms_file {
        push_file(
            "extra terms (L4)",
            p,
            Some(s.server.filter.extra_terms_count() as u64),
            &mut files,
        );
    }
    if let Some(p) = &cf.jargon_terms_file {
        push_file(
            "jargon terms (L1)",
            p,
            Some(s.server.filter.jargon_terms_count() as u64),
            &mut files,
        );
    }
    if let Some(p) = &cf.layer2_terms_file {
        // Reported like the term files, though it is not one: the count is every
        // entry across all twelve of its sections. Worth having on this page
        // precisely because the file can be edited live — if a reload was
        // rejected, the count here still shows the vocabulary actually in force,
        // and the log below says why the new one was refused.
        push_file(
            "L2 vocabulary",
            p,
            Some(s.server.filter.layer2_terms_size() as u64),
            &mut files,
        );
    }
    if let Some(p) = &cf.whitelist_hashes_file {
        push_file(
            "hash whitelist",
            p,
            Some(s.server.filter.whitelist_size() as u64),
            &mut files,
        );
    }
    let ipf = s.server.ip_filter.read().await.len() as u64;
    push_file(
        "IP filter",
        &s.config.storage.ipfilter_path,
        Some(ipf),
        &mut files,
    );
    let geo = s.server.country_db.read().await.range_count() as u64;
    push_file(
        "GeoIP database",
        &s.config.storage.country_db_path,
        Some(geo),
        &mut files,
    );

    // ── recent warnings/errors ───────────────────────────────────────────
    let entries = crate::health::ring().snapshot(100);
    let total_seen = crate::health::ring().total_seen();

    Json(serde_json::json!({
        "ports": ports,
        "files": files,
        "log": { "total_seen": total_seen, "shown": entries.len(), "entries": entries },
    }))
}

async fn api_publishers(
    State(s): State<WebState>,
    uri: axum::http::Uri,
) -> Json<serde_json::Value> {
    // Query string parsed by hand: axum's `Query` extractor sits behind the
    // optional "query" feature, which this build does not enable, and pulling it
    // in just for two optional numbers is not worth the dependency change.
    let qs = uri.query().unwrap_or("");
    let param = |key: &str| -> Option<&str> {
        qs.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            if k == key {
                Some(v)
            } else {
                None
            }
        })
    };
    let min_flagged: usize = param("min_flagged")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    // Cap per-publisher file listings so one prolific account cannot produce a
    // multi-megabyte response.
    let max_files: usize = param("max_files")
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    // flagged_only=1 → return, per publisher, ONLY the files that actually tripped
    // the filter (resolved to their names), and skip the rest of their library.
    // This is the QA view: exactly the handful of files that caused each ban, so a
    // human can confirm the filter did not misfire. Small and bounded (≤ threshold
    // files per publisher), unlike the full library dump.
    let flagged_only: bool = matches!(param("flagged_only"), Some("1") | Some("true"));
    // Only report files caught within this window. Defaults to 24 h because the
    // records live for `publisher_blacklist_seconds` (30 days by default), so an
    // unfiltered export grows every day the server stays up. Pass 0 for "all".
    let max_age_hours: u64 = param("max_age_hours")
        .and_then(|v| v.parse().ok())
        .unwrap_or(24);
    let max_age = std::time::Duration::from_secs(max_age_hours.saturating_mul(3600));

    let mut out: Vec<serde_json::Value> = Vec::new();

    for e in s.server.csam_files_by_user.iter() {
        let user_hash = *e.key();
        let (flagged_map, last_seen) = e.value();
        if flagged_map.len() < min_flagged {
            continue;
        }

        // Resolve each FLAGGED hash to its filename via the slab. A file may have
        // been evicted after the ban (no sources left), in which case the name is
        // gone — reported as null so the reviewer knows it existed but is no longer
        // resolvable.
        // Name comes from the catch-time record, so it survives eviction. We also
        // report whether the file is still live in the index (has sources) — a
        // reviewer wants to know if it is still being served right now.
        // Files caught inside the window (all of them when max_age_hours = 0).
        let recent: Vec<_> = flagged_map
            .iter()
            .filter(|(_, c)| max_age_hours == 0 || c.at.elapsed() <= max_age)
            .collect();
        if recent.is_empty() {
            continue; // nothing recent from this publisher — skip it entirely
        }
        let recent_count = recent.len();

        let flagged_detail: Vec<serde_json::Value> = recent
            .into_iter()
            .map(|(h, c)| {
                let still_live = s
                    .server
                    .file_slab
                    .id_of(h)
                    .and_then(|id| s.server.file_slab.get(id))
                    .map(|rec| rec.sources.len());
                serde_json::json!({
                    "hash": hex::encode(h),
                    "name": c.name,
                    // Why it was blocked — the same reason /api/review groups by.
                    "layer": format!("{:?}", c.layer),
                    "reason": c.reason,
                    "caught_secs_ago": c.at.elapsed().as_secs(),
                    "still_live": still_live.is_some(),
                    "sources": still_live.unwrap_or(0),
                })
            })
            .collect();

        // In flagged_only mode skip the (potentially huge) full-library resolve.
        let mut published: Vec<serde_json::Value> = Vec::new();
        let mut published_total = 0usize;
        if !flagged_only {
            if let Some(files) = s.server.user_files.get(&user_hash) {
                published_total = files.len();
                for fid in files.iter().take(max_files) {
                    if let Some(rec) = s.server.file_slab.get(*fid) {
                        published.push(serde_json::json!({
                            "hash": hex::encode(rec.hash),
                            "name": rec.name(),
                            "size": rec.size,
                            "sources": rec.sources.len(),
                            // true = this exact file already tripped the filter
                            "flagged": flagged_map.contains_key(&rec.hash),
                        }));
                    }
                }
            }
        }

        let mut entry = serde_json::json!({
            "user_hash": hex::encode(user_hash),
            "flagged_files": recent_count,
            "flagged_files_total": flagged_map.len(),
            "flagged": flagged_detail,
            "banned": s.server.banned_publishers.contains_key(&user_hash),
            "last_flagged_secs_ago": last_seen.elapsed().as_secs(),
        });
        if !flagged_only {
            entry["published_now"] = serde_json::json!(published_total);
            entry["published_truncated"] = serde_json::json!(published_total > published.len());
            entry["published"] = serde_json::json!(published);
        }
        out.push(entry);
    }

    // Worst offenders first.
    out.sort_by(|a, b| {
        b["flagged_files"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["flagged_files"].as_u64().unwrap_or(0))
    });

    Json(serde_json::json!({
        "publishers": out.len(),
        "min_flagged": min_flagged,
        "results": out,
    }))
}

/// The stored "port answered with a DIFFERENT user hash" cases, for analysis
/// without turning logging on.
///
/// `?anonymize=1` replaces each IP with its /24 prefix plus a pseudonym that is
/// stable within this process (so repeats stay visible) but not reversible.
/// Use it for anything leaving the server: the IPs are other people's.
///
/// Every record is annotated with what can be learned NOW:
/// * whether the answering hash is connected to us, and from which address
///   (`same_ip` = a second client behind the same NAT holds the port);
/// * whether the answer is simply OUR OWN probe hash echoed back — a client or
///   mod that reflects the hello rather than a different machine;
/// * whether each hash carries eMule's marker bytes (index 5 = 0x0E,
///   index 14 = 0x6F), which other implementations do not set;
/// * the client software of whichever side is still connected.
async fn api_highid_mismatches(
    State(s): State<WebState>,
    axum::extract::RawQuery(q): axum::extract::RawQuery,
) -> Json<serde_json::Value> {
    use std::collections::HashMap;
    let anonymize = q
        .as_deref()
        .map(|q| {
            q.split('&')
                .any(|kv| kv == "anonymize=1" || kv == "anonymize=true")
        })
        .unwrap_or(false);

    let live = s.server.live_cfg.load();
    let our_probe_hash = crate::server::highid_probe::server_pseudo_user_hash(
        &crate::server::udp::resolve_seckey(&live),
    );

    let recent: Vec<crate::state::HighIdMismatch> = s
        .server
        .highid_observe
        .recent_mismatches
        .lock()
        .map(|q| q.iter().cloned().collect())
        .unwrap_or_default();

    // Pseudonyms: a salted hash, salt drawn once per process. Stable across
    // calls so two exports from one run can be compared, useless after restart.
    static SALT: once_cell::sync::Lazy<[u8; 16]> = once_cell::sync::Lazy::new(|| {
        let mut b = [0u8; 16];
        b.copy_from_slice(&crate::proto::obfuscation::random_bytes(16)[..16]);
        b
    });
    let show_ip = |ip: std::net::IpAddr| -> serde_json::Value {
        if !anonymize {
            return serde_json::json!(ip.to_string());
        }
        use md5::{Digest, Md5};
        let mut h = Md5::new();
        h.update(*SALT);
        h.update(ip.to_string().as_bytes());
        let tag = hex::encode(&h.finalize()[..4]);
        let prefix = match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("{}.{}.{}.x", o[0], o[1], o[2])
            }
            std::net::IpAddr::V6(_) => "v6".to_string(),
        };
        serde_json::json!(format!("{prefix}#{tag}"))
    };
    let emule_marker = |h: &[u8; 16]| h[5] == 0x0E && h[14] == 0x6F;

    let mut by_ip: HashMap<String, u64> = HashMap::new();
    let mut by_answered: HashMap<String, u64> = HashMap::new();
    let mut logins: std::collections::HashSet<[u8; 16]> = Default::default();
    let (mut same, mut other, mut none, mut echo) = (0u64, 0u64, 0u64, 0u64);
    let (mut login_marked, mut answered_marked) = (0u64, 0u64);
    let mut marked = 0u64;

    let mut records = Vec::with_capacity(recent.len());
    for m in &recent {
        let ip_shown = show_ip(m.ip);
        *by_ip
            .entry(ip_shown.as_str().unwrap_or("").to_string())
            .or_insert(0) += 1;
        *by_answered.entry(hex::encode(m.answered_hash)).or_insert(0) += 1;
        logins.insert(m.login_hash);

        let answered_now = s
            .server
            .clients
            .get(&m.answered_hash)
            .map(|c| (c.ip, c.software.clone()));
        let login_now = s
            .server
            .clients
            .get(&m.login_hash)
            .map(|c| (c.ip, c.software.clone()));
        let answered_status = match &answered_now {
            Some((ip, _)) if *ip == m.ip => {
                same += 1;
                "connected_same_ip"
            }
            Some(_) => {
                other += 1;
                "connected_other_ip"
            }
            None => {
                none += 1;
                "not_connected"
            }
        };
        let is_echo = m.answered_hash == our_probe_hash;
        if is_echo {
            echo += 1;
        }
        if emule_marker(&m.login_hash) {
            login_marked += 1;
        }
        if emule_marker(&m.answered_hash) {
            answered_marked += 1;
        }
        if m.marked {
            marked += 1;
        }
        records.push(serde_json::json!({
            "at": chrono::DateTime::from_timestamp(m.at as i64, 0).map(|d| d.to_rfc3339()),
            "ip": ip_shown,
            "port": m.port,
            "marked": m.marked,
            "login_hash": hex::encode(m.login_hash),
            "answered_hash": hex::encode(m.answered_hash),
            "answered_is_our_probe_hash": is_echo,
            "login_hash_emule_marker": emule_marker(&m.login_hash),
            "answered_hash_emule_marker": emule_marker(&m.answered_hash),
            "answered_client_now": answered_status,
            "answered_client_software": answered_now.map(|(_, sw)| sw),
            "login_client_still_connected": login_now.is_some(),
            "login_client_software": login_now.map(|(_, sw)| sw),
        }));
    }

    let top = |m: HashMap<String, u64>| -> Vec<serde_json::Value> {
        let mut v: Vec<(String, u64)> = m.into_iter().filter(|(_, n)| *n > 1).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(20);
        v.into_iter()
            .map(|(k, n)| serde_json::json!({ "key": k, "count": n }))
            .collect()
    };
    let distinct_ips = by_ip.len();
    let distinct_answered = by_answered.len();

    Json(serde_json::json!({
        "anonymized": anonymize,
        "our_probe_hash": hex::encode(our_probe_hash),
        "total_since_start": s.server.highid_observe.mismatch.load(Ordering::Relaxed),
        "lowid_logins_by_mark_since_start": s.server.highid_observe.downgraded.load(Ordering::Relaxed),
        "marks_active": s.server.highid_observe.marks_active(),
        "marks_cleared_since_start": s.server.highid_observe.marks_cleared.load(Ordering::Relaxed),
        "downgrade_on_wrong_hash": live.network.highid_downgrade_on_wrong_hash,
        "summary": {
            "records": recent.len(),
            "marked": marked,
            "buffer_capacity": crate::state::HighIdObserve::RECENT_MISMATCHES,
            "distinct_ips": distinct_ips,
            "distinct_login_hashes": logins.len(),
            "distinct_answered_hashes": distinct_answered,
            "answered_is_our_probe_hash": echo,
            "answered_client_connected_same_ip": same,
            "answered_client_connected_other_ip": other,
            "answered_client_not_connected": none,
            "login_hash_has_emule_marker": login_marked,
            "answered_hash_has_emule_marker": answered_marked,
            "repeated_ips": top(by_ip),
            "repeated_answered_hashes": top(by_answered),
        },
        "records": records,
    }))
}

async fn api_memsize(State(s): State<WebState>) -> Json<serde_json::Value> {
    // Per-container byte breakdown by CAPACITY (see ServerState::memsize_report).
    // Keys ending in _TOTAL are subtotals of the lines above them; GRAND_TOTAL_tracked
    // sums the subtotals. `unaccounted_bytes` is what jemalloc holds beyond that:
    // size-class rounding, DashMap per-shard control state, Arc/Box control blocks,
    // tokio socket buffers and per-thread allocator caches.
    // Walks every file record: on the blocking pool, not a runtime worker —
    // with the default single worker thread it would stall all networking.
    let srv = Arc::clone(&s.server);
    let report = tokio::task::spawn_blocking(move || srv.memsize_report())
        .await
        .unwrap_or_default();
    let tracked: u64 = report
        .iter()
        .find(|(k, _)| k == "GRAND_TOTAL_tracked")
        .map(|(_, v)| *v)
        .unwrap_or(0);
    let sizes: serde_json::Map<String, serde_json::Value> = report
        .into_iter()
        .map(|(k, v)| (k, serde_json::json!(v)))
        .collect();
    let allocated = jemalloc_allocated().unwrap_or(0);
    Json(serde_json::json!({
        // Which tokenisation built this index. Recorded in the reading itself so
        // a before/after comparison cannot mix up which snapshot was which — the
        // flag is only read at startup, and nothing else in this JSON reveals it.
        "index_subtokens": s.server.keyword_index.subtokens_enabled(),
        "sizes_bytes": sizes,
        "tracked_total_bytes": tracked,
        "jemalloc_allocated_bytes": allocated,
        "unaccounted_bytes": allocated.saturating_sub(tracked),
        // Element counts for the same structures, so bytes-per-element can be
        // derived directly (capacity vs live shows the peak-plateau slack).
        "counts": {
            "files": s.server.file_count(),
            "slab_slots": s.server.file_slab.slot_count(),
            "keyword_keys": s.server.keyword_index.posting_stats().0,
            "keyword_cold_keys": s.server.keyword_index.tier_sizes().0,
            "keyword_hot_keys": s.server.keyword_index.tier_sizes().1,
            "keyword_pending_removal_keys": s.server.keyword_index.tier_sizes().2,
            "alias_tracked_files": s.server.file_aliases.len(),
            "keyword_postings": s.server.keyword_index.posting_stats().1,
            // Always 0 since the dedup table was removed; kept so the JSON
            // shape does not change under a monitoring script.
            "unique_names": s.server.name_interner.len(),
            "clients": s.server.clients.len(),
            "user_files_users": s.server.user_files.len(),
            "smart_sources_entries": s.server.smart_sources.entry_count(),
            "ipfilter_ranges": s.server.ip_filter.try_read().map(|f| f.len()).unwrap_or(0),
            "geoip_ranges": s.server.country_db.try_read().map(|d| d.range_count()).unwrap_or(0),
        },
    }))
}

async fn api_memdebug(State(s): State<WebState>) -> Json<serde_json::Value> {
    // Structure element counts (what logically holds memory).
    // Off the runtime, for the same reason as /api/memsize.
    let srv = Arc::clone(&s.server);
    let report = tokio::task::spawn_blocking(move || srv.memory_report())
        .await
        .unwrap_or_default();
    // Raw /proc/self/status memory lines (what the OS actually accounts).
    let mut proc_mem: Vec<(String, String)> = Vec::new();
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("Vm") || line.starts_with("Rss") {
                if let Some((k, v)) = line.split_once(':') {
                    proc_mem.push((k.trim().to_string(), v.trim().to_string()));
                }
            }
        }
    }
    let structures: serde_json::Map<String, serde_json::Value> = report
        .into_iter()
        .map(|(k, v)| (k, serde_json::json!(v)))
        .collect();
    let procm: serde_json::Map<String, serde_json::Value> = proc_mem
        .into_iter()
        .map(|(k, v)| (k, serde_json::json!(v)))
        .collect();
    Json(serde_json::json!({
        "structures": structures,
        "proc_status": procm,
        "jemalloc": jemalloc_stats(),
    }))
}

/// jemalloc internal stats, to distinguish real app data from fragmentation:
/// - `allocated`: bytes the app actually holds (live data)
/// - `active`/`resident`: pages backing allocations / physically resident
/// - `retained`: virtual memory kept (not resident, reusable)
/// - `metadata`: allocator bookkeeping
/// `resident - allocated` ≈ fragmentation + cached free pages. If that gap is
/// large while `allocated` is small, RSS growth is allocator retention
/// (plateaus / tunable via decay), not real structural growth (tombstones, etc.).
#[cfg(not(target_env = "msvc"))]
fn jemalloc_stats() -> serde_json::Value {
    use tikv_jemalloc_ctl::{epoch, stats};
    // stats are cached; advancing the epoch refreshes them.
    if epoch::advance().is_err() {
        return serde_json::Value::Null;
    }
    let rd = |r: Result<usize, _>| r.map(|v| v as u64).unwrap_or(0);
    serde_json::json!({
        "allocated": rd(stats::allocated::read()),
        "active": rd(stats::active::read()),
        "metadata": rd(stats::metadata::read()),
        "resident": rd(stats::resident::read()),
        "retained": rd(stats::retained::read()),
    })
}

#[cfg(target_env = "msvc")]
fn jemalloc_stats() -> serde_json::Value {
    serde_json::Value::Null
}

/// Just the jemalloc `allocated` figure (bytes the app actually holds, with no
/// reusable free pages) — the "non-evictable" working set. None when jemalloc is
/// not the allocator (msvc). Surfaced in the status card so the operator sees the
/// real in-use memory next to RSS (which also counts lazily-freed pages).
#[cfg(not(target_env = "msvc"))]
fn jemalloc_allocated() -> Option<u64> {
    use tikv_jemalloc_ctl::{epoch, stats};
    if epoch::advance().is_err() {
        return None;
    }
    stats::allocated::read().ok().map(|v| v as u64)
}

#[cfg(target_env = "msvc")]
fn jemalloc_allocated() -> Option<u64> {
    None
}

async fn api_block_stats(State(s): State<WebState>) -> Json<Vec<BlockStatRow>> {
    let mut rows: Vec<BlockStatRow> = s
        .server
        .block_stats
        .iter()
        .map(|e| {
            let reason = e.key().clone();
            // For CSAM: also report distinct IPs blocked (one user can publish many files).
            let unique_ips = if reason == "csam" {
                Some(s.server.csam_unique_ips.len() as u64)
            } else {
                None
            };
            BlockStatRow {
                reason,
                count: *e.value(),
                unique_ips,
            }
        })
        .collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count));
    Json(rows)
}

/// Single-page dashboard. Plain HTML + a tiny bit of JS — no build step.
/// The page is compiled into the binary, so a browser must not keep an old
/// copy across an upgrade: an old page against a new API shows stale tabs
/// (seen after 0.9.77: no search box, no peer names, letters for flags
/// until the cache was cleared). `no-cache` makes it revalidate every load.
async fn dashboard() -> impl IntoResponse {
    (
        [(axum::http::header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")],
        Html(DASHBOARD_HTML),
    )
}

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ed2k-server admin</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
@font-face{font-family:"Twemoji Country Flags";unicode-range:U+1F1E6-1F1FF,U+1F3F4,U+E0062-E0063,U+E0065,U+E0067,U+E006C,U+E006E,U+E0073-E0074,U+E0077,U+E007F;src:url('/assets/flags.woff2') format('woff2');font-display:swap}
body{font-family:"Twemoji Country Flags",system-ui,-apple-system,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh}
header{background:#1a1d27;border-bottom:1px solid #2d3148;padding:14px 24px;display:flex;align-items:center;gap:12px}
header h1{font-size:1.1rem;font-weight:600;color:#fff}
header .ver{font-size:.75rem;color:#6b7280;margin-left:auto}
nav{background:#13151f;border-bottom:1px solid #252840;display:flex;gap:0;overflow-x:auto}
nav button{background:none;border:none;color:#9ca3af;padding:12px 20px;cursor:pointer;font-size:.85rem;border-bottom:2px solid transparent;white-space:nowrap}
nav button.active{color:#6366f1;border-bottom-color:#6366f1}
nav button:hover{color:#c7d2fe}
.tab{display:none;padding:20px}.tab.active{display:block}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;margin-bottom:20px}
.card{background:#1a1d27;border:1px solid #252840;border-radius:8px;padding:16px}
.card .lbl{font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;color:#6b7280;margin-bottom:4px}
.card .val{font-size:1.5rem;font-weight:700;color:#a5b4fc}
.card .sub{font-size:.75rem;color:#6b7280;margin-top:2px}
.section{background:#1a1d27;border:1px solid #252840;border-radius:8px;padding:16px;margin-bottom:16px}
.section h3{font-size:.85rem;font-weight:600;color:#9ca3af;margin-bottom:12px;text-transform:uppercase;letter-spacing:.05em}
table{width:100%;border-collapse:collapse;font-size:.82rem}
th{text-align:left;padding:7px 10px;color:#6b7280;border-bottom:1px solid #252840;font-weight:500;font-size:.75rem;text-transform:uppercase}
td{padding:7px 10px;border-bottom:1px solid #1e2035;color:#cbd5e1}
tr:hover td{background:#1e2035}
.badge{display:inline-block;padding:2px 8px;border-radius:9999px;font-size:.7rem;font-weight:600}
.badge.yes{background:#1e3a2f;color:#4ade80}.badge.no{background:#3b1f1f;color:#f87171}
.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.72rem;background:#252840;color:#a5b4fc;margin:2px}
.bar-wrap{display:flex;align-items:center;gap:8px}
.bar{height:8px;border-radius:4px;background:#6366f1;min-width:2px;transition:width .3s}
.bar-label{font-size:.72rem;color:#9ca3af;min-width:40px;text-align:right}
.flag{font-size:1.1rem;margin-right:4px}
#refreshed{font-size:.72rem;color:#4b5563;margin-top:10px;text-align:right}
.reload-btn{background:#252840;color:#a5b4fc;border:1px solid #6366f1;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:.83rem}
.reload-btn:hover{background:#2d3060}
#reload-out{font-size:.82rem;color:#6b7280;margin-top:8px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:640px){.grid2{grid-template-columns:1fr}}
.empty{color:#4b5563;font-size:.83rem;padding:12px 0}
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
.filters input,.filters select{background:#0f1117;color:#e2e8f0;border:1px solid #2d3148;border-radius:6px;padding:7px 10px;font-size:.82rem;font-family:inherit}
.filters input[type=search]{min-width:260px;flex:1 1 260px}
.filters button{background:#252840;color:#a5b4fc;border:1px solid #2d3148;border-radius:6px;padding:7px 12px;cursor:pointer;font-size:.8rem}
.filters button:disabled{opacity:.4;cursor:default}
.filters .count{font-size:.78rem;color:#9ca3af;margin-left:auto}
.sub{color:#6b7280;font-size:.75rem}
</style>
</head>
<body>
<header>
  <span>🖥</span>
  <h1>ed2k-server</h1>
  <div class="ver" id="hdr-ver">loading...</div>
  <form id="logout" method="post" action="/logout" style="display:none;margin-left:auto">
    <button type="submit" style="background:none;border:1px solid #4b5563;color:#9ca3af;border-radius:4px;padding:2px 10px;cursor:pointer">Log out</button>
  </form>
</header>
<nav>
  <button class="active" onclick="showTab('status',this)">Status</button>
  <button onclick="showTab('clients',this)">Clients</button>
  <button onclick="showTab('peers',this)">Peers</button>
  <button onclick="showTab('filter',this)">Filter</button>
  <button onclick="showTab('bots',this)">Bots</button>
  <button onclick="showTab('blocks',this)">Blocks</button>
  <button onclick="showTab('health',this)">Health</button>
  <button onclick="showTab('settings',this)">Settings</button>
</nav>

<!-- STATUS TAB -->
<div id="tab-status" class="tab active">
  <div class="cards" id="cards"></div>
  <div class="section">
    <h3>System</h3>
    <div id="sys-info"></div>
  </div>
</div>

<!-- CLIENTS TAB -->
<div id="tab-clients" class="tab">
  <div class="grid2">
    <div class="section">
      <h3>Client Software</h3>
      <div id="sw-chart"></div>
    </div>
    <div class="section">
      <h3>Country Distribution</h3>
      <div id="country-chart"></div>
    </div>
  </div>
  <div class="section">
    <h3>Connected Now</h3>
    <div class="filters">
      <input type="search" id="cf-q" placeholder="IP, 82.48.0.0/16, nick, IPv6…" oninput="clientsFilterChanged()">
      <select id="cf-country" onchange="clientsFilterChanged()"><option value="">all countries</option></select>
      <select id="cf-software" onchange="clientsFilterChanged()"><option value="">all software</option></select>
      <select id="cf-id" onchange="clientsFilterChanged()"><option value="">High + Low</option><option value="high">HighID</option><option value="low">LowID</option></select>
      <select id="cf-sort" onchange="clientsFilterChanged()">
        <option value="connected">sort: connected time</option><option value="files">sort: files</option>
        <option value="ip">sort: IP</option><option value="nick">sort: nick</option>
        <option value="country">sort: country</option><option value="software">sort: software</option>
      </select>
      <select id="cf-dir" onchange="clientsFilterChanged()"><option value="desc">↓ desc</option><option value="asc">↑ asc</option></select>
      <button id="cf-prev" onclick="clientsPage(-1)">‹ prev</button>
      <button id="cf-next" onclick="clientsPage(1)">next ›</button>
      <span class="count" id="cf-count"></span>
    </div>
    <div id="clients-table"></div>
  </div>
</div>

<!-- PEERS TAB -->
<div id="tab-peers" class="tab">
  <div class="section">
    <h3>Gossip Peer Servers</h3>
    <div id="peers-table"></div>
  </div>
</div>

<!-- FILTER TAB -->
<div id="tab-filter" class="tab">
  <div class="section">
    <h3>IP Filter (guarding.p2p)</h3>
    <div id="filter-info"></div>
    <div style="margin-top:14px">
      <button class="reload-btn" onclick="doReload()">↺ Reload filters (SIGHUP)</button>
      <div id="reload-out"></div>
    </div>
  </div>
  <div class="section" style="margin-top:16px">
    <h3>Range Hit Statistics</h3>
    <p style="font-size:.82rem;color:#9ca3af;line-height:1.6">
      Per-range block counts since startup. Only ranges that actually blocked an
      IP are shown. Descriptions are read from the source file on demand (not kept
      in RAM), so this loads on click rather than auto-refreshing.
    </p>
    <button class="reload-btn" onclick="loadIpfilterHits()">↓ Load range hit stats</button>
    <div id="ipfilter-hits" style="margin-top:12px"></div>
  </div>
  <div class="section" style="margin-top:16px">
    <h3>About IP Filter</h3>
    <p style="font-size:.82rem;color:#9ca3af;line-height:1.6">
      Place <code style="background:#252840;padding:2px 6px;border-radius:3px">guarding.p2p</code>
      in the path configured at <code style="background:#252840;padding:2px 6px;border-radius:3px">[storage] ipfilter_path</code>.
      Format: <code style="background:#252840;padding:2px 6px;border-radius:3px">AAA.BBB.CCC.DDD - EEE.FFF.GGG.HHH , priority , description</code>
      (eMule-compatible). Reloaded without restart via the button above.
    </p>
  </div>
</div>

<!-- SETTINGS TAB -->
<!-- BOTS TAB -->
<div id="tab-bots" class="tab">
  <div class="section">
    <h3>Bot Detection</h3>
    <p style="font-size:.78rem;color:#9ca3af;margin-bottom:10px">
      IPs flagged for abnormal UDP query patterns, judged over at least <code>bots.min_span_secs</code> (10 s) so a short burst is not a flood. <strong>Flood</strong> &gt; 600 qpm: <strong>banned for 24h</strong>, its UDP traffic dropped at the recv loop. <strong>Uniform timing</strong> &gt; 200 qpm with stddev &lt; 50 ms: <strong>throttled for 24h</strong> to <code>bots.throttle_qpm</code> (60), still answered — mostly one client build with broken pacing. A source that keeps sending through its ban (<code>bots.ipfilter_min_dropped</code>, 10 000 dropped; ten times that when throttled) is added to the IP filter file for good, marked <code>bot</code>. TCP sessions are not affected until then.
    </p>
    <div id="bots-table"></div>
    <p class="sub" style="margin-top:8px">Keep a record: <a href="/api/bots/export?format=csv" style="color:inherit">export CSV</a> ·
      <a href="/api/bots/export" style="color:inherit">JSON lines</a> ·
      <a href="/api/bots/log" style="color:inherit">ledger</a> (detections and ban ends, kept across restarts) ·
      files asked: <a href="/api/bots/files" style="color:inherit">all</a>,
      <a href="/api/bots/files?indexed=1" style="color:inherit">indexed only</a> (CSV with names)</p>
    <div id="bot-detail"></div>
  </div>
</div>

<!-- BLOCKS TAB -->
<div id="tab-blocks" class="tab">
  <div class="section">
    <h3>Block Statistics</h3>
    <p style="font-size:.78rem;color:#9ca3af;margin-bottom:10px">
      Counts since server start. Cleared on restart.
    </p>
    <div id="blocks-table"></div>
  </div>
</div>

<div id="tab-health" class="tab">
  <div class="section">
    <h3>Listening ports</h3>
    <div style="opacity:.7;font-size:12px;margin-bottom:8px">
      UDP ports are fixed by the protocol at TCP+4 / +8 / +12 / +14 and are derived automatically.
    </div>
    <div id="health-ports"></div>
  </div>
  <div class="section">
    <h3>Filter data files</h3>
    <div style="opacity:.7;font-size:12px;margin-bottom:8px">
      "entries" is what is actually loaded in memory. Per-line parse errors appear in the log below.
    </div>
    <div id="health-files"></div>
  </div>
  <div class="section">
    <h3>Data file updates</h3>
    <div style="opacity:.7;font-size:12px;margin-bottom:8px" id="updates-meta"></div>
    <div id="updates-files"></div>
    <div id="updates-result" style="margin-top:10px;font-size:13px"></div>
    <div style="opacity:.6;font-size:11px;margin-top:10px;line-height:1.5">
      Every download is checked for a valid signature, parsed with the same code that loads it at
      runtime, and refused if it would collapse the list. Nothing is written unless all of that
      passes &mdash; a failed update leaves the current file in place. The previous versions are kept
      alongside as <code>.1</code>&hellip;<code>.N</code>.
      <br>
      <b>Update &amp; rewrite</b> replaces the file. <b>Update &amp; merge</b> unions it with the file
      on disk, comparing hashes only and keeping whichever side carries the comment.
    </div>
  </div>
  <div class="section">
    <h3>Recent warnings &amp; errors</h3>
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
      <span style="opacity:.7;font-size:12px" id="health-log-meta"></span>
      <label style="font-size:12px;opacity:.8;cursor:pointer;margin-left:auto">
        <input type="checkbox" id="health-show-warn" onchange="refreshHealth()"> show warnings
      </label>
    </div>
    <div id="health-log" style="max-height:420px;overflow:auto;font-family:ui-monospace,monospace;font-size:12px"></div>
  </div>
</div>

<div id="tab-settings" class="tab">
  <div class="section">
    <h3>Edit config.toml</h3>
    <div id="settings-path" style="font-size:.78rem;color:#9ca3af;margin-bottom:8px"></div>
    <div id="settings-error" style="display:none;background:#3b1f1f;color:#f87171;padding:10px;border-radius:6px;margin-bottom:10px;font-size:.85rem"></div>
    <textarea id="settings-content" spellcheck="false"
      style="width:100%;min-height:500px;background:#0f1117;color:#e2e8f0;border:1px solid #252840;border-radius:6px;padding:12px;font-family:ui-monospace,'Cascadia Code','Source Code Pro',monospace;font-size:.82rem;line-height:1.5;resize:vertical"></textarea>
    <div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
      <button class="reload-btn" onclick="saveSettings()">💾 Save & Reload</button>
      <button class="reload-btn" style="background:#252840;border-color:#6b7280" onclick="refreshSettings()">↻ Reload from disk</button>
      <div id="settings-out" style="font-size:.83rem;color:#6b7280"></div>
    </div>
  </div>
  <div class="section" style="margin-top:16px">
    <h3>About Settings</h3>
    <p style="font-size:.82rem;color:#9ca3af;line-height:1.6">
      Edits the TOML config file directly. On Save:
      <br>• File is validated as TOML before being written (atomic rename).
      <br>• Hot-reloadable sections are applied immediately (<code>[filter]</code>, <code>[storage].ipfilter_path</code>).
      <br>• Changes to ports, seckey, server name require <code>systemctl restart ed2k-server</code>.
    </p>
  </div>
</div>

<div id="refreshed" style="padding:0 20px 10px"></div>
<div style="padding:0 20px 14px;font-size:.68rem;color:#374151;text-align:right">Flag images: <a href="https://github.com/twitter/twemoji" style="color:#4b5563">Twemoji</a>, CC-BY 4.0</div>

<script>
// A session that expired (or a server restart) answers 401: go to the login.
const _fetch = window.fetch.bind(window);
window.fetch = async (...a) => {
  const r = await _fetch(...a);
  if (r.status === 401) location.href = '/login';
  return r;
};
let currentTab = 'status';
function showTab(name, btn) {
  const changed = name !== currentTab;
  currentTab = name;
  if (changed) refreshTab(name);
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  if (btn) btn.classList.add('active');
}
function fmt(n) { return n >= 1e6 ? (n/1e6).toFixed(2)+'M' : n >= 1e3 ? (n/1e3).toFixed(1)+'k' : String(n); }
function fmtDur(s) {
  if (s < 60) return s+'s';
  if (s < 3600) return Math.floor(s/60)+'m '+( s%60)+'s';
  // Past a day, hours alone stop being readable — "47h 12m" takes a moment to
  // turn into "about two days". Days are the last unit: weeks and months are
  // worse, since nobody counts a 40-day uptime in weeks.
  if (s < 86400) return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m';
  const d = Math.floor(s/86400);
  return d+(d === 1 ? ' day ' : ' days ')+Math.floor((s%86400)/3600)+'h '+Math.floor((s%3600)/60)+'m';
}
function countryFlag(code) {
  if (!code || code === '??') return '🌐';
  try {
    return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
  } catch { return '🌐'; }
}

async function refreshStatus() {
  const [st, sys] = await Promise.all([
    fetch('/api/status').then(r=>r.json()),
    fetch('/api/stats').then(r=>r.json()),
  ]);
  document.getElementById('hdr-ver').textContent = st.server_name + ' v' + st.version;
  document.getElementById('logout').style.display = st.login_required ? '' : 'none';
  document.getElementById('cards').innerHTML =
    card('Clients', fmt(st.client_count), st.low_id_count + ' Low ID') +
    card('Files', fmt(st.file_count), 'in index') +
    card('Uptime', fmtDur(st.uptime_seconds), '') +
    card('CPU', sys.cpu_pct.toFixed(1)+'%', sys.rss_mb.toFixed(0)+' MB RSS') +
    card('Memory', sys.allocated_mb.toFixed(0)+' MB', sys.bytes_per_file.toFixed(0)+' B/file · in-use, non-evictable');
  document.getElementById('sys-info').innerHTML =
    `<table><tr><th>Key</th><th>Value</th></tr>
     <tr><td>Server IP</td><td>${st.public_ip || '(auto)'}</td></tr>
     <tr><td>TCP Port</td><td>${st.tcp_port}</td></tr>
     <tr><td>Seckey</td><td><code style="font-size:.75rem">${st.seckey_hex}</code></td></tr>
     ${st.tls_fingerprint ? `<tr><td>HTTPS certificate</td><td><code style="font-size:.7rem">${st.tls_fingerprint}</code> <span style="color:#6b7280;font-size:.75rem">SHA-256; the browser shows the same when the connection is genuine</span></td></tr>` : ''}
     <tr><td>Cache hits</td><td>${sys.cache_hit_pct.toFixed(1)}%</td></tr>
     <tr><td>Searches served</td><td>${fmt(sys.searches_served)} <span style="color:#6b7280;font-size:.75rem">since start</span></td></tr>
     ${sys.highid_observe_enabled ? `<tr><td>HighID hello check (${sys.highid_downgrade_enabled ? 'verdict' : 'observe'})</td><td>${fmt(sys.highid_observe_verified)} verified${sys.highid_observe_verified_marker ? ` (${fmt(sys.highid_observe_verified_marker)} with a different client-type marker in the hello)` : ''} · ${fmt(sys.highid_observe_no_answer)} no answer · ${fmt(sys.highid_observe_mismatch)} wrong hash · ${fmt(sys.highid_observe_skipped)} skipped${sys.highid_downgrade_enabled || sys.highid_downgraded ? `<br>${fmt(sys.highid_marks_active)} marked now · ${fmt(sys.highid_downgraded)} logins given LowID by a mark · ${fmt(sys.highid_marks_cleared)} marks cleared (own hash again)` : ''} <span style="color:#6b7280;font-size:.75rem">${sys.highid_downgrade_enabled ? 'HighID clients re-checked with OP_HELLO in the background, login not delayed. A wrong hash marks (IP, port, hash); its next logins get LowID until the mark expires or its own hash answers again. "No answer" never costs HighID.' : 'HighID clients re-checked with OP_HELLO; "no answer" would be LowID on Lugdunum. Verdict unchanged.'}</span>${sys.highid_observe_reasons ? `<br><span style="color:#6b7280;font-size:.75rem">${escapeHtml(sys.highid_observe_reasons)}</span>` : ''}${sys.highid_mismatch_recent ? `<br><span style="color:#6b7280;font-size:.75rem">wrong hash, last ${fmt(sys.highid_mismatch_recent)}: answering client connected from the SAME IP ${fmt(sys.highid_mismatch_same_ip)} (second client behind one NAT) · from another IP ${fmt(sys.highid_mismatch_other_ip)} · not connected here ${fmt(sys.highid_mismatch_not_here)}</span>` : ''}</td></tr>` : ''}
     <tr><td>Busiest IP</td><td>${fmt(sys.busiest_ip_logged_in)} logged in${sys.busiest_ip ? ` from <code>${sys.busiest_ip}</code>${sys.busiest_ip_country ? ' ('+countryFlag(sys.busiest_ip_country)+' '+escapeHtml(sys.busiest_ip_country)+')' : ''}${sys.busiest_ip_provider ? ' · '+escapeHtml(sys.busiest_ip_provider) : ''} · ${fmt(sys.busiest_ip_connections)} connections` : ''} <span style="color:#6b7280;font-size:.75rem">most logged-in clients behind one address right now (a NAT or CGNAT); connections = its open TCP sockets, which limits.max_clients_per_ip = ${sys.max_clients_per_ip ? fmt(sys.max_clients_per_ip) : 'off'} caps; loopback exempt</span></td></tr>
     <tr><td>Replaced sessions closed</td><td>${fmt(sys.replaced_sessions_closed)} <span style="color:#6b7280;font-size:.75rem">sockets a newer login of the same user took over, closed after 10 min without traffic of their own; a copy that still talks keeps its socket</span></td></tr>
     <tr><td>Soft file limit reached</td><td>${fmt(sys.offer_over_soft_batches)} batches · ${fmt(sys.offer_over_soft_records)} files not indexed <span style="color:#6b7280;font-size:.75rem">limits.soft_limit_files = ${sys.soft_limit_files ? fmt(sys.soft_limit_files) : 'off'}; new files beyond it are not indexed, the client is told once, the session stays up</span></td></tr>
     <tr><td>Admission</td><td>${(()=>{const a=sys.admission||{};const p=x=>x?`${fmt(x.in_use)}/${fmt(x.cap)}${x.rejected?` · ${fmt(x.rejected)} refused`:''}`:'–';const u=a.udp||{};return `<b style="color:${a.ready?'#16a34a':'#dc2626'}">${a.ready?'ready':'NOT READY: '+(a.saturated||[]).join(', ')}</b> · sockets ${p(a.open_tcp)} · pending logins ${p(a.pending_login)} · probes ${p(a.probes)} (${fmt(a.probe_shed_lowid||0)} → LowID) · search jobs ${p(a.search_jobs)}, queue ${p(a.search_queue)} · UDP ${u.enforce?'enforced':'observe'}: refused ${fmt((u.refused_global||0)+(u.refused_source||0)+(u.refused_table_full||0))} (global ${fmt(u.refused_global||0)}, source ${fmt(u.refused_source||0)}, table ${fmt(u.refused_table_full||0)}), sources ${fmt(u.source_entries||0)}/${fmt(u.source_entries_cap||0)}`})()} <span style="color:#6b7280;font-size:.75rem">[admission] — details at /api/admission</span></td></tr>
     <tr><td>Hard file limit reached</td><td>${fmt(sys.offer_over_hard_packets)} packets rejected <span style="color:#6b7280;font-size:.75rem">limits.hard_limit_files = ${sys.hard_limit_files ? fmt(sys.hard_limit_files) : 'off'}; an OFFERFILES declaring this many records or more is rejected and the connection closed</span></td></tr>
     <tr><td>OFFERFILES v1</td><td>${(()=>{const o=sys.offer_v1||{};if(!sys.offerfiles_v1)return `off${o.sessions?` · ${fmt(o.sessions)} sessions advertised before it was turned off`:''}`;if(sys.offerfiles_v1_error)return `<b style="color:#dc2626">not advertised: ${escapeHtml(sys.offerfiles_v1_error)}</b>`;return `${escapeHtml(sys.offerfiles_v1_policy||'')}<br>${fmt(o.requested||0)} logins asked · ${fmt(o.sessions)} advertised · ${fmt(o.batches)} batches, ${fmt(o.records)} records · waited for own pace ${fmt(o.conn_waits)} (${fmt(o.conn_wait_ms)} ms) · for the server-wide ceiling ${fmt(o.global_waits)} (${fmt(o.global_wait_ms)} ms, longest ${fmt(o.global_wait_max_ms)} ms, ${fmt(o.global_waiting_now)} waiting now) · above batch size ${fmt(o.oversized)}`})()} <span style="color:#6b7280;font-size:.75rem">limits.offerfiles_v1 — batch size and pace, advertised in SERVERIDENT only to clients that ask for it at login (issue #19); early batches wait, never dropped; other clients publish exactly as with v1 off</span></td></tr>
     <tr><td>Unknown words dropped</td><td>${fmt(sys.searches_words_dropped)} <span style="color:#6b7280;font-size:.75rem">searches in which a word no indexed file contains was ignored instead of emptying the search</span></td></tr>
     <tr><td>Ranking scan cap hit</td><td>${fmt(sys.searches_rank_capped)} (${sys.searches_rank_capped_pct.toFixed(1)}%) <span style="color:#6b7280;font-size:.75rem">ranked over part of the candidate set, not all of it — raise limits.search_rank_scan if this is a large share</span></td></tr>
     <tr><td>Banned bots (24h)</td><td>${fmt(st.banned_bots)}</td></tr>
     <tr><td>NAT-T capable clients</td><td>${fmt(st.natt_capable_clients)} <span style="color:#6b7280;font-size:.75rem">connected clients with the NAT-traversal mod</span></td></tr>
     <tr><td>IPv6-capable clients</td><td>${fmt(st.ipv6_clients)} <span style="color:#6b7280;font-size:.75rem">sessions that can parse an inline IPv6 source record</span></td></tr>
     <tr><td>IPv6 publishers</td><td>${fmt(st.ipv6_sources)} <span style="color:#6b7280;font-size:.75rem">connected clients with a usable IPv6 address</span></td></tr>
     <tr><td>NAT-T punches coordinated</td><td>${fmt(st.natt_coordinated)} <span style="color:#6b7280;font-size:.75rem">LowID↔LowID since start</span></td></tr>
     <tr><td>obf_decode_cache</td><td>${fmt(st.obf_decode_cache_entries)} <span style="color:#6b7280;font-size:.75rem">entries (capped at 8192)</span></td></tr>
     <tr><td>seed_challenges</td><td>${fmt(st.incoming_seed_challenges_entries)} <span style="color:#6b7280;font-size:.75rem">entries (capped at 2048)</span></td></tr>
     </table>`;
}
function card(lbl, val, sub) {
  return `<div class="card"><div class="lbl">${lbl}</div><div class="val">${val}</div><div class="sub">${sub}</div></div>`;
}

async function refreshClients() {
  const [sw, countries] = await Promise.all([
    fetch('/api/client_stats').then(r=>r.json()),
    fetch('/api/country_stats').then(r=>r.json()),
  ]);
  const total = sw.reduce((a,e)=>a+e.count, 0);
  document.getElementById('sw-chart').innerHTML = sw.length === 0
    ? '<div class="empty">No data yet.</div>'
    : sw.map(e => {
        const pct = total ? (e.count/total*100).toFixed(1) : 0;
        return `<div style="margin-bottom:10px">
          <div style="display:flex;justify-content:space-between;margin-bottom:3px">
            <span class="tag">${escapeHtml(e.software)}</span>
            <span style="font-size:.78rem;color:#9ca3af">${e.count} (${pct}%)</span>
          </div>
          <div class="bar-wrap"><div class="bar" style="width:${pct}%"></div></div>
          ${(e.versions||[]).length > 1 || ((e.versions||[])[0]||[''])[0] !== e.software
            ? `<div class="sub" style="margin-top:3px">${e.versions.map(([v, n]) =>
                `${escapeHtml(v)} <span style="color:#9ca3af">${n}</span>`).join(' · ')}${e.other_versions ? ` · other ${e.other_versions}` : ''}</div>`
            : ''}
        </div>`;
      }).join('');
  const ctotal = countries.reduce((a,e)=>a+e.count,0);
  document.getElementById('country-chart').innerHTML = countries.length === 0
    ? '<div class="empty">No data yet or country DB not loaded.</div>'
    : countries.slice(0,20).map(e => {
        const pct = ctotal ? (e.count/ctotal*100).toFixed(1) : 0;
        return `<div style="margin-bottom:8px">
          <div style="display:flex;justify-content:space-between;margin-bottom:3px">
            <span>${countryFlag(e.code)} ${e.code}</span>
            <span style="font-size:.78rem;color:#9ca3af">${e.count} (${pct}%)</span>
          </div>
          <div class="bar-wrap"><div class="bar" style="width:${pct}%;background:#818cf8"></div></div>
        </div>`;
      }).join('');
  fillSelect('cf-country', countries.map(e => [e.code, countryFlag(e.code) + ' ' + e.code + ' (' + e.count + ')']));
  fillSelect('cf-software', sw.map(e => [e.software, e.software + ' (' + e.count + ')']));
  const res = await fetch('/api/clients/search?' + clientsQuery()).then(r=>r.json());
  const rows = res.rows;
  const from = res.matched ? res.offset + 1 : 0, to = res.offset + rows.length;
  document.getElementById('cf-count').textContent =
    `${from}–${to} of ${res.matched.toLocaleString()}` + (res.matched !== res.total ? ` (filtered from ${res.total.toLocaleString()})` : '');
  document.getElementById('cf-prev').disabled = res.offset === 0;
  document.getElementById('cf-next').disabled = to >= res.matched;
  document.getElementById('clients-table').innerHTML = rows.length === 0
    ? '<div class="empty">' + (res.total ? 'No client matches the filter.' : 'No clients connected.') + '</div>'
    : '<table><thead><tr><th>IP</th><th>Country</th><th>Software</th><th>Nick</th><th>Files</th><th>ID</th><th>IPv6</th><th>Connected</th></tr></thead><tbody>'
      + rows.map(c =>
          `<tr><td><a href="#" style="color:inherit" title="${escapeHtml(c.provider||'')}" onclick="return clientsSearchFor('${escapeHtml(c.ip)}')">${escapeHtml(c.ip)}</a>`
          + `${c.provider ? `<br><span class="sub">${escapeHtml(c.provider)}</span>` : ''}</td>`
          + `<td>${countryFlag(c.country)} ${escapeHtml(c.country)}</td>`
          + `<td><span class="tag" title="${escapeHtml(c.login_fp||'')}">${escapeHtml(c.software_detail||c.software||'?')}</span></td>`
          + `<td>${escapeHtml(c.nick)}</td>`
          + `<td>${(c.shared_files||0).toLocaleString()}</td>`
          + `<td><span class="badge ${c.high_id?'yes':'no'}">${c.high_id?'High':'Low'}</span></td>`
          + `<td>${c.ipv6 ? `<code style="font-size:11px">${escapeHtml(c.ipv6)}</code>`
                          : (c.ipv6_capable ? '<span style="opacity:.6">capable</span>' : '')}</td>`
          + `<td>${fmtDur(c.connected_seconds)}</td></tr>`).join('')
      + '</tbody></table>';
}

// Clients tab: the filter lives in the controls; the server filters, sorts
// and pages. Typing waits 300 ms so a search is one request, not one per key.
let clientsOffset = 0, clientsTimer = null;
const CLIENTS_PAGE = 100;
function clientsQuery() {
  const v = id => document.getElementById(id).value;
  const p = new URLSearchParams({q: v('cf-q'), country: v('cf-country'), software: v('cf-software'),
    id: v('cf-id'), sort: v('cf-sort'), dir: v('cf-dir'), offset: clientsOffset, limit: CLIENTS_PAGE});
  return p.toString();
}
function clientsFilterChanged() {
  clientsOffset = 0;
  clearTimeout(clientsTimer);
  clientsTimer = setTimeout(refreshClients, 300);
}
function clientsPage(d) {
  clientsOffset = Math.max(0, clientsOffset + d * CLIENTS_PAGE);
  refreshClients();
}
function clientsSearchFor(text) {
  document.getElementById('cf-q').value = text;
  clientsFilterChanged();
  return false;
}
// Refill a <select> from [value, label] pairs, keeping the current choice
// (and keeping it listed even if its count dropped to zero).
function fillSelect(id, items) {
  const el = document.getElementById(id);
  const cur = el.value, first = el.options[0].outerHTML;
  if (cur && !items.some(([v]) => v === cur)) items = [[cur, cur], ...items];
  const html = first + items.map(([v, l]) => `<option value="${escapeHtml(v)}">${escapeHtml(l)}</option>`).join('');
  if (el.dataset.html !== html) { el.innerHTML = html; el.dataset.html = html; el.value = cur; }
}

async function refreshPeers() {
  const r = await fetch('/api/peers').then(r=>r.json());
  r.sort((a, b) => (b.users ?? -1) - (a.users ?? -1));
  const num = v => v == null ? '<span class="sub">—</span>' : v.toLocaleString();
  document.getElementById('peers-table').innerHTML = r.length === 0
    ? '<div class="empty">No peer servers known yet.</div>'
    : '<table><thead><tr><th>Server</th><th>Address</th><th>Country</th><th>Users</th><th>Files</th><th>Version</th><th>Verified</th><th>ServerKey</th></tr></thead><tbody>'
      + r.map(p => `<tr><td>${p.name ? escapeHtml(p.name) : `<span class="sub">${p.asked ? 'no answer' : 'not asked yet'}</span>`}`
               + `${p.desc ? `<br><span class="sub">${escapeHtml(p.desc)}</span>` : ''}</td>`
               + `<td><code style="font-size:11px">${escapeHtml(p.ip)}:${p.port}</code></td>`
               + `<td>${p.country ? countryFlag(p.country) + ' ' + escapeHtml(p.country) : ''}`
               + `${p.provider ? `<br><span class="sub">${escapeHtml(p.provider)}</span>` : ''}</td>`
               + `<td>${num(p.users)}</td><td>${num(p.files)}</td>`
               + `<td>${p.version ? escapeHtml(p.version) : ''}</td>`
               + `<td><span class="badge ${p.verified?'yes':'no'}">${p.verified?'yes':'no'}</span></td>`
               + `<td><span class="badge ${p.has_server_key?'yes':'no'}">${p.has_server_key?'✓ known':'pending'}</span></td></tr>`).join('')
      + '</tbody></table>';
}

async function refreshFilter() {
  const f = await fetch('/api/filter_info').then(r=>r.json());
  document.getElementById('filter-info').innerHTML =
    `<table><tr><th>Setting</th><th>Value</th></tr>
     <tr><td>IP filter ranges</td><td>${f.ipfilter_ranges === 0 ? '<span class="badge no">not loaded</span>' : '<span class="badge yes">'+f.ipfilter_ranges.toLocaleString()+' ranges</span>'}</td></tr>
     <tr><td>Country DB</td><td><span class="badge ${f.country_db_loaded?'yes':'no'}">${f.country_db_loaded?(f.country_db_ipv6?'IPv4 + IPv6':'IPv4 only'):'not loaded'}</span> <span class="sub">${escapeHtml(f.country_db||'')}</span></td></tr>
     </table>`;
}

async function loadIpfilterHits() {
  const out = document.getElementById('ipfilter-hits');
  out.textContent = 'loading...';
  try {
    const rows = await fetch('/api/ipfilter_hits').then(r=>r.json());
    if (!rows.length) {
      out.innerHTML = '<span class="badge no">no blocks recorded yet</span>';
      return;
    }
    let html = '<table><tr><th>IP range</th><th>Hits</th><th>Description</th></tr>';
    for (const r of rows) {
      const desc = (r.description || '').replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));
      html += `<tr><td><code style="font-size:.75rem">${r.range}</code></td><td>${fmt(r.count)}</td><td>${desc}</td></tr>`;
    }
    html += '</table>';
    out.innerHTML = html;
  } catch (e) {
    out.innerHTML = '<span class="badge no">failed to load</span>';
  }
}

async function doReload() {
  const out = document.getElementById('reload-out');
  out.textContent = 'sending...';
  try {
    const r = await fetch('/api/reload', {method:'POST'});
    out.textContent = r.ok ? '✓ Reload triggered — watch journalctl for details.' : '✗ Failed: HTTP ' + r.status;
  } catch (e) { out.textContent = '✗ Error: ' + e; }
}

let settingsLoaded = false;
async function refreshSettings() {
  const ta = document.getElementById('settings-content');
  const pathEl = document.getElementById('settings-path');
  const errEl = document.getElementById('settings-error');
  errEl.style.display = 'none';
  try {
    const r = await fetch('/api/config').then(r => r.json());
    if (r.error) {
      errEl.style.display = 'block';
      errEl.textContent = r.error;
      ta.value = '';
      ta.disabled = true;
    } else {
      ta.value = r.content;
      ta.disabled = r.read_only;
      pathEl.textContent = '📄 ' + r.path + (r.read_only ? ' (read-only)' : '');
    }
    settingsLoaded = true;
  } catch (e) {
    errEl.style.display = 'block';
    errEl.textContent = 'fetch error: ' + e;
  }
}

async function saveSettings() {
  const ta = document.getElementById('settings-content');
  const out = document.getElementById('settings-out');
  const errEl = document.getElementById('settings-error');
  errEl.style.display = 'none';
  out.textContent = 'saving...';
  try {
    const r = await fetch('/api/config', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({content: ta.value}),
    }).then(r => r.json());
    if (r.ok) {
      out.textContent = '✓ Saved. ' + (r.hint || '');
      out.style.color = '#4ade80';
    } else {
      errEl.style.display = 'block';
      errEl.textContent = r.error + (r.hint ? ' — ' + r.hint : '');
      out.textContent = '';
    }
  } catch (e) {
    errEl.style.display = 'block';
    errEl.textContent = 'request error: ' + e;
    out.textContent = '';
  }
}

// Hook into showTab to load settings lazily on first open
const origShowTab = showTab;
showTab = function(name, btn) {
  origShowTab(name, btn);
  if (name === 'settings' && !settingsLoaded) refreshSettings();
};

async function refreshBots() {
  const rows = await fetch('/api/bots').then(r => r.json());
  const el = document.getElementById('bots-table');
  if (!rows || rows.length === 0) {
    el.innerHTML = '<div class="empty">No bots detected.</div>';
    return;
  }
  el.innerHTML = '<table><thead><tr>'
    + '<th>IP</th><th>Country</th><th>QPM</th><th>Stddev (ms)</th>'
    + '<th>Sent</th><th>Files asked</th><th>TCP client on this IP</th>'
    + '<th>Reason</th><th>First seen</th><th>Last seen</th></tr></thead><tbody>'
    + rows.map(b => {
        // -1 is our sentinel for "not enough samples to compute stddev"
        const stddev = (b.interval_stddev_ms < 0) ? '—' : b.interval_stddev_ms.toFixed(0);
        const total = (b.searches||0) + (b.source_requests||0);
        const pct = n => total ? Math.round(n * 100 / total) + '%' : '—';
        const sent = total === 0 ? '<span class="sub">—</span>'
          : `${b.searches ? `search ${b.searches.toLocaleString()}` : ''}`
            + `${b.searches && b.source_requests ? ' · ' : ''}`
            + `${b.source_requests ? `sources ${b.source_requests.toLocaleString()} `
                + `(${(b.source_hashes / b.source_requests).toFixed(1)} hash/req)` : ''}`
            + `<br><span class="sub">obf ${pct(b.obfuscated)} · from :${b.src_port}`
            + `${b.src_port_changes ? ` (${b.src_port_changes} port changes)` : ''} → :${b.our_port}</span>`;
        return `<tr><td>${escapeHtml(b.ip)}</td>`
          + `<td>${countryFlag(b.country)} ${escapeHtml(b.country)}`
          + `${b.provider ? `<br><span class="sub">${escapeHtml(b.provider)}</span>` : ''}</td>`
          + `<td>${b.queries_per_minute.toFixed(0)}</td>`
          + `<td>${stddev}</td>`
          + `<td>${sent}</td>`
          + `<td>${b.hashes_distinct ? `<a href="#" style="color:inherit" onclick="return botDetail('${escapeHtml(b.ip)}')">${b.hashes_distinct.toLocaleString()} distinct</a>`
                + `<br><span class="sub">${b.hashes_total.toLocaleString()} asked`
                + `${b.dropped_after_ban ? ` · ${b.dropped_after_ban.toLocaleString()} dropped since ${b.throttled ? 'throttle' : 'ban'}`
                    + (b.last_dropped_secs_ago != null ? `, last ${fmtDur(b.last_dropped_secs_ago)} ago` : '') : ''}</span>`
              : '<span class="sub">—</span>'}</td>`
          + `<td>${b.tcp_client ? escapeHtml(b.tcp_client) : '<span class="sub">none</span>'}</td>`
          + `<td><span class="badge no">${escapeHtml(b.reason)}</span>${b.banned ? ' <span class="badge no" style="background:#7f1d1d;color:#fecaca;border-color:#b91c1c">BANNED 24h</span>' : ''}`
          + `${b.throttled ? ' <span class="badge no" style="background:#78350f;color:#fde68a;border-color:#b45309">THROTTLED 24h</span>' : ''}`
          + `${b.ipfilter_added ? ' <span class="badge no" style="background:#1e1b4b;color:#c7d2fe;border-color:#4338ca">IP FILTER</span>' : ''}</td>`
          + `<td>${fmtDur(b.first_seen_secs_ago)} ago</td>`
          + `<td>${fmtDur(b.last_seen_secs_ago)} ago</td></tr>`;
      }).join('')
    + '</tbody></table>';
}

async function botDetail(ip) {
  const el = document.getElementById('bot-detail');
  el.innerHTML = '<div class="empty">Loading…</div>';
  const r = await fetch('/api/bots/detail?ip=' + encodeURIComponent(ip));
  if (!r.ok) { el.innerHTML = `<div class="empty">${escapeHtml(await r.text())}</div>`; return false; }
  const d = await r.json();
  const size = n => n >= 1073741824 ? (n/1073741824).toFixed(2)+' GB' : (n/1048576).toFixed(1)+' MB';
  el.innerHTML = `<h3 style="margin-top:16px">Files asked by ${escapeHtml(d.ip)}</h3>`
    + `<p class="sub">${d.hashes_distinct.toLocaleString()} distinct of ${d.hashes_total.toLocaleString()} asked`
    + `${d.hashes_distinct_capped ? ' (distinct count capped)' : ''}. Last ${d.recent.length}, newest first. `
    + `All of them: <a href="/api/bots/files?ip=${encodeURIComponent(d.ip)}" style="color:inherit">CSV</a>.</p>`
    + (d.shares_hashes_with.length
        ? `<p style="font-size:.85rem">Same files asked by: ${d.shares_hashes_with.map(o =>
            `<a href="#" style="color:inherit" onclick="return botDetail('${escapeHtml(o.ip)}')">${escapeHtml(o.ip)}</a> (${o.common})`).join(', ')}</p>`
        : '<p class="sub">No other bot asked for the same files.</p>')
    + '<table><thead><tr><th>Hash</th><th>Name</th><th>Size</th><th>Sources</th></tr></thead><tbody>'
    + d.recent.map(f => `<tr><td><code style="font-size:11px">${f.hash}</code></td>`
        + (f.indexed === false
            ? '<td colspan="3"><span class="sub">not in the index</span></td>'
            : `<td>${escapeHtml(f.name)}</td><td>${size(f.size)}</td><td>${f.sources}</td>`)
        + '</tr>').join('')
    + '</tbody></table>';
  el.scrollIntoView({behavior: 'smooth'});
  return false;
}

async function refreshBlocks() {
  const rows = await fetch('/api/block_stats').then(r => r.json());
  const el = document.getElementById('blocks-table');
  if (!rows || rows.length === 0) {
    el.innerHTML = '<div class="empty">No blocks recorded yet.</div>';
    return;
  }
  el.innerHTML = '<table><thead><tr><th>Reason</th><th>Count</th><th>Unique IPs</th><th>Counts what</th></tr></thead><tbody>'
    + rows.map(r => {
        const meta = {
          'ipfilter':                { label: 'IP filter (guarding.p2p)',  desc: 'TCP connections dropped' },
          'csam':                    { label: 'CSAM filter (total)',       desc: 'unique blocked files (sum of all layers). "Unique IPs" = distinct publishers' },
          'csam_L1_jargon':          { label: '  └ Layer 1 — jargon',      desc: 'sealed CSAM-marker term list (long substrings)' },
          'csam_L2_age':             { label: '  └ Layer 2 — age + sex',   desc: 'filename contains both a minor-age token AND a sexual-context term' },
          'csam_L3_hash':            { label: '  └ Layer 3 — hash list',   desc: 'MD4 file hash matches the operator-loaded hash banlist' },
          'csam_L4_extra':           { label: '  └ Layer 4 — operator',    desc: 'custom term list from [content_filter].extra_terms_file' },
          'bot':                     { label: 'Bot detection (flagged)',   desc: 'detection events (cooldown 30s/IP)' },
          'bot_ban':                 { label: '  └ Bots banned (24h)',     desc: 'distinct flood-bot IPs auto-banned; UDP dropped for 24h' },
          'rate_limit':              { label: 'Rate limit',                desc: 'queries throttled' },
          'max_connections_per_ip':  { label: 'Too many connections',      desc: 'TCP connections refused: the IP already had limits.max_clients_per_ip open' },
          'server_full':             { label: 'Server full',               desc: 'logins refused: limits.max_clients clients were connected' },
        }[r.reason] || { label: r.reason, desc: '' };
        const uniq = (r.unique_ips != null) ? r.unique_ips.toLocaleString() : '—';
        return `<tr><td>${meta.label}</td><td>${r.count.toLocaleString()}</td>`
          + `<td>${uniq}</td>`
          + `<td style="color:#6b7280;font-size:.78rem">${meta.desc}</td></tr>`;
      }).join('')
    + '</tbody></table>';
}

let updatesBusy = false;

async function refreshUpdates() {
  let u;
  try { u = await fetch('/api/updates').then(r=>r.json()); } catch { return; }

  let meta = u.enabled
    ? 'Installing into <code>' + u.dest_dir + '</code>. Backups kept: ' + u.backups + '.'
    : '<b>Updates are disabled.</b> Set <code>updates.enabled = true</code> in the config.';
  if (u.enabled && !u.has_public_key && u.require_signature)
    meta += ' <span style="color:#e57373">No public key configured &mdash; signed files cannot be verified and every update will be refused.</span>';
  if (u.enabled && !u.require_signature)
    meta += ' <span style="color:#e5a23c">Signature checking is OFF.</span>';
  if (u.enabled && u.access_key)
    meta += '<br>Access key <code>' + u.access_key + '</code>, derived against ' + u.key_reference_ip + '.';
  else if (u.enabled)
    meta += '<br><span style="opacity:.8">No <code>updates.key_reference_ip</code> &mdash; access-controlled files cannot be fetched.</span>';
  document.getElementById('updates-meta').innerHTML = meta;

  const rows = u.files.map(function(f) {
    const size = f.exists ? (f.size_bytes/1024).toFixed(0) + ' KB' : '<span style="opacity:.5">absent</span>';
    let buttons;
    if (!u.enabled) {
      buttons = '<span style="opacity:.5">disabled</span>';
    } else if (!f.configured) {
      buttons = '<span style="opacity:.5">no URL configured</span>';
    } else if (f.supports_merge) {
      buttons =
        '<button onclick="runUpdate(&quot;' + f.id + '&quot;,&quot;replace&quot;)">Update &amp; rewrite</button> ' +
        '<button onclick="runUpdate(&quot;' + f.id + '&quot;,&quot;merge&quot;)">Update &amp; merge</button>';
    } else {
      buttons = '<button onclick="runUpdate(&quot;' + f.id + '&quot;,&quot;replace&quot;)">Update</button>';
    }
    return '<tr><td>' + healthDot(f.exists) + '</td><td>' + f.label +
           '</td><td><code style="font-size:11px">' + f.filename + '</code></td><td>' + size +
           '</td><td>' + (f.needs_credentials ? 'key' : '<span style="opacity:.6">public</span>') +
           '</td><td>' + buttons + '</td></tr>';
  }).join('');
  document.getElementById('updates-files').innerHTML =
    '<table><tr><th></th><th>List</th><th>File</th><th>On disk</th><th>Access</th><th></th></tr>' +
    rows + '</table>';
}

async function runUpdate(id, mode) {
  if (updatesBusy) return;
  updatesBusy = true;
  const out = document.getElementById('updates-result');
  out.innerHTML = '<span style="opacity:.7">' + id + ': downloading&hellip;</span>';
  try {
    const r = await fetch('/api/update', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({target: id, mode: mode})
    }).then(x=>x.json());
    if (r.ok) {
      out.innerHTML = '<span style="color:#7fbf7f">' + id + ': ' + r.message +
        (r.signature_verified ? ' &middot; signature verified' : ' &middot; <b>unsigned</b>') +
        '</span><div style="opacity:.6;font-size:11px">' + r.path +
        ' &middot; reload requested, live within ~2s</div>';
    } else {
      out.innerHTML = '<span style="color:#e57373">' + id + ': ' + r.message + '</span>';
    }
  } catch (e) {
    out.innerHTML = '<span style="color:#e57373">' + id + ': request failed &mdash; ' + e + '</span>';
  }
  updatesBusy = false;
  refreshUpdates();
  refreshHealth();
}

function healthDot(ok) {
  return '<span style="color:' + (ok ? '#4ade80' : '#f87171') + '">' + (ok ? '●' : '●') + '</span>';
}
async function refreshHealth() {
  refreshUpdates();
  let h;
  try { h = await fetch('/api/health').then(r=>r.json()); } catch { return; }

  document.getElementById('health-ports').innerHTML =
    '<table><thead><tr><th></th><th>Proto</th><th>Port</th><th>Role</th><th>State</th></tr></thead><tbody>'
    + h.ports.map(p =>
        '<tr><td>' + healthDot(p.ok) + '</td><td>' + p.proto.toUpperCase() + '</td><td>' + p.port
        + '</td><td>' + p.role + '</td><td>' + p.detail + '</td></tr>').join('')
    + '</tbody></table>';

  document.getElementById('health-files').innerHTML =
    '<table><thead><tr><th></th><th>File</th><th>Entries</th><th>Size</th><th>Modified</th><th>Path</th></tr></thead><tbody>'
    + h.files.map(f =>
        '<tr><td>' + healthDot(f.ok) + '</td><td>' + f.label + '</td><td>'
        + (f.entries === null ? '<span style="opacity:.5">merged</span>' : fmt(f.entries))
        + '</td><td>' + (f.exists ? fmt(f.size_bytes)+'B' : '<span style="color:#f87171">missing</span>')
        + '</td><td>' + (f.exists ? fmtDur(f.modified_secs_ago)+' ago' : '-')
        + '</td><td style="opacity:.6;font-size:11px">' + f.path + '</td></tr>').join('')
    + '</tbody></table>';

  // Errors only by default. Warnings are still COLLECTED (that is how a bad line
  // in a filter file surfaces — the loaders warn! with file and line number), but
  // they are noisy day to day, so they are behind a toggle.
  const showWarn = document.getElementById('health-show-warn').checked;
  const shown = h.log.entries.filter(e => showWarn || e.level === 'ERROR');
  const errCount = h.log.entries.filter(e => e.level === 'ERROR').length;
  const warnCount = h.log.entries.length - errCount;
  document.getElementById('health-log-meta').textContent =
    errCount + ' errors' + (warnCount ? ', ' + warnCount + ' warnings' : '')
    + ' in the last ' + h.log.shown + ' events (' + h.log.total_seen + ' since start)'
    + (h.log.total_seen === 0 ? ' — nothing has gone wrong' : '');
  document.getElementById('health-log').innerHTML =
    shown.length === 0
      ? '<div style="opacity:.5;padding:8px">'
        + (showWarn ? 'No warnings or errors recorded.' : 'No errors. Tick "show warnings" for the rest.')
        + '</div>'
      : shown.map(e => {
          const t = new Date(e.ts * 1000).toLocaleTimeString();
          const col = e.level === 'ERROR' ? '#f87171' : '#fbbf24';
          return '<div style="padding:3px 0;border-bottom:1px solid rgba(255,255,255,.06)">'
            + '<span style="opacity:.5">' + t + '</span> '
            + '<span style="color:' + col + '">' + e.level + '</span> '
            + escapeHtml(e.message)
            + (e.fields ? ' <span style="opacity:.55">' + escapeHtml(e.fields) + '</span>' : '')
            + '</div>';
        }).join('');
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
}

// Only the tab on screen is polled. Every tab every 5 s meant the server
// rebuilt the client list, the peer list, the bot and block tables and the
// health log for each open admin page whether anyone looked at them or not.
// A tab is refreshed at once when it is opened, so nothing shows stale data.
const tabRefresh = {
  clients: refreshClients, peers: refreshPeers, filter: refreshFilter,
  bots: refreshBots, blocks: refreshBlocks, health: refreshHealth,
};
function refreshTab(name) {
  const f = tabRefresh[name];
  return f ? f().catch(() => {}) : Promise.resolve();
}
async function refresh() {
  // Status also fills the page header, so it is always kept current.
  await Promise.all([refreshStatus(), refreshTab(currentTab)]);
  document.getElementById('refreshed').textContent = 'last updated: ' + new Date().toLocaleTimeString();
}
refresh();
setInterval(refresh, 5000);
</script>
</body></html>
"##;

#[cfg(test)]
mod highid_mismatch_endpoint_tests {
    use super::*;
    use crate::state::HighIdMismatch;
    use std::net::{IpAddr, Ipv4Addr};

    fn web_state() -> WebState {
        let server = Arc::new(ServerState::for_test());
        let config = Arc::new(Config::minimal_test_config());
        WebState {
            server,
            config,
            metrics: Arc::new(Metrics::new()),
            seckey_hex: String::new(),
            config_path: String::new(),
            reload_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cached_public_ip: String::new(),
            auth: None,
            tls: None,
        }
    }

    fn rec(ip: [u8; 4], login: [u8; 16], answered: [u8; 16]) -> HighIdMismatch {
        HighIdMismatch {
            at: 1_790_000_000,
            ip: IpAddr::V4(Ipv4Addr::from(ip)),
            port: 4662,
            login_hash: login,
            answered_hash: answered,
            marked: false,
        }
    }

    async fn call(ws: &WebState, q: Option<&str>) -> serde_json::Value {
        let Json(v) = api_highid_mismatches(
            State(ws.clone()),
            axum::extract::RawQuery(q.map(|s| s.to_string())),
        )
        .await;
        v
    }

    #[tokio::test]
    async fn summarises_what_the_analysis_needs() {
        let ws = web_state();
        let st = &ws.server;
        // A second client behind the same NAT: connected from the probed IP.
        st.register_test_client([0xB1; 16], 1, true, 0); // 10.0.0.2
        let live = st.live_cfg.load();
        let ours = crate::server::highid_probe::server_pseudo_user_hash(
            &crate::server::udp::resolve_seckey(&live),
        );
        let mut emule = [0x11u8; 16];
        emule[5] = 0x0E;
        emule[14] = 0x6F;
        let o = &st.highid_observe;
        o.record_mismatch(rec([10, 0, 0, 2], emule, [0xB1; 16])); // same-IP NAT
        o.record_mismatch(rec([10, 9, 9, 9], [0x22; 16], ours)); // echo of our hello
        o.record_mismatch(rec([10, 9, 9, 9], [0x22; 16], ours)); // same IP again

        let v = call(&ws, None).await;
        let sm = &v["summary"];
        assert_eq!(sm["records"], 3);
        assert_eq!(sm["distinct_ips"], 2);
        assert_eq!(sm["distinct_answered_hashes"], 2);
        assert_eq!(sm["answered_is_our_probe_hash"], 2);
        assert_eq!(sm["answered_client_connected_same_ip"], 1);
        assert_eq!(sm["answered_client_not_connected"], 2);
        assert_eq!(sm["login_hash_has_emule_marker"], 1);
        assert_eq!(sm["repeated_ips"][0]["key"], "10.9.9.9");
        assert_eq!(sm["repeated_ips"][0]["count"], 2);
        assert_eq!(v["our_probe_hash"], hex::encode(ours));
        assert_eq!(v["records"][0]["answered_client_now"], "connected_same_ip");
        assert_eq!(v["records"][1]["answered_is_our_probe_hash"], true);
    }

    #[tokio::test]
    async fn anonymize_hides_addresses_but_keeps_repeats_visible() {
        let ws = web_state();
        let o = &ws.server.highid_observe;
        o.record_mismatch(rec([85, 17, 116, 5], [1; 16], [2; 16]));
        o.record_mismatch(rec([85, 17, 116, 5], [1; 16], [2; 16]));
        o.record_mismatch(rec([85, 17, 116, 6], [3; 16], [4; 16]));
        let v = call(&ws, Some("anonymize=1")).await;
        assert_eq!(v["anonymized"], true);
        let ips: Vec<String> = v["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["ip"].as_str().unwrap().to_string())
            .collect();
        for ip in &ips {
            assert!(ip.starts_with("85.17.116.x#"), "{ip}");
            assert!(!ip.contains("116.5") && !ip.contains("116.6"), "{ip}");
        }
        assert_eq!(
            ips[0], ips[1],
            "the same address must map to the same pseudonym"
        );
        assert_ne!(ips[0], ips[2], "different addresses must not collide here");
        assert_eq!(v["summary"]["distinct_ips"], 2);
    }
}

#[cfg(test)]
mod client_search_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn client(ip: [u8; 4], nick: &str, country: &str, sw: &str, high: bool) -> crate::state::ClientHandle {
        crate::state::ClientHandle {
            user_hash: [ip[3]; 16],
            assigned_id: 1,
            ip: IpAddr::V4(Ipv4Addr::from(ip)),
            port: 4662,
            udp_port: 0,
            natt_capable: false,
            nick: nick.into(),
            server_flags: 0,
            ipv6_capable: false,
            ipv6: None,
            is_high_id: high,
            connected_at: Instant::now(),
            country: country.into(),
            software: sw.into(),
            software_detail: sw.into(),
            login_fp: String::new(),
            csam_attempts: 0,
            soft_limit_warned: false,
            offer_policy: None,
            slot: Default::default(),
            tx: None,
            last_activity_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    #[test]
    fn url_decoding() {
        assert_eq!(url_decode("82.48.0.0%2F16"), "82.48.0.0/16");
        assert_eq!(url_decode("a+b%20c"), "a b c");
        assert_eq!(url_decode("100%"), "100%");
        assert_eq!(url_decode("%zz%4"), "%zz%4");
        assert_eq!(url_decode("%D0%BF%D1%80"), "пр");
    }

    #[test]
    fn query_defaults_and_limits() {
        let q = ClientQuery::parse("");
        assert_eq!((q.sort, q.descending, q.offset, q.limit), (ClientSort::Connected, true, 0, 100));
        let q = ClientQuery::parse("limit=100000&offset=200&sort=files&dir=asc&id=low&country=it");
        assert_eq!(q.limit, ClientQuery::MAX_LIMIT);
        assert_eq!((q.offset, q.sort, q.descending, q.high_id), (200, ClientSort::Files, false, Some(false)));
        assert_eq!(q.country, "IT");
        assert_eq!(ClientQuery::parse("limit=0").limit, 1);
        assert_eq!(ClientQuery::parse("limit=x").limit, 100);
    }

    #[test]
    fn text_matches_ip_and_nick_case_insensitively() {
        let c = client([82, 48, 45, 246], "http://www.aMule.org", "IT", "aMule", false);
        assert!(ClientQuery::parse("q=82.48.").matches(&c));
        assert!(ClientQuery::parse("q=AMULE").matches(&c));
        assert!(!ClientQuery::parse("q=emule-project").matches(&c));
        assert!(ClientQuery::parse("").matches(&c));
    }

    #[test]
    fn cidr_matches_by_network_not_by_text() {
        let c = client([82, 48, 45, 246], "x", "IT", "aMule", false);
        assert!(ClientQuery::parse("q=82.48.0.0%2F16").matches(&c));
        assert!(ClientQuery::parse("q=82.48.45.0/24").matches(&c));
        assert!(!ClientQuery::parse("q=82.49.0.0/16").matches(&c));
        assert!(ClientQuery::parse("q=0.0.0.0/0").matches(&c));
        assert_eq!(parse_cidr_v4("1.2.3.4/33"), None);
        assert_eq!(parse_cidr_v4("1.2.3.4"), None);
    }

    #[test]
    fn exact_filters_combine() {
        let c = client([1, 2, 3, 4], "n", "ES", "eMule", true);
        assert!(ClientQuery::parse("country=es&software=eMule&id=high").matches(&c));
        assert!(!ClientQuery::parse("country=IT").matches(&c));
        assert!(!ClientQuery::parse("software=aMule").matches(&c));
        assert!(!ClientQuery::parse("id=low").matches(&c));
        assert!(!ClientQuery::parse("ipv6=1").matches(&c));
    }
}

#[cfg(test)]
mod cross_site_tests {
    use super::*;

    fn h(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(*k, HeaderValue::from_str(v).unwrap());
        }
        m
    }

    #[test]
    fn own_form_over_plain_http_passes() {
        // Plain HTTP to a public IP: no Sec-Fetch-*, real Origin under
        // Referrer-Policy: same-origin.
        assert!(!cross_site(&h(&[("host", "85.17.116.222:8080"), ("origin", "http://85.17.116.222:8080")])));
    }

    #[test]
    fn sec_fetch_site_decides_when_present() {
        // A browser under an old no-referrer page may send Origin: null with
        // same-origin; Sec-Fetch-Site wins.
        assert!(!cross_site(&h(&[("host", "127.0.0.1:8080"), ("origin", "null"), ("sec-fetch-site", "same-origin")])));
        assert!(!cross_site(&h(&[("host", "127.0.0.1:8080"), ("sec-fetch-site", "none")])));
        assert!(cross_site(&h(&[("host", "127.0.0.1:8080"), ("origin", "http://127.0.0.1:8080"), ("sec-fetch-site", "cross-site")])));
        assert!(cross_site(&h(&[("host", "127.0.0.1:8080"), ("sec-fetch-site", "same-site")])));
    }

    #[test]
    fn foreign_or_null_origin_refused_without_sec_fetch() {
        assert!(cross_site(&h(&[("host", "85.17.116.222:8080"), ("origin", "http://evil.example")])));
        assert!(cross_site(&h(&[("host", "85.17.116.222:8080"), ("origin", "http://85.17.116.222:8081")])));
        assert!(cross_site(&h(&[("host", "85.17.116.222:8080"), ("origin", "null")])));
    }

    #[test]
    fn scripts_without_browser_headers_pass() {
        assert!(!cross_site(&h(&[("host", "127.0.0.1:8080")])));
    }
}

#[cfg(test)]
mod https_redirect_tests {
    use super::*;

    fn admin(names: &[&str]) -> crate::config::AdminConfig {
        let mut a = crate::config::AdminConfig::default();
        a.tls_names = names.iter().map(|s| s.to_string()).collect();
        a
    }

    #[test]
    fn keeps_host_and_path() {
        let a = admin(&[]);
        assert_eq!(
            redirect_target(b"GET /login HTTP/1.1\r\nHost: 85.17.116.222:8080\r\n\r\n", &a).as_deref(),
            Some("https://85.17.116.222:8080/login")
        );
        assert_eq!(
            redirect_target(b"GET / HTTP/1.1\r\nhost: [2001:db8::1]:8080\r\n\r\n", &a).as_deref(),
            Some("https://[2001:db8::1]:8080/")
        );
        assert_eq!(
            redirect_target(b"GET /x HTTP/1.1\r\nHost: panel.example\r\n\r\n", &admin(&["panel.example"]))
                .as_deref(),
            Some("https://panel.example/x")
        );
    }

    #[test]
    fn refuses_unknown_host_and_odd_requests() {
        let a = admin(&[]);
        assert!(redirect_target(b"GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n", &a).is_none());
        assert!(redirect_target(b"GET / HTTP/1.0\r\n\r\n", &a).is_none());
        assert!(redirect_target(b"POST /login HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n", &a).is_none());
        // Absolute or protocol-relative targets never become the Location path.
        assert_eq!(
            redirect_target(b"GET //evil.example/ HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n", &a).as_deref(),
            Some("https://1.2.3.4/")
        );
        assert_eq!(
            redirect_target(b"GET http://evil.example/ HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n", &a).as_deref(),
            Some("https://1.2.3.4/")
        );
    }
}

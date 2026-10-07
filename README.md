# ed2k-server

A modern, open-source **eDonkey2000 / eMule index server**, written from scratch
in **Rust**. It is a clean-room replacement for the long-unmaintained,
closed-source *Lugdunum* eserver — built to be lean, memory-efficient, and
stable at the scale of the largest real eD2k servers (tens of millions of files).

## Features

- Full eD2k protocol: TCP (login, search, get-sources, offer-files) and **UDP**
  (search, get-sources, server pings, server-to-server gossip) — UDP is the bulk
  of real-world traffic.
- Inverted keyword index with boolean search trees and numeric size filters.
  Results are ranked by source count, the result cap is configurable, and a
  query word no indexed file contains no longer empties the search.
- Memory-optimized in-memory index (sharded slab, intrusive hash index, name
  interning, jemalloc tuning) — roughly **half the RAM** of the Lugdunum
  reference at the same scale.
- **Mandatory multi-layer CSAM content filter** on every published file
  (age+context heuristics in code; operator-supplied jargon, hash, and
  extra-term lists loaded at runtime — see *Content filter* below).
- Server-to-server **gossip** with obfuscation; mldonkey/junk-server filtering
  via verification.
- **NAT traversal (NAT-T)** hole-punch coordination for LowID↔LowID transfers.
- **IPv6** (opt-in): clients can connect over IPv6, and a client that is LowID on
  IPv4 but has a public IPv6 is published as an IPv6 source to peers that can
  parse it — see *IPv6* below.
- HighID verified by a client-to-client hello, not only a TCP connect: a port
  forwarded to a *different* client behind the same NAT no longer earns HighID.
- IP filtering in eMule **guarding.p2p** format, with per-range hit statistics.
- GeoIP country and provider for IPv4 and IPv6 (MaxMind DB, with the
  `ip-to-country.csv` fallback), bot/scanner detection, CSAM-publisher banning.
- **Work admission**: bounded sockets, logins, probes, searches and UDP, sized
  for 50 000 clients and the reconnect storm after a restart.
- Built-in **admin web panel** (status, clients with server-side search, peers
  with their names, filters, bots, blocks, settings) bound to localhost.
- Hot-reloadable filter lists and config without a restart.

> Status: production-used test/MVP build (v0.9.x). The protocol surface is
> complete and running live; expect ongoing iteration.

## Language & dependencies

- **Rust** (edition 2021, `rust-version >= 1.75`), async on **Tokio**.
- Memory allocator: **jemalloc** (`tikv-jemallocator`) on non-MSVC targets.
- Web panel: **axum**. All dependency versions are pinned in `Cargo.toml`.

## System requirements

- **Linux x86-64.** Developed and tested on **Debian 13 (codename trixie)**. Other
  modern distributions (Ubuntu, etc.) work the same way.
- A Rust toolchain (`rustc` / `cargo`) ≥ 1.75 — install via [rustup](https://rustup.rs).
- Build tools: a C compiler and `make` (jemalloc-sys builds a small C library).
  On Debian/Ubuntu: `sudo apt install build-essential`.
- RAM scales with index size. A small/medium server runs comfortably in a few
  hundred MB; planning for tens of millions of files, budget ~10–13 GB.
- Raise the open-file limit for production (see *systemd service* below).

---

## Building

### On a Linux VPS

```bash
# 1. Install Rust (if not present)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
sudo apt update && sudo apt install -y build-essential

# 2. Get the source
git clone https://github.com/andrey23127/ed2k-server.git
cd ed2k-server

# 3. Build (release)
cargo build --release

# Binary: target/release/ed2k-server
```

### Under WSL on Windows

The server is Linux software; on Windows build it inside **WSL** (a real Linux
environment), not native Windows.

```powershell
# In PowerShell (once): install WSL with Debian
wsl --install -d Debian
```

Then open the **Debian** (WSL) shell and follow the exact same Linux steps
above (`rustup`, `apt install build-essential`, `cargo build --release`). The
resulting binary is a Linux binary — run it inside WSL, or copy it to your VPS.

### CPU optimization via `.cargo/config.toml`

The repo ships a portable `.cargo/config.toml` that bakes the jemalloc memory
tuning into the binary for everyone. It also contains **commented-out** examples
for tuning the binary to a specific CPU. Uncomment **one** block that matches the
machine that will *run* the binary:

- `target-cpu=native` — optimize for the build host (safe if you build on the
  same machine you deploy to).
- `target-cpu=x86-64-v3` — any CPU with AVX2 (Intel since 2013, every AMD Zen).
  **The right choice on a VPS:** the hypervisor may hide instructions the model
  name promises, so a model-specific value such as `znver3` can crash there.
- A model name (`znver3`, `znver4`, `icelake-server`, …) — only on a dedicated
  server whose CPU you know.

**[CPU-TUNING.md](CPU-TUNING.md)** has the full table (AMD, Intel, ARM), how to
check what a machine supports, and how to trace periodic CPU load.

> A binary built for a specific `target-cpu` must only run on that CPU family or
> newer, or it will crash with an illegal-instruction error. When in doubt, leave
> all CPU blocks commented out — the default build runs anywhere.

You can confirm the jemalloc tuning was embedded at runtime:

```bash
ps -T -p $(pgrep -f ed2k-server) | grep jemalloc   # a jemalloc_bg_thd thread = OK
```

The tuning includes `thp:never`: jemalloc's memory is kept out of transparent
huge pages. On a system with THP set to `always` (`cat
/sys/kernel/mm/transparent_hugepage/enabled`) the kernel otherwise counts every
partly used 2 MB page as resident, and RSS ran ~25% above what the server held
(live: 1.20 GB RSS, 0.94 GB held, `AnonHugePages` 938 MB). Check with
`grep AnonHugePages /proc/$(pidof ed2k-server)/smaps_rollup` — near 0 with the
tuning in place. A binary built without it gets the same effect from
`Environment=_RJEM_MALLOC_CONF=thp:never` in the service unit.

---

## Installing on a VPS

### 1. Place the binary

```bash
sudo install -m 0755 target/release/ed2k-server /usr/local/bin/ed2k-server
```

### 2. Configuration and data files in `/etc/ed2k-server`

```bash
sudo mkdir -p /etc/ed2k-server
sudo cp config/config.toml /etc/ed2k-server/config.toml
sudo nano /etc/ed2k-server/config.toml      # replace every CHANGE_ME
```

`config/config.toml` is the only template, and it is set up for a public
server: `public = true`, `max_clients = 5000`, the seed servers, IPv6, and every
data file under `/etc/ed2k-server`, kept current by `[updates]`. (Up to 0.9.77
there were two templates; `config.toml` was a small local test setup — not
public, 1000 clients — and servers started from it by mistake stopped at 1000
users. `config.vps.toml` is gone; its content is `config.toml` now.)

Fill in at least:

| Key | What |
|---|---|
| `server.name`, `server.desc` | how the server appears in eMule server lists |
| `server.this_ip` | the server's public IPv4 |
| `welcome.messages` | the greeting clients see |
| `network.tcp_port` | 4661 in the template; UDP is this + 4, the admin panel is on `admin.port` (8080, localhost only) |
| `limits.max_clients` | 5000 in the template; raise it for a large server (see `LimitNOFILE` below) |

The server **refuses to start** while `server.name` or `server.this_ip` still
read `CHANGE_ME`. Because the unit below discards the server's output, run it
once by hand to see any configuration error before installing the service:

```bash
sudo /usr/local/bin/ed2k-server --config /etc/ed2k-server/config.toml
# Ctrl+C once it is running
```

Put your runtime data files here too (the template already points at them):

- **`ip-to-country.csv`** — GeoIP database for the admin panel's country stats.
  Download and unpack it from
  **https://upd.emule-security.org/ip-to-country.csv.zip**:
  ```bash
  cd /etc/ed2k-server
  curl -O https://upd.emule-security.org/ip-to-country.csv.zip
  unzip ip-to-country.csv.zip      # produces ip-to-country.csv
  ```
  The template's `storage.country_db_path` already points here.

- **`ipinfo_lite.mmdb`** (optional) — a MaxMind DB file, IPv4 **and IPv6**, with
  each network's provider (ASN and name). IPinfo Lite (`ipinfo_lite.mmdb`) and
  MaxMind GeoLite2 Country files both work:
  ```bash
  cd /etc/ed2k-server
  curl -O https://ed2k.emule-security.org/pub/ipinfo_lite.mmdb.zip
  unzip ipinfo_lite.mmdb.zip       # produces ipinfo_lite.mmdb
  ```
  Next to `ip-to-country.csv` it is used instead; when it is missing or unreadable the server falls back
  to the CSV (IPv4 only). Another location: `storage.geoip_mmdb_path`; `"off"`
  disables it. The whole file is held in memory: about 23 MB for IPinfo Lite,
  against about 7 MB for the CSV. IPinfo Lite data is CC BY-SA 4.0 and requires
  attribution to IPinfo.

- **`guarding.p2p`** — IP blocklist in eMule format (same format used by
  emule-security). The template's `storage.ipfilter_path` already points here.

- **Content filter lists** (optional but recommended — see *Content filter*).

Keeping those files current by hand is tedious, and the term and hash lists are
not published in this repository. See **[UPDATE-SERVICE.md](UPDATE-SERVICE.md)**
for pulling them from an update service — or running one — including the
signature checks that make an automatic update safe.

### 3. Run as a systemd service

A ready unit is in `contrib/ed2k-server.service`. Install it:

```bash
sudo cp contrib/ed2k-server.service /etc/systemd/system/ed2k-server.service
# edit paths if needed
sudo systemctl daemon-reload
sudo systemctl enable --now ed2k-server
sudo systemctl status ed2k-server
```

Reload filter lists / config live (no downtime):

```bash
sudo systemctl reload ed2k-server      # sends SIGHUP
```

The unit (excerpt — full file in `contrib/`):

```ini
[Unit]
Description=ed2k index server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ed2k-server --config /etc/ed2k-server/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
StandardOutput=null
StandardError=null
LimitNOFILE=262144

[Install]
WantedBy=multi-user.target
```

> **`LimitNOFILE` matters — size it to `max_clients`, not to the file index.**
> The default 1024 file-descriptor limit is fatally low. File-descriptor usage
> tracks **concurrent client connections**, not the number of indexed files: the
> 33M-entry index lives entirely in RAM and consumes **zero** descriptors. Budget
> roughly one fd per connected client, plus ~10–20 fixed (one TCP + five UDP
> listeners, the admin socket, logging) and a transient margin for outbound HighID
> probes and ephemeral gossip sockets during login storms.
>
> Size it for the worst moment — the **reconnect storm after a restart**, when
> every client logs in again at once: open sockets (`max_clients` + 10% +
> `admission.max_pending_logins`) plus one outbound HighID probe per pending
> login (`admission.max_probe_jobs`). With the `[admission]` defaults that is
> about **121 000 for `max_clients = 50000`**, so the shipped unit sets
> **`262144`**. The server warns at startup if the ceilings exceed the limit.
>
> At startup the server raises its own soft limit to the hard limit (no
> privilege needed), so a unit without `LimitNOFILE`, or a server started from
> a shell or a container, gets the system's hard limit (524288 under current
> systemd) instead of 1024. An explicit `LimitNOFILE` still sets both. If the
> descriptors do run out, accepts pause briefly and the Health tab shows
> "accept failed: out of file descriptors". At 1024 that used to happen at
> ~900–1000 clients, with one core at 100%.

### ⚠️ Logging is OFF by default — on purpose

The provided unit sends `StandardOutput`/`StandardError` to **`/dev/null`**.
**On a busy server, logs grow very fast** and can fill the disk. Logging is
therefore disabled by default. To enable it for troubleshooting:

1. In the unit, change `StandardOutput=null` / `StandardError=null` to `journal`.
2. Optionally set `Environment=RUST_LOG=ed2k_server=debug` for verbose tracing.
3. `systemctl daemon-reload && systemctl restart ed2k-server`, then
   `journalctl -u ed2k-server -f`.

Turn it back off once you're done — `debug` especially is extremely chatty.

---

## Configuration reference

Edit `/etc/ed2k-server/config.toml`. The table below lists the settings and
whether a change applies **live** (via `systemctl reload` / SIGHUP, or by editing
a watched file) or needs a **restart**.

> Rule of thumb: filter lists apply live; anything that changes a listening
> socket needs a restart. When unsure, restart.

### `[server]`
| Key | Meaning | Apply |
|---|---|---|
| `name`, `desc` | Server name / description shown to clients | restart |
| `public` | If `true`, requires a non-empty hash blocklist (enforced) | restart |
| `this_ip` | **Mandatory.** The server's public IPv4. Used for the obfuscation seckey (derived from `this_ip` + `tcp_port`) and identity. | restart |
| `seed_servers` | List of `ip:port` seed servers to gossip with on start | restart |
| `version_major`, `version_minor` | Advertised version — **do not set below 17.15** | restart |

> **`this_ip` is required.** Set it to your server's public IP. The server-to-server
> obfuscation key is derived from `this_ip` + `tcp_port`, so it is stable across
> restarts and rotates automatically only if the IP or port changes.

> **Keep the version at 17.15 or higher.** Lugdunum servers reject servers
> advertising an older version and will not add them to their `server.met`
> (the 17.15 minimum was confirmed from the Lugdunum decompile). The default is
> 17.15; raising it is fine, lowering it gets you silently dropped from peer lists.

### `[network]`
| Key | Meaning | Apply |
|---|---|---|
| `tcp_port` | eD2k TCP port (default 4661). All UDP ports are derived from it (see below) | **restart** |
| `listen_ip` | Bind address for the listeners | restart |
| `listen_backlog`, `max_frame_size` | TCP accept backlog (IPv4 and IPv6 listeners; `0` = 1024; the kernel caps it at `net.core.somaxconn`) / max accepted frame size | restart |
| `max_decompressed_frame_size` | Max bytes one compressed (`0xD4`) frame may decompress to; `max_frame_size` bounds only its compressed wire length, and zlib expands up to ~1000:1. Default 8 000 000; must be at least 1 | new connections |
| `login_timeout_ms` | Login handshake timeout | restart |
| `support_crypt` | Advertise protocol obfuscation support | restart |
| `hairpin_lan_clients` | Let a client on the server's own network reach HighID (see below). Off by default | live |
| `highid_verify_observe` | **Observe only.** After a client gets HighID from the plain TCP probe, also send OP_HELLO in the background and count whether it answers with the user hash that logged in. Nothing changes for the client. Counters on the Status tab, cases in `/api/highid_mismatches`. Default off | live |
| `highid_downgrade_on_wrong_hash` | **Verdict.** The same background check, acted on: a port that answers with a *different* client's user hash marks (IP, port, login hash), and that client's next logins get LowID while the mark lasts (see below). Default off | live |
| `highid_wrong_hash_ttl_secs` | How long a wrong-hash mark lasts. Default 86400 (a day) | live |
| `ipv6_enabled` | Accept clients over IPv6 on the same TCP port, plus an IPv6 UDP socket on `tcp_port + 4`. Separate IPv6-only sockets, so the IPv4 path is unchanged; a host without IPv6 logs a warning and serves IPv4 only. Default off | restart |
| `listen_ip6` | Bind address for the IPv6 sockets. Default `::` | restart |
| `this_ip6` | The server's public IPv6, announced in `OP_SERVERIDENT` when `ipv6_publish_sources` is on. Empty = not announced | live |
| `ipv6_publish_sources` | Publish IPv6 sources to clients that can parse them, and advertise the extension in `OP_IDCHANGE` and UDP pings. Independent of `ipv6_enabled`. Default off | live |

> **UDP ports are derived from `tcp_port`, not configured.** The eD2k protocol
> fixes the whole UDP block relative to the TCP port, and seed servers compute a
> peer's ports the same way, so there is nothing to set:
>
> | Port | Purpose |
> |---|---|
> | `tcp_port + 4` | main eD2k UDP (searches, sources) |
> | `tcp_port + 8` | auxiliary UDP |
> | `tcp_port + 12` | server-to-server obfuscated ping |
> | `tcp_port + 14` | `portUDPobf` (obfuscated UDP) |
>
> Earlier versions had a separate `udp_port` key that had to be kept at
> `tcp_port + 4` by hand; a wrong value silently broke discovery. It has been
> removed. A stale `udp_port = ...` left in an old `config.toml` is ignored, so
> existing configs keep working without edits.

> **`hairpin_lan_clients` — for running a client on the same network as the
> server.** In that topology the client reaches the server through the router's
> hairpin NAT, so the login arrives from an RFC1918 address and the ordinary
> HighID probe refuses to even try: there is nothing useful to connect to at a
> private address. With this on, the server falls back to probing
> `server.this_ip` on the client's port — in that topology the client's public
> address is by definition the server's own.
>
> It runs only after the ordinary probe has already decided LowID, so it can add
> a HighID but never take one away, and it requires the peer to answer a
> client-to-client handshake with **the user hash that just logged in**. That
> check is what makes it safe: where a router source-NATs hairpin traffic, every
> local client arrives from the same address and cannot be told apart, so a port
> forward may well lead to a different machine. Without the identity check the
> server would hand the public address out as a source for the wrong host.
>
> Off by default because a server in a datacentre may see private addresses from
> a management network that has nothing to do with its public address.

> **HighID hello check (`highid_verify_observe`, `highid_downgrade_on_wrong_hash`).**
> HighID is decided by a TCP connect to the client's address and port. That
> proves *something* is listening there, not that it is this client. Behind a
> NAT shared by two eD2k clients — two machines at home, or strangers behind a
> provider's CGNAT where one of them has the port open — both claim the default
> port, the forward leads to one of them, and the other one used to get a HighID
> every peer is sent to the wrong machine by.
>
> With either option on, a client that passed the connect is also sent a
> client-to-client `OP_HELLO` in the background, and the user hash in its
> answer is compared with the one that logged in (the two client-type marker
> bytes are ignored: some clients send MLDonkey's in the hello and eMule's at
> login). The login is **never delayed** — a synchronous check was tried, and
> clients whose login is still pending mostly do not answer in time.
>
> In verdict mode a *different* hash marks (IP, port, login hash) for
> `highid_wrong_hash_ttl_secs`, and that client's next logins get LowID
> immediately, which lets it be reached through server callback. Its first
> session keeps the HighID. Every later login re-checks in the background: its
> own hash again (forwarding fixed) clears the mark, a wrong hash renews it.
>
> **No answer never costs HighID.** A silent close or a reset is what eMule's IP
> filter does to us, a timeout proves nothing, and Lugdunum-style "no answer →
> LowID" would take HighID from clients that are in fact reachable. Only a
> positive answer from another client counts. The hairpin path above is
> separate and unchanged.

### `[limits]`
| Key | Meaning | Apply |
|---|---|---|
| `max_clients` | Max concurrent logged-in clients, also advertised (`ST_MAXUSERS`). Reserved atomically before the login does any work, so concurrent logins cannot overshoot it. A login beyond it gets "Server full" and is closed; a client replacing its own stale session is always let in. `0` = no cap | live |
| `max_clients_per_ip` | Max open TCP connections per client IP — per `admission.ipv6_source_prefix_bits` prefix for IPv6 — checked at accept before any work is done. Loopback is exempt; `0` = no cap. The Status tab shows the busiest IP — the address with the most logged-in clients, with its open connections — so you can check the value against real traffic (a provider NAT puts many users behind one address) | live |
| `soft_limit_files`, `hard_limit_files` | Advertised to clients (`ST_SOFTFILES` / `ST_HARDFILES`) and enforced with Lugdunum semantics. `soft_limit_files` is the per-client indexing budget: new files beyond it are not indexed and the client gets one server message per connection; re-offers of files it already sources and filtered files use no budget; the session stays up. `hard_limit_files` is a per-packet bound: an `OFFERFILES` declaring that many records or more is rejected and the connection closed — keep it well above 200 (the eMule batch size). `0` disables either | live |
| `max_string_size` | Max bytes STORED for a file name or nick (cut at a character boundary). The content filter always sees the full name first. `0` = no cap | live |
| `ping_delay_seconds` | Server keep-alive ping interval | restart |
| `max_search_results` | Results returned per search, across all pages; best-sourced first. Default 200, ceiling 5000. One value for every client — unlike Lugdunum, which varies it by zlib support and halves it for LowID | live |
| `search_rank_scan` | Candidates examined when ranking one search. Past it, ranking covers only what was seen; the share of searches that hit it is shown on the Status tab. Default 20000, must be ≥ `max_search_results` | live |
| `index_subtokens` | Also index letter/digit pieces of each word, so `S01E08` is found by `s01` and `e08`, `1080p` by `1080`. Changes what searches return, so off by default. Read once at startup: the index must split names the same way for its whole life. **Not a superset of Lugdunum**: a query that starts mid-run (`1x05` against `01x05`) is still not found | restart |
| `search_drop_unknown_words` | Ignore query words that no indexed file contains instead of returning nothing because of them (a typo no longer empties the search). A query of only unknown words still returns nothing; OR branches and negated words are never rewritten. Default on | live |

### `[content_filter]`
| Key | Meaning | Apply |
|---|---|---|
| `hash_banlist` | L3 ban-list file path(s) — blocked **and** counted against the publisher | **live** (file edit / reload) |
| `hash_filter` | L5 filter-only file path(s) — blocked, publisher **not** accused | **live** |
| `extra_terms_file` | L4 operator extra terms | **live** |
| `jargon_terms_file` | L1 jargon list | **live** |
| `layer2_terms_file` | L2 vocabulary (see below) | **live** |
| `whitelist_hashes_file` | Hash false-positive overrides (wins over every layer) | **live** |
| `publisher_attempt_disconnect_threshold` | Distinct blocked files tolerated before a publisher is banned (ban fires on the next one) | restart |
| `publisher_count_window_seconds` | How far back those files are counted. Defaults to `publisher_blacklist_seconds` | restart |
| `publisher_blacklist_seconds` | Ban duration (by user-hash) | restart |

> `hash_banlist` was `hash_blocklists` and `hash_filter` was `poison_hashes`
> before 0.9.71; the shipped filenames changed to match. See *Content filter*.

### `[updates]`

Optional; disabled by default. Fetches the filter data files from an update
service, verifies an Ed25519 signature over them, validates them with the same
parser that loads them at runtime, keeps rotating backups and installs
atomically. Full description, including how to run a service:
**[UPDATE-SERVICE.md](UPDATE-SERVICE.md)**.

| Key | Meaning | Apply |
|---|---|---|
| `enabled` | Master switch | live |
| `dest_dir` | Where files are installed; must match the paths above | live |
| `public_key` | Ed25519 public key (32 bytes, hex) files must be signed with | live |
| `require_signature` | Refuse anything unsigned. Leave on | live |
| `key_reference_ip` | The server whose exported peer table the service loaded | live |
| `backups` | Generations kept as `<name>.1` … `<name>.N` | live |
| `min_keep_ratio` | Refuse a replacement that shrinks the list below this fraction | live |
| `export_url`, `export_token`, `export_interval_secs` | Peer table export | restart |
| `[updates.urls]` | Per-file URLs | live |

> **`public_key` is public and `export_token` is not.** The key verifies a
> signature and cannot create one, so it is safe to ship and to commit. The token
> lets its holder push a peer table to the service and is issued per server —
> never copy one out of a repository, and never commit yours.

Updates are triggered from the **Health** tab, which lists every data file with
what is on disk and an **Update** button. The three hash lists additionally offer
**Update & merge**, which unions the download with the file already installed,
comparing hashes only and keeping whichever side carries the comment.

Nothing is written unless the signature verifies, the file parses and it would
not collapse the list — a failed update leaves the current file in place and says
why.

### `[storage]`
| Key | Meaning | Apply |
|---|---|---|
| `ipfilter_path` | Path to `guarding.p2p` | **live** (SIGHUP reload) |
| `country_db_path` | Path to `ip-to-country.csv` (IPv4) | restart; a new file at the path reloads live |
| `geoip_mmdb_path` | MaxMind DB tried before the CSV (IPv4 + IPv6). Empty = `ipinfo_lite.mmdb` next to the CSV; `"off"` = CSV only | restart; a new file at the path reloads live |

### `[admission]`
Server-wide ceilings on the work remote peers can cause, however the load is
spread across addresses, listeners and address families (issue #25). All are
**restart-only** (the admin config editor says so when they change, including
the open-socket ceiling derived from `max_clients`), and none accepts `0` — a
zero ceiling is refused at startup.
The whole section is optional; the defaults are below.

The defaults are sized for the load the server is designed for — **50 000
clients (about 45 000 of them LowID) and 30 000 000 files** — and for its worst
moment, a restart, after which every client reconnects at once. Each value
leans high: a ceiling costs memory only while it is in use, whereas one that is
too low refuses real users. The pending-login pool is the one a restart
stresses: a login holds its slot through the obfuscation handshake, the login
and the HighID probe, and for a LowID client, whose port does not answer, the
probe lasts the whole `network.login_timeout_ms`. On a live server a restart
with 9 000 clients overflowed 4 096 pending slots, a peak above 0.45 pending per
client — about 23 000 at 50 000 clients; the default is 32 768. A smaller
server can lower these to save memory during the storm, but need not.

| Key | Default | When full |
|---|---|---|
| `max_open_tcp_connections` | `max_clients` + 10% + `max_pending_logins` (200 000 if `max_clients` = 0) | the socket is closed at accept, before a task exists. Keep it under `LimitNOFILE`; the server warns at startup if it is not |
| `max_pending_logins` | 32 768 | same — sockets still in handshake or login, including the HighID probe. IP-filtered addresses are dropped before they take a slot. Sized for the reconnect storm after a restart (see below) |
| `max_pending_logins_per_source` | 32 | same, per source (IPv4 address, IPv6 prefix), so a few sources cannot hold the whole pending pool. Loopback exempt |
| `max_probe_jobs` | `max_pending_logins` + 64 | HighID probes, at login and in the background together (background checks are at most 64, so logins always find one). A login that finds none free gets **LowID** at once rather than waiting |
| `max_retry_tasks` | 1024 | hole-punch re-coordination is skipped; one pending retry per (requester, target) pair at most |
| `session_relay_per_second`, `session_relay_burst` | 10, 200 | per session, callback and hole-punch requests. Over it a callback gets `OP_CALLBACK_FAIL`; a hole-punch request is ignored |
| `max_search_jobs` | 8 | searches run off the async runtime, at most this many at once |
| `max_queued_tcp_searches`, `tcp_search_wait_ms` | 512, 2000 | a TCP search waits in arrival order behind at most this many others, for at most this long, then gets an empty result |
| `max_queued_udp_searches`, `udp_search_wait_ms` | 128, 500 | a UDP search waits the same way, from a task (never in the receive loop), in its own smaller queue so UDP cannot crowd out TCP; beyond it, dropped |
| `max_rate_state_entries` | 524 288 (≈ 50 MB at most) | UDP sources tracked at once; a new source beyond it is refused. Idle entries are forgotten every 30 s |
| `ipv6_source_prefix_bits` | 64 | IPv6 addresses sharing this prefix are one source (UDP budgets and the TCP per-IP limit). IPv4 is per address; IPv4-mapped IPv6 counts as its IPv4 |
| `udp_global_credits_per_second`, `udp_global_burst_credits` | 200 000, 400 000 | server-wide UDP budget, checked first |
| `udp_source_credits_per_second`, `udp_source_burst_credits` | 60, 1000 | per-source UDP budget, checked second |
| `udp_rate_enforce` | `false` | **Off = observe:** over-budget UDP packets are counted but still served. Watch the counters on the Status tab, adjust the budgets, then set `true` to drop them |
| `readiness_window_secs` | 30 | `/api/ready` returns 503 once open sockets, pending logins or search jobs have stayed full this long |

UDP costs, in credits: every datagram 1 on arrival (before any parsing);
an obfuscated datagram that misses the decode cache +4; a search +9; a source
request +1 per file hash (up to 64); a server-list request or response +20.
Every UDP listener and both address families share the same budgets.

`GET /api/admission` returns every gauge and counter (fixed cardinality, no
addresses); the Status tab shows a one-line summary. `GET /api/ready` is
readiness, separate from the diagnostic `/api/health`.
`contrib/overload_test.py` with `contrib/overload_test.toml` drives a running
server past every ceiling and checks that it stays bounded and recovers.

### `[admin]`
| Key | Meaning | Apply |
|---|---|---|
| `enabled` | Enable the admin web panel | **restart** |
| `port` | Admin panel port (localhost-only) | **restart** |

### `[log]`, `[welcome]`, runtime
| Key | Meaning | Apply |
|---|---|---|
| `log.level`, `log.connection_trace` | Log verbosity (see logging note above) | restart |
| `welcome.messages` | MOTD lines sent on login | restart |
| `worker_threads` | Tokio worker threads. Default 1 (single-threaded runtime); 0 is treated as 1 | restart |

**Live changes that take effect without a restart:** the CSAM filter lists —
**L1 jargon**, **L3 ban list(s)**, **L4 extra terms**, **L5 filter list(s)** and
the **hash whitelist** — all reload automatically within ~30 s of editing the
file, or immediately on `systemctl reload` / `POST /api/reload`. Copy list files
with `cp` and **not** `cp -p`: the watcher polls mtime, so preserving timestamps
means nothing reloads.

Changes take effect on **search results and source lists**, not just on new
publications — a hash added to either list disappears from what the server serves
within one reload cycle, with no restart.

---

## Content filter (CSAM)

The filter runs on every offered file and cannot be disabled. It has five layers:

- **L1 – jargon list** — known marker terms. The list is **not shipped** with the
  source (publishing a catalog of such terms is itself harmful). Supply your own
  via `jargon_terms_file`. Operators obtain indicators from authoritative bodies
  (INHOPE, IWF, NCMEC). Absent ⇒ L1 inactive; the other layers still run.
- **L2 – age + sexual-context heuristics** — compiled into the binary, works out
  of the box, no data file needed. This is the main heuristic layer.
- **L3 – ban list** (`hash_banlist`) — exact known-file hashes. Obtain from
  authoritative sources (NCMEC, IWF, Project Arachnid / C3P). These lists are
  typically licensed and **must not be redistributed** — keep them private.
  A hit here counts against the publisher.
- **L4 – operator extra terms** — optional additive substrings.
- **L5 – filter list** (`hash_filter`) — blocked like anything else, but the
  block carries **no accusation**: it does not raise `csam_attempts` and does not
  count toward `publisher_attempt_disconnect_threshold`.

### Why L3 and L5 are separate lists

Two things belong in `hash_filter`: **decoys** — one hash advertised under a
dozen unrelated names, a 700 MB file claiming at once to be a music compilation,
a film and an office installer — and **takedown requests**, where a rightsholder
complaint means the file should leave the index and says nothing about whoever
happens to share it.

Keeping those in the ban list did two kinds of damage: it pushed ordinary users
toward a ban for downloading a decoy, and it diluted a list whose whole value is
that every entry means one specific thing. `/api/review` reports blocklisted
hashes carrying several unrelated names or a size their extension cannot hold —
those are the candidates to move.

### Whitelist

`whitelist_hashes_file` overrides **every** layer, not just the hash lists. The
false positives that actually occur are term matches — song titles that happen to
contain a marker word, or historical texts whose title does — so an override that
left the term layers running did nothing for the one class of mistake that
happens in practice.

### Layer 2: age plus context

Layer 2's word lists live in `layer2_terms_file` rather than in the binary, and
hot-reload like the other lists. They change often, and a rebuild-and-restart per
change costs every connected client. With no file configured the built-in
vocabulary is used, which is what the server did before the option existed; a
file replaces the sections it names and leaves the rest alone. An unknown section
name rejects the whole file and keeps the previous lists, because a typo would
otherwise silently empty a category.

Layer 2 normally needs BOTH an age claim and a sexual term, so a birthday video
is not caught. Three refinements to that rule:

- **Ages of 12 and under stand alone.** Below 13 an age written into a filename
  is the anomaly by itself — legal material does not label participants "11yo".
  Only the compact notations (`yo`, `yr`) qualify; `12 years` is ordinary English
  and keeps the pairing rule, or "12 Years a Slave" would be blocked. Guard words
  near the number (`whisk`, `malt`, `service manual`) disqualify it.
- **Non-English contexts.** Russian minor/sexual word lists were added after a
  search sample found files with both halves written in plain Russian and nothing
  in any list covering them. These are ordinary words and work only behind the
  pairing rule — measured against legitimate Russian titles, a bare term list
  matched nine of thirteen.
- **Fixed innocent phrases override everything** (`SEX_TERM_EXCEPTIONS`). Some
  broad terms are common words inside set expressions — an idiom that is also a
  film title, the name of a school subject. Naming the phrase keeps the term
  usable; narrowing the term instead cost five of six real catches in testing.

Filenames damaged by repeated UTF-8/Latin-1 round-trips are recovered and
re-tested, so a CJK marker mangled into `Ã¥Â¹Â¼` still matches.

### Term matching

L1 and L4 share one matcher. A term is classified by length: **≥6 chars** →
substring match, **≤5** → word-boundary match. Three refinements matter:

- A long term must not begin immediately after an ASCII letter. Without this a
  six-character term that is a suffix of an ordinary English word fires inside
  it — one such term was a suffix of a common medical word and blocked every
  paper mentioning it.
- Digits and `_` separate, letters bind: `term_001`, `2term` and `term2011` all
  match, `aterm` and `termly` do not.
- A trailing `$` on a term additionally forbids digits and `_` after the match.
  Use it only when the term is the start of a longer innocent word.

Terms in CJK are exempt from the boundary rules — that script has no word
separators, so they match as plain substrings wherever they appear.

Template/format files are provided as `config/*.example`. The real list files are
git-ignored and never committed. Format: one entry per line, `#` comments allowed
(`;` inline comments too in the hash lists).

---

## NAT traversal (server side)

eD2k clients behind NAT get a **LowID** (no routable address). This server helps
such clients still exchange data, acting purely as a lightweight **coordinator**
— it relays small address packets over the TCP control channel it already has to
every logged-in client, and **never relays file data** (that would turn a light
index server into a bandwidth relay).

Two mechanisms are active:

- **Classic callback (HighID ↔ LowID).** When a HighID client wants a file from a
  LowID client, it sends `OP_CALLBACKREQUEST(low_id)`. The server validates the
  requester is HighID, finds the LowID client by its assigned id, and forwards
  `OP_CALLBACKREQUESTED(requester_ip, requester_port)` so the LowID side connects
  *out* to the reachable requester. On failure it returns `OP_CALLBACK_FAIL`.

- **LowID ↔ LowID hole-punch coordination.** Two LowID clients normally cannot
  connect at all — neither is reachable, so the stock callback doesn't help. Some
  eMule mods solve this with a Kademlia "buddy" HighID relay; this server needs
  neither Kad nor a third party. The flow (`src/server/holepunch.rs`):
  1. LowID **A** sends `OP_LOWID_HOLEPUNCH_REQUEST(target_id = B, requester_udp_port)`.
  2. The server looks up **B** among connected clients.
  3. The server sends `OP_LOWID_HOLEPUNCH_INFO` to **both** A and B, each carrying
     the other side's `(ip, tcp_port, udp_port, user_hash)` plus a role byte.
  4. Both clients fire UDP packets at each other simultaneously; with cone NAT on
     both sides this opens the path and a direct connection forms.

  The server sends only those two small address packets, and best-effort re-sends
  them a couple of times over the next few seconds so a lost/late packet on the
  TCP link doesn't leave the peers punching at non-overlapping times.

  > **Limitation (by design, not a bug):** hole punching works when each side's
  > public UDP port is predictable from what the server observed — i.e. **cone
  > NAT** (including cone-type carrier-grade NAT). If either side is behind a
  > **symmetric** NAT/CGNAT (a different external port per destination), the punch
  > fails. There is no server-only fix without relaying data, which this server
  > deliberately refuses, so the feature is best-effort.

  To keep each client's observed public UDP endpoint fresh, clients send a
  periodic UDP NAT-T keepalive; the server also enables OS TCP keepalive on each
  accepted socket so a dropped NAT mapping is detected in ~5 minutes (and kept
  warm in the meantime).

### Implementing a compatible client (wire contract for eMule mods)

If you maintain an eMule mod and want your client to use this server's LowID↔LowID
NAT-T, this is the complete interface. Nothing else in the eD2k protocol changes,
and every tag/opcode below is backward-safe — a non-NAT-T client simply omits them.

**1. Advertise capability at login.** Add tag `CT_EMULE_UDPPORTS` (`0xF9`) to the
login request, value `((kadUDPPort << 16) | clientUDPPort)`. This tells the server
your client UDP port and flags you as NAT-T capable. Lugdunum-style servers already
parse `0xF9`, so sending it is safe against any server.

**2. Refresh your external UDP port — the keepalive (critical).** While connected,
send `OP_SERVER_NATT_KEEPALIVE` (`0x9F`) **from your client UDP socket** (not the TCP
link) to the server's UDP port (`= server TCP port + 4`), payload = your 16-byte
userhash, about every 60 s. The server reads the *source* port of this datagram to
learn your real post-NAT UDP port — the port peers must actually punch.

> **Timing invariant — do not get this wrong.** This server trusts an observed
> external UDP port for **600 s** (`OBSERVED_UDP_FRESH`). Your keepalive interval
> must stay well under that — ~60 s gives a 10× margin. If it lapses, the server
> falls back to your *announced* internal port and hands peers a port your NAT never
> opened. The symptom is distinctive and easy to misdiagnose: **freshly connected
> peers download fine, but hole punching stops a few minutes after connect** until a
> reconnect. The `0x9F` keepalive also doubles as your liveness signal (step 5), so a
> share-only LowID client must keep sending it.

**3. Client ↔ server opcodes** (travel over `OP_EDONKEYPROT`, the server link):

| Opcode | Value | Direction | Payload |
|---|---|---|---|
| `OP_LOWID_HOLEPUNCH_REQUEST` | `0x60` | client → server (TCP) | `<target_id 4><our_udp_port 2>` |
| `OP_LOWID_HOLEPUNCH_INFO` | `0x61` | server → both (TCP) | `<peer_ip 4><tcp 2><udp 2><userhash 16><role 1>` |
| `OP_LOWID_HOLEPUNCH_FAIL` | `0x62` | server → client (TCP) | `<target_id 4><reason 1>` |
| `OP_SERVER_NATT_KEEPALIVE` | `0x9F` | client → server (UDP) | `<userhash 16>` |

To download from a LowID source **B**, send `0x60` with B's assigned id and your UDP
port. The server replies `0x61` to **both** you and B — each gets the other's address
plus a role byte — or `0x62` if B is HighID, gone, or has a dead session. On `0x61`
both sides punch and raise the tunnel; on `0x62` retry or fall back. The `role` byte
is advisory: in the reference client both sides initiate, so order does not matter.
(`0x60`–`0x62` are unused in the server TCP opcode space, which runs `0x01`–`0x44`,
and `0x9F` was free in the server UDP namespace — no conflict on the server link.)

**4. Peer ↔ peer opcodes** (over `OP_EMULEPROT`, sent directly between the two
clients — **the server never sees these**; listed only so the full path is clear):
`OP_NATT_HOLEPUNCH` (`0xB3`, opens the pin-hole), `OP_NAT_SYN` / `OP_NAT_SYN_ACK`
(`0xD0`/`0xD1`, tunnel handshake), `OP_NAT_DATA` (`0xD2`, carries the tunnel packets),
and `0xD3`–`0xD7` (ack/close/reset/ping). The transport *inside* the tunnel is the
mod's own choice — the reference mod runs a UserModeTCP-over-QUIC tunnel — and the
server is agnostic to it. Both sides should send SYN (symmetric handshake) so the
peer behind the stricter NAT opens its own mapping; a per-run 4-byte session nonce on
`0xB3`/`0xD0`/`0xD1` lets a peer restart be detected and the stale tunnel rebuilt.

**5. Keep your LowID source alive.** A share-only client is TCP-silent for hours.
This server keeps such a source by **(a)** counting your `0x9F` UDP keepalive as
activity against the session idle timer (idle backstop is 900 s, refreshed by any
TCP frame *or* the UDP keepalive), **(b)** enabling OS TCP keepalive on the accepted
socket (first probe at 60 s, then every 30 s, give up after 8 → ~5 min) to keep the
NAT mapping warm and reap a genuinely dead peer, and **(c)** tolerating a multi-minute
NAT outage during a heavy transfer before reaping. The same 5 minutes bound data the
server has sent and the client has not acknowledged (`TCP_USER_TIMEOUT`, Linux): a
connection whose path has gone dark is dropped then, not after the ~15 minutes of
kernel retransmission. Your only obligation is to keep
sending the `0x9F` keepalive; the rest is the server's bookkeeping. Get the cadence
wrong and a live share-only source is silently evicted after a few minutes — the
symptom is identical to a successful connection, which makes it easy to misdiagnose.

---

## IPv6

Off by default; two independent switches in `[network]`:

- `ipv6_enabled` — **accept** clients over IPv6. A separate IPv6-only TCP
  listener on `tcp_port` and UDP socket on `tcp_port + 4`; the IPv4 sockets are
  untouched.
- `ipv6_publish_sources` — **publish** IPv6 sources to peers that can parse
  them. Kept separate because it changes what other peers receive.

An eD2k client id is a 32-bit IPv4 address, so there is no such thing as an
IPv6 HighID. A client connected over IPv6 is LowID on IPv4 by construction and
is never probed. What IPv6 adds is a second way to reach a LowID client: its
IPv6 address, handed to peers as a source.

### Wire contract

Agreed with the two other implementations that speak it, eMuleQt and eNode-go.
Every element is ignored by a client that does not know it.

| Direction | Element | Value | Meaning |
|---|---|---|---|
| client → server | login tag `CT_MOD_IP_V6` | `0xAE`, 16 raw bytes | the client's public IPv6 |
| client → server | `CT_SERVER_FLAGS` bit | `0x1000` | client can parse IPv6 sources |
| server → client | `OP_IDCHANGE` flags / UDP ping flags bit | `0x4000` | server speaks the extension |
| server → client | `OP_SERVERIDENT` tag `ST_IPV6` | `0xAE`, 16 raw bytes | the server's IPv6 (`this_ip6`) |
| server → client | `OP_SERVERIDENT` tag `ST_IPV6_STATUS` | `0xAB`, u8 | `0x01` address held, `0x02` treated as reachable |
| server → client | source record in `OP_FOUNDSOURCES` / UDP answer | id `0xFFFFFFFF`, port, then 16 bytes | an IPv6 source |

The client-flag bit (`0x1000`) and the server-flag bit (`0x4000`) are different
numbers on purpose; they must not be "unified".

Rules the server applies:

- The address a session actually arrived from is preferred over the one the
  tag claims: an observed address over an asserted one.
- Only a globally usable IPv6 is published — never link-local, unique-local,
  loopback, multicast or IPv4-mapped.
- An IPv6 record is sent only for a source that is LowID on IPv4 (a HighID
  source is reachable already), and only to a requester that can parse it: a
  TCP client that sent the tag or connected over IPv6, or a UDP query that
  arrived over IPv6.
- Answers carrying IPv6 records bypass the source cache, which is shared with
  clients that cannot parse them.

What else covers IPv6:

- **Country and provider** — from a MaxMind DB (`ipinfo_lite.mmdb`); the CSV
  knows IPv4 only. See *Installing on a VPS* → *Configuration and data files*.
- **Bot detection and its 24-hour bans, the per-IP connection limit and the
  UDP budgets** count an IPv6 client by its /64 (`admission.ipv6_source_prefix_bits`):
  a host has a whole /64 to rotate through, so per-address counting would never
  see a flood. An IPv4-mapped address counts as its IPv4.
- **Not covered: the IP filter.** `guarding.p2p` carries IPv4 ranges only.

---

## Server lists & IP filter

- **Seed servers** (`server.seed_servers`): get a current list from
  **https://www.emule-security.org/serverlist** or **https://peerates.net/**.
- **IP filter**: the server reads **guarding.p2p** in the same format used by
  emule-security / eMule (`start_ip - end_ip , level , description`). Per-range
  block-hit statistics are available in the admin panel's *Filter* tab.

---

## Admin web panel & SSH tunnel

The admin panel binds to **localhost only** (`127.0.0.1:<admin.port>`, default
8080) and is **not** exposed to the internet. To reach it from your PC, forward
the port over SSH.

### With PuTTY (Windows)

1. Open **PuTTY**. Enter your VPS host/IP under *Session*.
2. In the left tree: **Connection → SSH → Tunnels**.
3. **Source port:** `8080` · **Destination:** `127.0.0.1:8080` · select
   **Local**, then click **Add** (you should see `L8080  127.0.0.1:8080`).
4. Go back to **Session**, save it, and **Open** — log in as usual.
5. While that session is connected, open **http://127.0.0.1:8080/** in your
   browser. You now see the panel served from the VPS.

> If the page is unreachable, the tunnel is down (e.g. the SSH session dropped or
> the server restarted) — reconnect the PuTTY session. The localhost binding is by
> design; nothing in the server needs changing.

Command-line SSH (Linux/macOS/WSL) equivalent:

```bash
ssh -N -L 8080:127.0.0.1:8080 user@your-vps
```

The panel shows live status, connected clients, peers/servers, filter info and
per-range IP-filter hits, blocks, and memory metrics (RSS plus the non-evictable
in-use bytes and per-file cost). The Status tab also carries search counters
(ranking cap hits, unknown words dropped), IPv6 clients and publishers, the
HighID hello-check counters, and the busiest IP: the address with the most
logged-in clients behind it (a NAT or CGNAT), with its open connections, to
check `limits.max_clients_per_ip` against.

`GET /api/memsize` breaks memory down by structure. Per connection it reports
the codec buffers (`clients_framed_buffers`), the obfuscation buffers and keys
(`clients_crypt_buffers`), the connection tasks (`clients_tasks_est`: live
tasks × the size of one, measured at spawn) and the push channels of logged-in
clients (`clients_push_channels_est`).

The *Clients* tab searches on the server: free text matches an address or a
nick (case-insensitive), an IPv4 CIDR such as `82.48.0.0/16` matches by
network, and country, software and High/LowID narrow it further; results are
sorted and paged 100 at a time. The same filter is available as
`GET /api/clients/search?q=&country=&software=&id=high|low&sort=connected|files|ip|nick|country|software&dir=asc|desc&offset=&limit=`
(limit at most 500). `GET /api/clients` still returns every connected client
for scripts.

The *Peers* tab shows each listed server's name, description and version (its
answer to UDP `0xA2`), its user and file counts (`0x96`), and its country. Each
peer is asked at most once an hour on UDP `TCP+4`; a peer that answers only
obfuscated UDP shows "no answer".

Country flags are drawn with a font built into the binary (a 78 KB Twemoji
subset), because Windows has no flag glyphs and Chrome, Edge and Opera there
showed two letters instead. The page loads nothing from other hosts.

`GET /api/highid_mismatches` exports the recent wrong-hash cases of the HighID
check (the last 1000) with a summary: which answering clients are connected
from the same address, repeated addresses and hashes, and whether a mark was
set. `?anonymize=1` replaces each address with its /24 plus a per-process salted
tag, so repeats stay visible and the export can be shared.

---

## License

Released under the **MIT License** — see [`LICENSE`](LICENSE).

## Credits

- A clean-room, independent reimplementation inspired by the original **Lugdunum**
  eserver and the broader **eMule / eDonkey2000** community.
- GeoIP and server-list data courtesy of emule-security.org and
  [peerates.net](https://peerates.net/).
- IP address data in `ipinfo_lite.mmdb`, when used, is powered by
  [IPinfo](https://ipinfo.io) (CC BY-SA 4.0).
- Country flags in the admin panel: [Twemoji](https://github.com/twitter/twemoji)
  graphics (CC-BY 4.0), as subset into the "Twemoji Country Flags" font by
  [country-flag-emoji-polyfill](https://github.com/talkjs/country-flag-emoji-polyfill)
  (MIT); see `assets/TwemojiCountryFlags-LICENSE.md`.

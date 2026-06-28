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
- Memory-optimized in-memory index (sharded slab, intrusive hash index, name
  interning, jemalloc tuning) — roughly **half the RAM** of the Lugdunum
  reference at the same scale.
- **Mandatory multi-layer CSAM content filter** on every published file
  (age+context heuristics in code; operator-supplied jargon, hash, and
  extra-term lists loaded at runtime — see *Content filter* below).
- Server-to-server **gossip** with obfuscation; mldonkey/junk-server filtering
  via verification.
- **NAT traversal (NAT-T)** hole-punch coordination for LowID↔LowID transfers.
- IP filtering in eMule **guarding.p2p** format, with per-range hit statistics.
- GeoIP country stats, bot/scanner detection, CSAM-publisher banning.
- Built-in **admin web panel** (status, clients, peers, filters, blocks,
  settings) bound to localhost.
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
git clone https://github.com/<your-user>/ed2k-server.git
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
- `target-cpu=znver3` — AMD Zen 3 (Ryzen 5000 / EPYC 7003). This is what the
  reference VPS uses. Other values: `znver2`, `znver4`, `skylake`,
  `icelake-server`, or `x86-64-v3` (portable baseline for most CPUs since ~2015).

> A binary built for a specific `target-cpu` must only run on that CPU family or
> newer, or it will crash with an illegal-instruction error. When in doubt, leave
> all CPU blocks commented out — the default build runs anywhere.

You can confirm the jemalloc tuning was embedded at runtime:

```bash
ps -T -p $(pgrep -f ed2k-server) | grep jemalloc   # a jemalloc_bg_thd thread = OK
```

---

## Installing on a VPS

### 1. Place the binary

```bash
sudo install -m 0755 target/release/ed2k-server /usr/local/bin/ed2k-server
```

### 2. Configuration and data files in `/etc/ed2k-server`

```bash
sudo mkdir -p /etc/ed2k-server
sudo cp config/config.vps.toml /etc/ed2k-server/config.toml   # then edit the CHANGE_ME fields
```

Put your runtime data files here too and point the config at them:

- **`ip-to-country.csv`** — GeoIP database for the admin panel's country stats.
  Download and unpack it from
  **https://upd.emule-security.org/ip-to-country.csv.zip**:
  ```bash
  cd /etc/ed2k-server
  curl -O https://upd.emule-security.org/ip-to-country.csv.zip
  unzip ip-to-country.csv.zip      # produces ip-to-country.csv
  ```
  Set `storage.country_db_path = "/etc/ed2k-server/ip-to-country.csv"`.

- **`guarding.p2p`** — IP blocklist in eMule format (same format used by
  emule-security). Set `storage.ipfilter_path = "/etc/ed2k-server/guarding.p2p"`.

- **CSAM filter lists** (optional but recommended — see *Content filter*).

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
LimitNOFILE=65536
Environment=RUST_LOG=ed2k_server=info

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
> Rule of thumb: **`LimitNOFILE` ≈ 2 × `max_clients`**. The shipped `65536` is
> ample for the default `max_clients = 1000`. For a large public server it is
> **tight**: at `max_clients = 50000` it leaves only ~15k headroom, which a login
> burst (each new HighID login opens a short-lived outbound probe socket) can eat
> into. For 50k clients prefer **`131072`**; scale up from there if you raise
> `max_clients` further.

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
| `tcp_port` | eD2k TCP port (default 4661) | **restart** |
| `udp_port` | eD2k UDP port — **must be `tcp_port + 4`** (default 4665) | **restart** |
| `listen_ip` | Bind address for the listeners | restart |
| `listen_backlog`, `max_frame_size` | Socket / frame tuning | restart |
| `login_timeout_ms` | Login handshake timeout | restart |
| `support_crypt` | Advertise protocol obfuscation support | restart |

> **`udp_port` must equal `tcp_port + 4`.** The server-to-server gossip protocol
> derives a peer's UDP port as TCP+4, and seed servers compute ours the same way.
> Any other pairing silently breaks discovery — seeds will not add you to their
> `server.met`. The default 4661/4665 already satisfies this; keep the +4 offset
> if you change the ports.

### `[limits]`
| Key | Meaning | Apply |
|---|---|---|
| `max_clients` | Max concurrent clients | restart |
| `max_clients_per_ip` | Per-IP connection cap | restart |
| `soft_limit_files`, `hard_limit_files` | Per-client offered-file limits | restart |
| `max_string_size` | Max accepted string length | restart |
| `ping_delay_seconds` | Server keep-alive ping interval | restart |

### `[content_filter]`
| Key | Meaning | Apply |
|---|---|---|
| `hash_blocklists` | L3 hash-blocklist file path(s) | **live** (file edit / reload) |
| `extra_terms_file` | L4 operator extra terms | **live** |
| `jargon_terms_file` | L1 jargon list | **live** |
| `whitelist_hashes_file` | Hash false-positive overrides | restart |
| `publisher_attempt_disconnect_threshold` | Max tolerated distinct CSAM files before banning a publisher (ban fires on the next one) | restart |
| `publisher_blacklist_seconds` | Ban duration (by user-hash) | restart |

### `[storage]`
| Key | Meaning | Apply |
|---|---|---|
| `ipfilter_path` | Path to `guarding.p2p` | **live** (SIGHUP reload) |
| `country_db_path` | Path to `ip-to-country.csv` | restart |

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
| `worker_threads` | Tokio worker threads (0 = auto) | restart |

**Live changes that take effect without a restart:** the CSAM filter lists —
**L1 jargon**, **L3 hash blocklist(s)**, **L4 extra terms** — reload automatically
within ~30 s of editing the file, or immediately on `systemctl reload` /
`POST /api/reload`.

---

## Content filter (CSAM)

The filter runs on every offered file and cannot be disabled. It has four layers:

- **L1 – jargon list** — known marker terms. The list is **not shipped** with the
  source (publishing a catalog of such terms is itself harmful). Supply your own
  via `jargon_terms_file`. Operators obtain indicators from authoritative bodies
  (INHOPE, IWF, NCMEC). Absent ⇒ L1 inactive; the other layers still run.
- **L2 – age + sexual-context heuristics** — compiled into the binary, works out
  of the box, no data file needed. This is the main heuristic layer.
- **L3 – hash blocklist** — exact known-file hashes. Obtain from authoritative
  sources (NCMEC, IWF, Project Arachnid / C3P). These lists are typically licensed
  and **must not be redistributed** — keep them private.
- **L4 – operator extra terms** — optional additive substrings.

Template/format files are provided as `config/*.example`. The real list files are
git-ignored and never committed. Format: one entry per line, `#` comments allowed.
L1 classifies a term by length (≥6 chars → substring match; ≤5 → word-boundary
match). All three list files hot-reload without a restart.

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
NAT outage during a heavy transfer before reaping. Your only obligation is to keep
sending the `0x9F` keepalive; the rest is the server's bookkeeping. Get the cadence
wrong and a live share-only source is silently evicted after a few minutes — the
symptom is identical to a successful connection, which makes it easy to misdiagnose.

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
in-use bytes and per-file cost).

---

## License

Released under the **MIT License** — see [`LICENSE`](LICENSE).

## Credits

- A clean-room, independent reimplementation inspired by the original **Lugdunum**
  eserver and the broader **eMule / eDonkey2000** community.
- GeoIP and server-list data courtesy of emule-security.org and
  [peerates.net](https://peerates.net/).

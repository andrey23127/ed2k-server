# Changelog

Earlier releases are described in their release commit messages.

## 0.9.84

Bot detection that stops banning ordinary users, scanners into the IP filter
for good (and off their TCP sessions), search activity per source to find
better criteria, and LowID hole punching: the support flag (issue #35), the
right UDP port for two clients behind one IP (#37), the peer ID in 0x61
(#38). One new optional
section, `[bots]`.

### Bots

- **A short burst is not a flood.** A source is judged only once its queries
  span `bots.min_span_secs` (10 s). Thirty packets in 15 ms read as
  "120 000 qpm" and earned a 24-hour ban, though the source had sent 67
  requests in all: an aMule user, partly behind a VPN exit.
- **"Uniform timing" is throttled, not banned.** That pattern (about 567 qpm,
  one hash per packet, a few dozen files, from many countries) is one
  client build with broken UDP pacing: ordinary users, who lost every UDP
  source answer for a day. They are now throttled for 24 h to
  `bots.throttle_qpm` (60) and still answered; `bots.uniform_action = "ban"`
  restores the old behaviour. A flood is still banned.
- **Scanners into the IP filter.** A banned source that keeps sending through
  its ban (`bots.ipfilter_min_dropped`, 10 000 dropped datagrams; ten times
  that if throttled) is appended to `storage.ipfilter_path` as
  `071.231.168.221 - 071.231.168.221 , 000 , bot`, only if no line covers it
  yet, and the filter is reloaded at once. The address is recorded in
  `bot-ipfilter.txt` next to the config and put back whenever the filter file
  is replaced (the update service installs it whole). The ledger gets an
  `ipfilter_added` event. Seen in the field: one source sent 243 804 datagrams
  into its ban, walking a list of 4 600 files.
- **The IP filter applies to UDP too**, not only to TCP connections: the
  scanners it now catches scan over UDP.
- **The IP filter file is watched**: a change on disk is applied within 30 s.
  Before, only SIGHUP or `/api/reload` reloaded it.
- **A new IP filter closes the TCP sessions it now blocks.** The filter was
  read only when a connection was accepted, so a scanner added to it stayed
  logged in until it reconnected (seen: 3 hours). Every filter swap (a bot
  added, the file changed, SIGHUP, `/api/reload`) now wakes each session to
  check its own address. Counted as `ipfilter_kick`.
- The Bots tab shows THROTTLED and IP FILTER next to BANNED.

### Scanners and hammers, over TCP too

Seven hours of `/api/activity` (91 000 sources) showed where the rate rules
fall short. An ordinary eMule asks its server for sources of 15 files every
5 minutes, about 180 an hour, however long its download list; the busiest
ordinary source stayed under 1 000. Two kinds of source did not, and nearly
all of them over TCP, where nothing was judged before:

- **Scanners**, walking a list: 2 000 to 20 000 files an hour, nearly all
  different (one asked 3 900 files in 6 minutes). New rule: at least
  `bots.scan_min_files` (2 000) files in an hour, at least
  `bots.scan_min_distinct` (1 000) different → `scan_action` ("ban").
  Over the 7 hours it matches 4 to 7 sources.
- **Hammers**, the same file or two up to 10 times a second, mostly one
  mobile client build: at least `bots.hammer_min_files` (3 000) in an hour,
  fewer than `bots.hammer_max_distinct` (100) different → `hammer_action`
  ("throttle": `throttle_qpm` answers a minute, the session stays). About
  20 sources.
- Both count TCP `OP_GETSOURCES` and UDP source requests by file, per
  source, over an hour from its first request. Different files are
  estimated from the 200th file on, so most sources cost a counter only.
- A bot ban now covers TCP: its sessions are closed and it can't log in for
  the 24 hours (`bot_kick`, `bot_tcp_refused`). A throttled source's TCP
  source requests beyond its allowance go unanswered.
- `"log"` as an action only writes the match to the log and the ledger.

### Search activity (temporary)

The rate detector misses a list scanner: one walked 4 400 files at about 150
requests a minute, below the 200 qpm a source needs to be looked at, and was
caught before only because a burst of its requests read as 605 qpm. What sets
such a source apart is how many different files it asks about. To pick that
threshold, and others, from real traffic:

- Per source (IPv4 address, IPv6 /64): searches over TCP and UDP, "more
  results" pages and results; source requests over TCP and UDP, files per
  request, files asked and different files (HyperLogLog, ±13%, no hash
  kept); gaps between requests, the busiest minute, requests per hour.
- `GET /api/activity`: totals, requests by UTC hour, and the spread of each
  figure over sources (mean, p50/p90/p99/p99.9, max) with histograms.
  `GET /api/activity/sources`: one row per source, sortable, as JSON or
  `format=csv`. `POST /api/activity/reset` starts a new period.
- The distinct-files estimate mixes each hash first: sources asking 700
  files were estimated at 6 000, from hashes with long runs of zero bytes.
  It is also never above the files asked.
- `bots.activity_stats` (on) and `bots.activity_max_sources` (100 000
  records, about 200 bytes each; further sources only in the totals). Both
  apply from the Settings tab without a restart.

### LowID hole punch flag (issue #35)

- `OP_IDCHANGE` TCP flags carry `0x20000` (`SRVFLG_LOWID_HOLEPUNCH`): this
  server accepts `OP_LOWID_HOLEPUNCH_REQUEST` (0x60). A client that knows
  both this scheme and Lugdunum's NAT callback (`0x1000`) can now tell which
  one a server runs, and send 0x60 only where it is understood. Free of every
  bit in use: 0x05DD, 0x1000, 0x4000, 0x8000, 0x10000.
- The IPv6 contract in the README no longer lists `CT_SERVER_FLAGS` `0x1000`.
  On Lugdunum that bit is `SRVCAP_NATTRAVERSAL`; eMuleQt withdrew it and aMule
  stops sending it. This server only ever keyed on the `CT_MOD_IP_V6` tag.

### Hole punch: per-client UDP port (issue #37)

- The UDP port handed to a peer in `OP_LOWID_HOLEPUNCH_INFO` came from a map
  keyed by IP and written by every 0x9F and every global query from it. With
  two LowID clients behind one public IP, the last packet won, and a client
  was told its own port as its peer's. Now each client's last 0x9F source
  port is kept by user hash and preferred; the per-IP port is used only for
  a client alone on its IP; the announced port comes last.
- A 0x9F counts only from the session's own IP: a user hash is no secret,
  and a keepalive from elsewhere could have sent the client's peers there.
- The 0x60 port, the client's local one, no longer replaces a keepalive port.
  Global queries (aMule sends them from TCP + 3) no longer either.
- The port is dropped with the session, so a reconnect from another address
  does not inherit it.

### Hole punch: peer ID in 0x61 (issue #38)

- `OP_LOWID_HOLEPUNCH_INFO` ends with `peer_id(4)`, the server ID of the
  peer described: the requester gets its 0x60 target, the target gets the
  requester. A requester can now keep several 0x60 in flight and match each
  answer, where before it had only the TCP port (often 4662) to go by. The
  payload is 29 bytes; clients read the ID only from 29 bytes or more.

### NAT-T documentation (issue #36)

- The README no longer points client authors at the eMule 0.72a "NAT-T
  edition": it is retired. Its tunnel used `0xB2` frame type `0x01`, which
  is eMuleAI's QUIC. The peer-to-peer part of the contract now says only
  what the server relies on.
- New table of `0xB2` frame types in use (eMuleAI, emule-qt), so that new
  clients pick a free one.
- Nothing changes on the server: `0x60`-`0x62`, `0x9F` and the `0x20000`
  flag stay, for aMule and any other client that wants server-coordinated
  hole punching.

## 0.9.83

Two fixes to how the server answers eMule's status ping on UDP TCP+12; media
metadata stored and searched as Lugdunum does, and search filters on sources
(issue #31); obfuscated LowID callbacks (issue #32); two IPv6 source fixes
(issues #33, #34); SERVERIDENT sent as Lugdunum does, for eMule mods that
dropped the connection; client versions, a closer look at bots with a ledger of
them, and providers on every tab with a country. One new optional key,
`storage.bot_log_path`. Compatible with every eMule since obfuscation appeared
(0.48a), 0.49c included.

### eMule's crypt ping (UDP TCP+12)

With obfuscation on, eMule pings a server with a "crypt ping" on TCP+12: a
nonzero 4-byte challenge plus `rand() % 16` bytes of padding (eMule
`ServerList.cpp`). The answer gives it the server's UDP key; right after it,
eMule asks for the server's name on the obfuscation port.

- Pings of all lengths, 4 to 19 bytes, are answered. The longest one, 15 bytes
  of padding, one in sixteen of eMule's pings, went unanswered, and eMule then
  waited 20 s and fell back to a plain ping.
- The reply carries the same UDP flags as the plain 0x97 and `ST_UDPFLAGS`. It
  still sent Lugdunum's 0x17FB, left behind when the flags became 0x073B.

### Search filters (issue #31)

- The minimum-availability filter eMule and aMule send (FT_SOURCES, 0x15) now
  works, and so does one on complete sources (0x30). Both compare against the
  same counts a result carries. Before, both were ignored.
- Length, bitrate and codec filters (0xD3-0xD5, or eMule's "length",
  "bitrate", "codec" names) are judged from the stored media fields (below).
  As in Lugdunum, a file offered without them has zeros: `length >= 3000`
  leaves it out, `length < 600` keeps it, and a codec no file was offered with
  matches nothing. A string codec filter used to be matched against the file
  name, so `codec = h264` kept only files with "h264" in the name.
- Artist, album and title (0xD0-0xD2) are matched as words of the file name,
  as Lugdunum does; it does not store them either.
- A filter the server cannot judge is removed from the expression, not
  answered "yes": `A NOT x` is `A`. Length and bitrate filters used to be
  answered "yes", so `A NOT length>3000` returned nothing.
- Type and format filters also accept the tag names "type" and "format", not
  only the IDs 0x03 and 0x04.

### Media metadata

Length, bitrate and codec from OP_OFFERFILES (0xD3-0xD5 or the old string
names; length also as text, "1:30:00") are stored and sent back in search
results, TCP and UDP, as Lugdunum does. Lugdunum keeps them in its file
record; here they sit in a side table per slab shard, 8 bytes packed per
file (27-bit length, 29-bit bitrate, codec as an index into a table of up to
255 names, lowercased and cut to 19 bytes as Lugdunum keeps them), because
only 13.7% of offers carry any of them (measured on 18.6M offers, with 129
distinct codecs). About 21 bytes per media file, 3 bytes per file on
average; `/api/memsize` shows it as `slab_media_cap`. A re-offer fills fields
the file lacks and keeps the ones it has. `GET /api/media_stats` counts the
media tags per offer since start and what is stored now.

### IPv6 sources

- **The sentinel goes to a LowID requester only (issue #33).** A HighID
  requester that can parse IPv6 records got a LowID source's IPv6 instead of
  its low id, and with it lost the callback, which always works for a HighID
  requester. The IPv6 comes from the login tag, unchecked, and many routers
  drop inbound IPv6, so the dial often failed with nothing to fall back on. A
  HighID requester now gets the classic record (and the source cache again);
  a LowID requester, which cannot use a callback, keeps the IPv6 route.
- **A client can update or withdraw its IPv6 within a session (issue #34).**
  New client-to-server opcode `OP_IPV6_UPDATE` (0x63): 16 bytes, the new
  address, or zeros to withdraw it. Announced by a new `OP_IDCHANGE` flag,
  `0x8000`, set with `0x4000` (`ipv6_publish_sources`); 0.9.82 sets `0x4000`
  without knowing the opcode, so a client sends it only to a server that set
  `0x8000`. Same rules as the login tag; ignored on a session that arrived
  over IPv6, whose observed address stays.

### SERVERIDENT after GETSERVERLIST, as Lugdunum (MorphCA, ZZUL-TRA)

Some eMule mods connected, got their ID and dropped the connection a second
later, in a loop: MorphCA 2.2, and by the reports ZZUL-TRA 2.6 and
UltiMatiX. MorphCA's release build skips the server IP and port of
OP_SERVERIDENT only in debug builds (the two reads sit inside an
`#if _DEBUG` block), so it reads the IP as the tag count, parsing fails and
the exception ends the session. Lugdunum never sent it SERVERIDENT: it sends
the packet only in answer to OP_GETSERVERLIST, which MorphCA never sends.
This server sent it to everyone at login.

Now, as Lugdunum: SERVERIDENT follows SERVERLIST in the answer to
OP_GETSERVERLIST. At login it goes only to a client that needs it there: one
that asked for OFFERFILES v1 (whose policy tags it carries) or speaks the
IPv6 extension (`ST_IPV6`). Clients still learn the name and description
over UDP (0xA2) as before.

### Obfuscated callbacks (issue #32)

OP_CALLBACKREQUESTED was always the 6-byte form (requester IP and port). When
the requester and the LowID target both announced obfuscation support
(CAPABLE_SUPPORTCRYPT) at login, it is now the 23-byte form Lugdunum sends:
the requester's crypt options (CT_SERVER_FLAGS bits 9-11) and its user hash.
Without the hash the LowID client cannot derive the obfuscation key, so its
callback connection went out in plain TCP, and a requester that requires
obfuscation refused it. eMule and aMule read the long form from 23 bytes up
and ignore the extra bytes otherwise.

### Admin panel

- **Client versions.** The version in CT_EMULE_VERSION was read only for its
  client ID and the rest thrown away. Clients now show as `eMule v0.70b`,
  `aMule v2.3.3`, `mldonkey v3.1.6`, with the mod in brackets when the client
  sends CT_MOD_VERSION. The *Client Software* chart lists the versions under
  each family, and the client search matches them. The software filter still
  works on the family.
- **Login fingerprint**, as a tooltip on the software: CT_VERSION, server
  flags and the tag IDs in the order sent. Two programs that both report eMule
  v0.50a rarely log in the same way.
- **Bots.** Each detection now shows what the source sent: searches, source
  requests and hashes per request, the obfuscated share, its UDP port and port
  changes, and which of our ports it wrote to. Also the TCP client logged in
  from the same address, if any, with version and nick. Before, a detection
  showed a rate and nothing that could tell one program from another.
- **Provider (ASN)** from `ipinfo_lite.mmdb` on the *Peers* and *Bots* tabs,
  as on *Clients* already.
- **Files a bot asks for.** The hashes of its source requests are kept (the
  last 64, up to 20 000 distinct), also after the ban: a banned source's plain
  source requests are still read, not answered, and counted. The tab shows
  the dropped count and when the last one came; clicking the hash count lists
  the files with names, sizes and sources, and the other bots that asked for
  the same files. `GET /api/bots/detail?ip=`.
- **Bot ledger.** Each detection and each ban end is appended as a JSON line
  to `bot-log.jsonl` next to the config file (`storage.bot_log_path`, `"off"`
  to disable), so the record survives restarts; `GET /api/bots/log?tail=N`.
  `GET /api/bots/export?format=csv` exports the detections since start. Both
  carry hashes, not file names.
- **Files the bots asked for, with names.** `GET /api/bots/files` (CSV, or
  `?format=json`): every hash the bots asked for since start, with the name,
  size and sources of the ones we index and the bots that asked;
  `?ip=` for one bot, `?indexed=1` for indexed files only.

### Other

- `CHANGELOG.md` itself was missing from the repository; it is added here.

## 0.9.82

Optional password login and HTTPS for the admin panel, so it can be reached
over a VPN or the network as well as through an SSH tunnel. The server makes
its own certificate; no domain is needed.

### Upgrade notes

- Two new optional keys under `[admin]`: `bind` (default `127.0.0.1`) and
  `password_hash` (default empty). With neither set nothing changes: loopback,
  no login, SSH tunnel.
- A `bind` other than loopback without `password_hash` stops the server at
  startup with an explanation.
- New command: `ed2k-server --hash-password` asks for a password and prints the
  `password_hash` line.
- New optional keys for HTTPS: `tls` (default `"off"`), `tls_cert`, `tls_key`,
  `tls_ca_cert`, `tls_ca_key`, `tls_names`. New command
  `ed2k-server --make-admin-ca DIR --admin-ca-names LIST`.
- The panel now answers only to `Host` headers carrying an IP address,
  `localhost` or a name in `admin.tls_names`. If you open it by a domain name,
  add the name to `tls_names`.
- With `tls = "self-signed"` the server writes `admin-cert.pem`,
  `admin-cert.pem.json` and `admin-key.pem` next to the config file, so that
  directory must be writable by the server user (it already is when
  `updates.dest_dir` points there).

### Admin panel

- Login with a password hash in `config.toml`: PBKDF2-HMAC-SHA256, random salt,
  600 000 iterations (at least 100 000 accepted). Session cookie `HttpOnly`,
  `SameSite=Strict`, 12 hours, kept in memory.
- With a password set, every page and API call needs a session from any
  address, the SSH tunnel included.
- Five wrong passwords per address (per /64 for IPv6) per ten minutes, then
  429 for that address; fifty from everywhere together stop remote logins for
  the window, never loopback. Hash checks run one at a time on a blocking
  thread, at most four waiting.
- `Host` check against DNS rebinding (421 for any other name), in every mode,
  with or without a password.
- Every connection, HTTP or HTTPS, is served by one accept loop with limits:
  64 connections, 16 per address, 30 s for request headers, five minutes per
  connection; the login form at most 4 KB within 10 s.
- Saving settings from the panel keeps `config.toml`'s permissions (a new file
  would have taken the umask, typically world-readable).
- State-changing requests from another site are refused, login or not:
  `Sec-Fetch-Site` decides when the browser sends it (HTTPS, loopback), else
  `Origin` must name the panel's own host. Every response carries
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and
  `Referrer-Policy: same-origin`. (`no-referrer` made browsers send
  `Origin: null` on the panel's own forms, so login and every button failed
  with "cross-site request refused"; checked in Chromium over plain HTTP,
  through the tunnel and over HTTPS.)
- The server key in the Status tab, and the update access key on the Updates
  tab, are shown only to requests from loopback.
- Log-out button in the header when a login is configured.
- A non-loopback `bind` without `tls` logs a startup warning: the panel then
  speaks plain HTTP.

### HTTPS for the admin panel

- `tls = "self-signed"`: on first start the server makes an ECDSA P-256 key
  and a certificate covering its address (the bind address, or
  `server.this_ip` on `0.0.0.0`), `127.0.0.1`, `::1`, `localhost` and
  `tls_names`. The SHA-256 fingerprint is logged at startup and shown on the
  Status tab, to compare with what the browser shows before accepting.
- Lifetime 397 days; replaced 30 days before the end, or when the names or the
  CA change, by a check every six hours, without a restart. What a certificate
  was made with is kept next to it (`<cert>.json`), so no certificate parser
  is needed.
- `ed2k-server --make-admin-ca DIR --admin-ca-names LIST` makes a CA (ten
  years), name-constrained to the listed addresses, networks and DNS names
  plus loopback, so an imported CA cannot vouch for anything else. With
  `tls_ca_cert` and `tls_ca_key` set, server certificates are signed by it:
  import the CA on the managing PC once and every server opens without a
  warning. The CA is checked against its key at startup, and a certificate
  that would need a name outside the CA's limits is refused with an
  explanation.
- Over HTTPS the cookie is `__Host-ed2k_admin`: only accepted with `Secure`,
  for this host and path `/`.
- Keys and certificates are written through fresh temporary files (`O_EXCL`,
  key mode 0600). In "files" mode a pair that fails to load is retried at the
  next check.
- `tls = "files"`: your own certificate (Let's Encrypt). Re-read when the files
  change.
- Over HTTPS the session cookie is marked `Secure`. If HTTPS cannot be set up,
  the server does not start: falling back to plain HTTP would send the password
  in clear on an address meant to be protected.
- Served with rustls (already in the tree) on hyper; at most 64 connections at
  a time, a 10 s handshake and a 30 s header timeout.
- README: the password setup, and one SSH connection for several servers on
  one machine.
- README: how to make `password_hash` (`--hash-password`, also from a script),
  and `bind = "0.0.0.0"` against the external IP, a VPN address or a private
  address behind NAT.

- `http://` on the HTTPS port is redirected (302) to `https://` on the same
  port; the server tells the two apart by the first byte. Only `GET`/`HEAD`
  with an accepted `Host` are redirected, anything else gets a 400.
- README, OFFERFILES v1 contract (issue #19): the re-offer rule (refreshes the
  source, no soft-budget slot, counted like any record; the searchable name is
  not part of the contract) and how versions evolve. No behaviour change.
- README: what Chrome's "Not secure" means for an accepted self-signed
  certificate, and the CA as the way to a normal padlock.

### Several servers on one IP

Peers that run more than one server on the same address (different TCP
ports) were mixed up, because the obfuscation state was kept per IP.

- Seed ServerKeys, incoming seed challenges and our sent random parts are now
  kept per server (IP and TCP port), and the decode cache per sender (IP and
  UDP port). Before, the second server's key overwrote the first, and gossip
  or the peer-info probe to one of them failed or was decoded with the wrong
  key.
- An obfuscated packet from an IP with several known servers is decoded with
  each of their keys in turn.
- An obfuscated status reply is matched to the server we pinged (from its
  UDP source port and the advertised `portUDPobf`), not to TCP = port − 4,
  which is wrong for replies from the obfuscation ports.
- Server lists, the verification probe, cleanup, `/api/peers` and the peer
  export look at each server by IP and port, so a verified server does not
  vouch for another one on the same IP, and every server gets its own row.

### Other

- 14 new unit tests: PBKDF2 against RFC 7914 and a 4096-iteration vector, hash
  round trip and refusal of malformed hashes, per-address lockout and session
  expiry, cookie and form parsing; TLS modes, covered names, a certificate made
  once and kept, renewal before the end, a CA-signed certificate verified as a
  browser would (and refused for another address), a CA paired with the wrong
  key refused, replaced files picked up; IPv6 failures per /64 and the global
  lock that spares loopback; CA name limits and a CA refusing an address
  outside them.
- New direct dependencies: `getrandom` 0.2.17 (already in the tree), `rcgen`
  0.12.1 (ring backend), `tokio-rustls` 0.25.0, `pem` 3.0.5, `time` 0.3.36,
  `rustls-pki-types`, `hyper` and `hyper-util` (already in the tree).
  `powerfmt` is pinned to 0.2.0 because 0.2.1 needs Rust 1.79.

## 0.9.81

The content filter reads ages written with French, Italian, Dutch and
Scandinavian year units; an OFFERFILES v1 pacing fix for intervals above a day.

### Upgrade notes

- No configuration keys added or removed. Nothing to change in the operator
  vocabulary files.

### Content filter

- Layer 2 reads "N ans", "N anni", "N jaar" and "N år" as age claims, and "N
  yop" as well. Like "N years", they block only together with a sexual term
  and never on their own, whatever `unpaired_age_max` is.
- The duration guard covers the same languages: "3 ans après", "5 anni dopo",
  "10 jaar geleden", "2 år senare" / "sedan", and Spanish "3 años después" are
  time spans, not ages. The last one is a live false positive from the 10.10
  review window (an adult studio's title). Italian "fa" ("ago") is deliberately
  not a guard: it is also the verb "does", and as a guard it let a real file
  through on the corpus.
- Measured on 123 563 names (review corpus, two captures of served results,
  link samples): 11 newly blocked, all material; nothing unblocked.

### OFFERFILES v1 (issue #19)

- Fixed: an `offerfiles_min_interval_ms` above one day let extra full batches
  through at once. The pacer capped a batch's cost at one day, which made a
  full batch cheaper than the bucket's depth (with two days, the second and
  third batch went immediately). The cap is now far above the largest interval
  the setting can hold. The 500 ms default was never affected.
- Corrected a comment on `offerfiles_global_records_per_sec`: the ceiling does
  not speed up one client. A 55,000-file library takes about 137 s at the
  default pace, not 11 s.

### Other

- 2 new unit tests (the new age units pair like "years", never block alone,
  ignore adult ages and respect the duration guard; an interval above a day
  still paces every batch).
- README, OFFERFILES v1 contract: one advertisement per connection (the first
  valid one is binding, a later SERVERIDENT changes nothing, slowing down does
  not lift the batch size), the batch size a v1 client sends, and what a
  legacy connection is and is not held to (issue #19). Documentation only;
  the server already behaved this way.

## 0.9.80

OFFERFILES v1 now applies only to clients that ask for it (issue #19), and
the content filter reads simplified-Chinese ages.

### Upgrade notes

- No configuration keys added or removed. With `offerfiles_v1 = true`, clients
  that do not ask for v1 at login are now treated exactly as with it off.
- A v1 client must now ask: string-named uint32 tag `offerfiles_v` = 1 in its
  `OP_LOGINREQUEST`. A client built against the 0.9.79 contract, which only
  read the advertisement, now receives none and publishes at the legacy pace
  until it sends the tag.

### OFFERFILES v1 (issue #19)

0.9.79 advertised v1 to every login and enforced it on every connection. The
server cannot tell a client that reads the advertisement from one that does
not, and the rules are not neutral for the second kind. One day on the live
server (about 189 thousand logins):

- 2.8 thousand OFFERFILES declaring more than `offerfiles_batch_max` records
  came from clients that had never seen the limit; under v1 those batches are
  not indexed;
- the server-wide ceiling held up nearly every publisher, up to 53 s, average
  about 0.6 s.

Now:

- A client asks for v1 with a string-named uint32 tag `offerfiles_v` (the
  highest version it implements, 1) in `OP_LOGINREQUEST`. Absent, another
  type or 0 means legacy.
- Only a client that asked, with v1 on and valid, gets the `offerfiles_*`
  tags and the snapshot of soft/hard in `OP_SERVERIDENT`, and only its
  connection is held to the batch limit, its pace and the server-wide
  ceiling.
- Every other client gets the SERVERIDENT and the publishing behaviour of v1
  off.
- Status tab and `/api/stats`: new counter "logins asked" (`requested`).
- Fixed: "waited for the server-wide ceiling" counted every batch, including
  those that went straight through; it now counts waits of 1 ms or more.

### Content filter

- Layer 2 reads the simplified-Chinese age suffix, as it already did the
  Japanese, traditional-Chinese and Korean ones. Measured on 110 454 names
  (review corpus, captures, link sample): 16 newly blocked; in the 09.10
  review window: 8 (partly the same names). All material, nothing unblocked.

### Other

- 1 new unit test, 3 new integration tests (a client that does not ask is a
  legacy client even with v1 on; the ceiling does not touch legacy publishers
  next to a v1 one; asking while v1 is off changes nothing). The contract tests
  now log in with the request tag.

## 0.9.79

Fast publishing for clients that can be told how fast they may go (issue
#19), and search ties no longer favour one range of file hashes (issue #14).
Nothing changes for an existing configuration: the new capability is off by
default, and the content filter is untouched.

### Upgrade notes

- New keys in `[limits]`, all optional: `offerfiles_v1` (default `false`),
  `offerfiles_batch_max` (200), `offerfiles_min_interval_ms` (500),
  `offerfiles_global_records_per_sec` (5000). `config/config.toml` lists them,
  turned off.
- With `offerfiles_v1 = true` the server needs `soft_limit_files > 0` and
  `hard_limit_files` above `offerfiles_batch_max`. Otherwise it logs an error,
  advertises nothing and behaves as before; it does not refuse to start.

### OFFERFILES v1 (issue #19)

Legacy clients publish at most 200 files a minute, because a Lugdunum server
may black out an IP that publishes faster; a 55,000-file library then takes
four and a half hours to appear. With `offerfiles_v1` on:

- The post-login `OP_SERVERIDENT` carries `offerfiles_v = 1`,
  `offerfiles_batch_max` and `offerfiles_min_interval_ms` (string-named
  `uint32` tags), together with `ST_SOFTFILES` and `ST_HARDFILES`. All five
  come from one snapshot taken at login and hold for the whole connection; a
  configuration change reaches new logins only.
- Each such connection has a token bucket in file records: one batch deep,
  refilled at `batch_max` per interval. An early batch waits for its turn and
  is never dropped; the connection reads nothing more meanwhile, so the client
  is held back by TCP. Frames pushed at the client (callbacks, hole-punch)
  are still delivered while it waits.
- A server-wide ceiling on records per second from all v1 connections, served
  in arrival order, so a reconnect wave of fast publishers slows each of them
  down instead of saturating the content filter. Default 5000/s, about a
  quarter of a core at the measured ~54 us per published record.
- A batch above `offerfiles_batch_max` but below the hard limit is not
  indexed and is counted; the session stays up. The hard limit, the soft
  budget and the content filter work as for every client.
- A session replaced by a newer login of the same user while its batch was
  waiting does not index that batch.
- Clients that do not read the advertisement, and every client when the
  option is off, see a byte-identical `OP_SERVERIDENT` and unchanged
  publishing.
- Status tab: the active policy, sessions advertised, batches and records,
  waits for the connection's own pace and for the ceiling (count, total,
  longest, waiting now), oversized batches. Same figures in `/api/stats`
  (`offer_v1`).
- README: new section "OFFERFILES v1" with the wire contract.

The client side is aMule PR #1715 (experimental, opt-in). The integration
tests include the contract tests 3togo drafted for that PR, adapted to the
final configuration keys, plus the cases listed in that draft as follow-up
work: invalid configurations, live change with a connection open, filtered
records and the soft budget, the server-wide ceiling with two publishers, and
the option off.

### Search ties (issue #14)

- Results with equal source counts used to be ordered by file id, lower
  first, described as oldest first. A file id is `shard << 26 | slot`, with
  the shard chosen by the file hash and slots reused a minute after an
  eviction, so it meant "hashes of shard 0 first" on every query. Ties are
  now broken by a per-query hash of the file hash, keyed per process: the
  same query still answers identically, different queries keep different
  files, and no age or hash-range bias remains. TCP and UDP search rank the
  same way.
- A condensed multi-episode tag such as `S01E01E02E03` (more than six runs)
  is not split into sub-tokens, so a search for `s01` does not reach it. Now
  documented in the tokenizer and pinned by a test.

### Other

- 9 new unit tests (pacing arithmetic with a controlled clock, the
  configuration rules, the tag encoding, arrival-order service, the tag rule
  above), 15 new integration tests.

## 0.9.78

The release removes the ~1000-user ceiling several operators ran into, ships a
single configuration template, cuts memory per indexed file by about a fifth
and makes the content filter about four times faster. What the filter blocks
and serves is unchanged.

### Upgrade notes

- **`config/config.vps.toml` is gone; `config/config.toml` is now the only
  template** and holds what `config.vps.toml` held: a public server,
  `max_clients = 5000`, seed servers, IPv6, every data file under
  `/etc/ed2k-server` kept current by `[updates]`. An existing
  `/etc/ed2k-server/config.toml` is not affected. The old `config.toml` was a
  small local test setup (not public, `max_clients = 1000`); servers started
  from it stopped at 1000 users once 0.9.77 enforced `max_clients`.
- **The server refuses to start while `server.name` or `server.this_ip` still
  read `CHANGE_ME`**, and names the key. The unit discards output, so run the
  binary once by hand after editing a fresh template (README, *Installing on a
  VPS*).
- `limits.max_clients` defaults to 5000 when the key is absent (was 1024).
- Rebuild from the repository's `.cargo/config.toml`: it now embeds
  `thp:never` in the jemalloc options (see *Memory*). A binary built without
  it gets the same with `Environment=_RJEM_MALLOC_CONF=thp:never` in the unit.
- `LimitNOFILE` in the unit still decides the descriptor limit. Without it the
  server now raises its own soft limit to the system's hard limit.

No configuration keys were added or removed.

### The ~1000-user ceiling

- **Out of file descriptors, the accept loop spun.** Every client is a socket,
  and the usual soft limit is 1024 — a unit without `LimitNOFILE`, a shell,
  screen or a container. At ~1000 clients `accept()` failed with EMFILE; the
  connection stayed queued, the loop retried at once, one core went to 100%
  and no client was admitted. Reproduced with 100 descriptors and 300
  connections: 0.9.77 logged 1.76 million "accept failed" lines in 9 s. The
  loop now pauses 100 ms on EMFILE/ENFILE/ENOBUFS/ENOMEM and logs the error at
  most once a minute, with a hint to raise `LimitNOFILE`.
- **The soft open-files limit is raised to the hard limit at startup** (no
  privilege needed; 524288 under current systemd).
- **One template**, see *Upgrade notes*.

### Bugs

- **GETSOURCES cache served wrong lists.** The cached reply was built with the
  first requester already removed: that source was hidden from everyone else
  for the cache lifetime (5 s), and every later requester got its own address
  back. The reply is now cached with every source and each requester's own
  record is cut out when served. Live, the cache hit rate rose from 0.9% to
  8.3%.
- **A file could be dropped while it had a source.** Eviction decided
  "sourceless" and removed the file under separate locks; a publish in between
  lost the file until all its sources left. The check and the removal now
  happen under one lock.
- **Searches could miss fresh files during keyword compaction** (and return
  removed ones): the deferred additions and removals were taken out before the
  merged list was written. They are now subtracted only after it is in place.
- **Masquerade detection** compared names by pointer, so every same-name
  re-publish counted as a different name. Names are compared by content.
- Each connection kept a second, unused push channel for its whole life.

### Memory

Measured with `examples/loadgen` (5 M files): 274.5 → 226.6 bytes per file of
RSS. On the live server the file structures take ~169 bytes per file.

- **Keyword index**: the compressed tier is 1024 shards of sorted keys, offsets
  and one byte arena instead of a hash map with an allocation per keyword —
  8 bytes per keyword besides the posting itself.
- **File record 80 → 64 bytes**: the name is a single thin pointer with a
  4-byte length instead of `Arc<str>` (20 bytes less per file), and the unused
  `last_seen` and the separate `alive` flag are gone. Re-publishing a known
  file allocates nothing.
- **Records are stored in chunks**, so growing the index no longer copies a
  whole shard (tens of MB at 30 M files) under its lock.
- **Transparent huge pages**: with THP set to `always`, the kernel counted
  partly used 2 MB pages as resident. Live: RSS 1.20 GB against 0.94 GB held,
  `AnonHugePages` 938 MB. jemalloc now runs with `thp:never`; RSS matches what
  the server holds.
- **Per connection**: the connection task is 1.3 KB instead of 5.3 KB, the
  obfuscation buffer keeps at most 512 bytes after sending (it kept the
  largest frame's buffer, up to 64 KB), and RC4 keys are only allocated for
  obfuscated connections.
- `/api/memsize` reports per-connection memory: `clients_crypt_buffers`,
  `clients_tasks_est`, `clients_push_channels_est`. `/api/memsize` and
  `/api/memdebug` no longer allocate a list of every file and run off the
  network thread.

### CPU

From a profile of the live server (14 000 clients, 5.9 M files), where the
content filter was about a quarter of all CPU time:

- **Content filter term layers ~4× faster** (25.6 → 6.0 µs per allowed name).
  One Aho-Corasick pass finds which terms can match at all; only those go
  through the unchanged word-boundary rules, in list order, so the same term
  fires and is reported.
- **Filter verdicts for served files are cached** (GETSOURCES over TCP and UDP,
  search results); any list change invalidates them at once.
- **Search**: the filter runs only for results that make the list; terms are
  folded once per search, not per candidate; a one-word search reads only as
  much of the word's file list as it examines; UDP search copies only the
  results it keeps.
- **OFFERFILES** batches of more than 8 files are processed off the network
  thread when a slot is free.
- **List reloads** (file watchers, SIGHUP, `/api/reload`, IP filter) read and
  parse off the network thread.
- **Keyword compaction** merges without a search per file id (a third of its
  time) and without holding locks during the merge.
- **Keepalive** is sent in 60 slices across `ping_delay_seconds` instead of to
  every client at once.
- The admin page polls only the tab on screen; client search builds rows only
  for the page shown; several periodic scans take locks in small pieces; busy
  log lines moved to debug.

### Connections and admin page

- **`TCP_USER_TIMEOUT` = 300 s** on client sockets (Linux), equal to the
  keepalive tolerance. A connection whose sent data has gone unacknowledged
  that long is dropped, instead of after ~15 minutes of retransmission. Seen
  live: a client behind a firewall that silently drops eD2k flows reconnected
  every 22 s and held 27 sockets.
- **Status tab, Busiest IP** shows the address with the most logged-in clients
  (a NAT or CGNAT) and its open connections, instead of the address with the
  most connections — which picked out abandoned sockets.

### Content filter verification

After every filter change in this release, verdicts on 105 073 review-corpus
names (210 146 checks with the current lists) were identical to 0.9.77, line
for line. A randomized test compares the prefiltered matcher with checking
every term.

### Other

- README: installation with the single template, the descriptor limit,
  `thp:never`, `TCP_USER_TIMEOUT`, Busiest IP, the memory report.
- CPU-TUNING.md: the keepalive is no longer a burst.
- `aho-corasick` 1.1.4, already in the dependency tree, is a direct
  dependency. Minimum Rust stays 1.75.

## 0.9.77

Fixes issues #17, #18 and #20–#28. The largest change is work admission
(#25): every kind of work a remote peer can cause is now bounded.

### Upgrade notes

- **Raise `LimitNOFILE` to 262144** (the example unit does). After a restart
  every client logs in again at once, and each pending login may hold an
  outbound HighID-probe socket besides its own: about 121 000 descriptors at
  50 000 clients. The server warns at startup when the `[admission]` ceilings
  exceed the limit.
- **Limits in `[limits]` are now applied** — they were parsed and ignored
  before (#18). Check `max_clients`, `max_clients_per_ip`, `soft_limit_files`,
  `hard_limit_files` and `max_string_size` in your config: a low value that
  did nothing until now will now refuse logins or leave files unindexed.
  `0` disables each of them.
- `network.udp_server_key` is removed (it was never read); a config that still
  has it loads.
- The admin page is served with `Cache-Control: no-cache` from this release
  on. A browser that cached the 0.9.76 page may show it once more after the
  upgrade (old tabs, letters instead of flags) — reload with the cache cleared.
- Optional: put `ipinfo_lite.mmdb` next to `ip-to-country.csv` for IPv6
  countries and provider names (see *GeoIP*).

### New settings

All have defaults, so a 0.9.76 `config.toml` starts unchanged.

| Section | Key | Default | Apply | What it does |
|---|---|---|---|---|
| `[network]` | `max_decompressed_frame_size` | `8000000` | new connections | Ceiling for an inflated 0xD4 frame; over it the connection is closed. `0` is refused |
| `[storage]` | `geoip_mmdb_path` | `""` | restart (file reloads live) | MaxMind DB tried before `country_db_path`. Empty = `ipinfo_lite.mmdb` next to the CSV; `"off"` = CSV only |
| `[updates.urls]` | `geoip_mmdb` | `""` | live | Where the update service fetches the MaxMind DB. No compiled-in default |
| `[admission]` | the whole section | see README | restart | Ceilings on sockets, pending logins, HighID probes, hole-punch retries, callback/hole-punch rate, search jobs and queues, UDP budgets. `/api/admission`, `/api/ready` |

`config/config.vps.toml` carries them with the values the reference server
runs.

### Security

- **Packed-frame decompression is bounded** (#20, #22). `max_frame_size`
  bounded only the compressed length of a 0xD4 frame and the decoder inflated
  into an unbounded buffer: any connection, logged in or not, could make one
  ~1 MB frame expand to ~1 GB. Decoding now stops at
  `max_decompressed_frame_size` and closes the connection.
- **Admin page: client nicks were inserted as HTML.** A nick carrying markup
  ran script in the operator's browser, on the admin origin that can save the
  config. Nicks, software names, addresses and peer names are now escaped.
- The admin config editor validates a config as startup does before saving
  it; a config the server would refuse at startup could be applied live.

### Work admission (#25)

One component (`src/admission.rs`) bounds the work remote peers can cause,
however it is spread across addresses, listeners and address families.

- **TCP.** Open sockets and sockets still in setup or login are counted at
  accept, before a task exists; when either is full the socket is closed and
  nothing unauthenticated queues. IP-filtered addresses are dropped before
  they take a slot. A source (IPv4 address, IPv6 /64) can hold only its share
  of the pending pool.
- **`max_clients` is a reservation taken before the login does any work**, so
  concurrent logins cannot overshoot it. A same-hash re-login releases the
  replaced session's slot at once.
- **HighID probes** — at login, hairpin and the background checks — share one
  pool. A login that finds none free gets LowID at once instead of waiting.
- **Search runs off the async runtime** in a bounded lane. A TCP search waits
  in arrival order for a while, then gets an empty result; a UDP search waits
  from a task in its own smaller queue, never in the receive loop, so UDP
  cannot crowd out established sessions.
- **UDP**: a server-wide credit budget, then a per-source one, shared by every
  listener and both families. Every datagram is charged on arrival, before
  parsing; obfuscated decodes, searches, source requests and server-list
  traffic cost more. `udp_rate_enforce = false` (default) only counts
  over-budget packets, so budgets can be chosen from live traffic first.
- **Callback and hole-punch requests** have a per-session budget; hole-punch
  retry tasks are capped and coalesced per pair.
- **Sizing.** The defaults are sized for 50 000 clients (~45 000 LowID) and
  30 000 000 files, including the reconnect storm after a restart, and lean
  high: a ceiling costs memory only while used (~11 KB per pending login,
  measured), one that is too low refuses real users. On a live server a
  restart with 9 000 clients overflowed 4 096 pending logins; the default is
  32 768.
- `GET /api/admission` exposes every gauge and counter; `GET /api/ready`
  returns 503 once a critical pool has stayed full for `readiness_window_secs`.
  The Status tab shows a summary.
- `contrib/overload_test.py` drives a running server past every ceiling and
  checks that it stays bounded and recovers.

### Protocol

- **`OP_IDCHANGE` bytes 12–15 carry the client's address, not the server's**
  (issue #17). eMule and aMule read this field as "your address as the server
  sees it": a LowID client calls `SetPublicIP` with it, and a HighID client
  expects it to equal its client id. It carried the server's `this_ip`, so every
  LowID client believed its public address was the server's, and keyed UDP
  obfuscation, the Kad verify key and what it advertises about itself on it.
  Now:
  - HighID — the client id itself. For a client verified through the hairpin
    path (`hairpin_lan_clients`) that is the server's public address, which is
    that client's public address too; its LAN address is never reported.
  - LowID from a public IPv4 — that address.
  - LowID from a private or loopback address — a client behind the same NAT as
    the server, whose public address is the server's: `this_ip` when set and
    public, otherwise 0. The old value was accidentally right for exactly this
    case, and it stays so.
  - IPv6 session — 0, so the client leaves its public IPv4 unset rather than
    learning a wrong one.

  The HighID decision does not read this field and is unchanged. The server's
  own address in `OP_SERVERIDENT` is unchanged.
- **Obfuscated TCP no longer desynchronises under write pressure** (#21). The
  RC4 keystream advanced before the socket accepted the bytes, so a short or
  pending write corrupted the stream. As in eMule, pending ciphertext is now
  flushed first and only the accepted plaintext is counted.
- **A stale session no longer evicts its own reconnect** (#23). A HighID
  reconnect from the same address has the same id, and the old session's
  cleanup removed the new session's entry and sources. Sessions are now told
  apart by identity, and the entry is removed atomically.
- **Meta-tag searches parse** (#24). Tag names were read as UTF-8 text; eMule
  sends a one-byte id, and the media ids 0xD0–0xD5 are not valid UTF-8, so any
  artist/album/title/length/bitrate/codec search failed.
- **An address ending in `.0` is never HighID** (#26). It encodes below
  0x01000000, the LowID range. Such a client now gets a LowID without a probe.
- **Search results name a reachable source** (#27). The first source was
  written verbatim — a LowID's NAT address as if HighID, a LAN address, or a
  departed client. A connected source is now chosen and encoded as GETSOURCES
  does: complete HighID first, then complete LowID, then partial copies.
- **Complete sources count only complete copies** (#28). `FT_COMPLETE_SOURCES`
  in search results equalled the source count, so a client sharing a file it
  was still downloading counted as a complete source. eMule and aMule offer a
  part file with the incomplete marker (`0xFCFCFCFC/0xFCFC`), and aMule also
  uses it for a complete file whose verify found corrupt parts. Only sources
  offered as complete count now, as with Lugdunum, and the count follows
  re-offers. A source offered without markers still counts.
- **`OP_SERVERIDENT` server hash** is derived from the seckey: stable per
  server, distinct between servers. Every server running this code used to
  send the same one.
- **Replaced sessions release their socket.** When a newer login of the same
  user takes over, the old session used to keep its socket until it closed or
  the 6-hour backstop fired; a peer abandoning such sockets filled
  `max_clients_per_ip` (seen live: 100 sockets from one address, one logged
  in). A replaced session now closes after 10 minutes without traffic of its
  own. A copy that still talks keeps its socket, so two installs sharing a
  user hash do not knock each other off.

### Limits (#18)

Every setting below was parsed but not applied.

- **`soft_limit_files`** — Lugdunum's per-client indexing budget: distinct
  files indexed for the client across all its OFFERFILES. Files beyond it are
  not indexed, the session stays up, and the client is told once per
  connection ("WARNING : This server accepts N shares per client…").
  Re-offers and filtered records use no budget.
- **`hard_limit_files`** — an OFFERFILES declaring this many records or more
  is rejected before it is read and the connection is closed. Keep it well
  above the 200-file eMule batch.
- **`max_clients`** — a login beyond it gets "Server full"; a client
  replacing its own stale session is always admitted.
- **`max_clients_per_ip`** — open TCP connections per IP (IPv6 per /64),
  counted at accept. Loopback is exempt.
- **`max_string_size`** — file names and nicks are stored capped at a
  character boundary; the content filter sees the whole name first.
- `network.listen_backlog` is used by both listeners (`0` = 1024).
- The Status tab shows the soft and hard limit counters and the busiest IP
  with its country, provider and how many of its connections are logged in.

### GeoIP and IPv6

- **GeoIP reads a MaxMind DB** — IPinfo Lite (`ipinfo_lite.mmdb`) or GeoLite2
  Country — and falls back to `ip-to-country.csv`. IPv6 clients get a country
  (they were all "??"), and with IPinfo Lite every network's provider (ASN and
  name) is shown. The file is held in memory and searched in place: about
  23 MB against 7 MB for the CSV; a lookup takes about 2 µs. The reader is our
  own (`src/filter/mmdb.rs`, no new dependency), bounds-checked throughout; a
  corrupt or truncated file fails to open and the CSV is used. On 200 000
  random IPv4 and IPv6 addresses it agrees with the reference reader on every
  lookup. The update service has a new target, `geoip_mmdb`.
- **Bot detection and its 24-hour bans cover IPv6.** They were keyed by IPv4
  address, so an IPv6 UDP querier was never measured or banned. Bots, bans and
  the unique-IP count of filter blocks are keyed by source: the IPv4 address,
  or the IPv6 /64. A flood spread over one /64 is one bot.

### Admin panel

- **Clients tab: search on the server.** Free text (part of an address or
  nick, or an IPv4 CIDR such as `82.48.0.0/16`), country, software,
  High/LowID; sorting; 100 rows a page. The page used to download every
  connected client every 5 seconds from every tab; it now receives one page.
  `GET /api/clients/search`; `GET /api/clients` is unchanged for scripts.
- **Files column.** It read 0 for every client — the counter behind it was
  never incremented. It now counts the client's files in the index.
- **Peers tab: server names.** Each listed server's name, description and
  version (UDP 0xA2/0xA3), its user and file counts and its country. Each peer
  is asked at most once an hour; a reply is accepted only from a peer we asked.
- **Country flags on Windows.** Chrome, Edge and Opera there have no flag
  glyphs and showed two letters. A 78 KB Twemoji subset font (CC-BY 4.0) is
  built into the binary; the page loads nothing from other hosts.
- Status tab: replaced sessions closed; Bots tab: an IPv6 bot is shown as its
  prefix.

### Content filter

- **A term inside the file extension no longer counts.** Layers 1 and 4 read
  the name without its last extension (1–8 letters or digits after the final
  dot). 66 FreeDOS package descriptors were blocked on one review window by a
  short term that happened to be their extension, because the dot before the
  extension satisfies the boundary rule. Measured on 155 862 names: those 66
  change, nothing else does. Layer 2 still reads the full name.
- **Decomposed accents (NFD).** An accented letter that arrives as base letter
  plus combining mark ("e" + U+0301) was read as a word boundary, so a short
  term fired inside an ordinary French word. The earlier fix covered the
  precomposed letter only, and one title had since been patched with a phrase
  exemption instead of the cause. Names are now recomposed before any term
  matching (`filter/nfc.rs`), so the boundary rules, the phrase exemptions and
  the age scanner all see the same text; a leftover combining mark still binds
  to the letter before it. Three French titles on one review window.
- **The unpaired age rule no longer applies to audio, e-books, documents and
  data files** (mp3, flac, pdf, epub, xml, bin and similar). On those types a
  number followed by "yo", "y" or "yr" is a track number before Spanish "Yo",
  a catalogue or model code, or a book title — 56 blocks on one review window,
  none of them material, and no hash-banned name affected. The pairing rule
  (age plus sexual term) still applies to every type; subtitles, text files,
  archives and pictures keep the unpaired rule.
- **`_` separates an age like any other separator.** The age scanner treated
  `_` as part of a word, so "…_12yo…" and "12yo_…" were never read as ages —
  while the term matcher has treated `_` as a separator since 0.9.71. Across
  60 815 names every name with an age glued to `_` is material; four of them
  were in served search results.
- **Recoverable mojibake: terms are judged on the recovered text only.** A
  name damaged by a double encoding ("l'Ã©lÃ©phant") was scanned both as
  recovered and as raw bytes, and in the raw form a non-letter sits where an
  accented letter was, so the boundary rule fired inside an ordinary French
  word. A term that is really in the name survives recovery unchanged, so the
  raw scan only ever added mistakes. Measured on 104 000 names: one verdict
  changes, the false positive. Layer 2 still reads both forms.

### Other

- **CPU-TUNING.md**: which `target-cpu` to build for (AMD, Intel, ARM, and
  `x86-64-v3` on a VPS, where a model-specific value can crash), how to check a
  machine, and how to trace periodic CPU load. `.cargo/config.toml` and README
  now recommend `x86-64-v3` on a VPS instead of `znver3`.
- The "`server.this_ip` is not set" warning is logged once per process.
- README: `worker_threads = 0` is treated as 1, not "auto".
- Dead code removed: an unused self-source flag in OFFERFILES, the never-built
  `TagError::StringTooLong`.

## 0.9.76

### New settings

All new keys have defaults, so a 0.9.75 `config.toml` starts unchanged. The
removed-in-development key `highid_verify_max_wait_ms` is ignored if present.

| Section | Key | Default | Apply | What it does |
|---|---|---|---|---|
| `[network]` | `ipv6_enabled` | `false` | restart | Accept clients over IPv6: IPv6-only TCP listener on `tcp_port` and UDP socket on `tcp_port + 4`. IPv4 sockets are unchanged; a host without IPv6 logs a warning and serves IPv4 only |
| `[network]` | `listen_ip6` | `"::"` | restart | Bind address for the IPv6 sockets |
| `[network]` | `this_ip6` | `""` | live | The server's public IPv6, announced in `OP_SERVERIDENT` (with `ipv6_publish_sources`) |
| `[network]` | `ipv6_publish_sources` | `false` | live | Publish IPv6 sources to peers that can parse them; advertise the extension in `OP_IDCHANGE` and UDP pings |
| `[network]` | `highid_verify_observe` | `false` | live | Re-check HighID clients with a client-to-client `OP_HELLO` in the background and count the outcome. Changes nothing for the client |
| `[network]` | `highid_downgrade_on_wrong_hash` | `false` | live | Same check, acted on: a port answering with another client's user hash marks that login, and its next logins get LowID |
| `[network]` | `highid_wrong_hash_ttl_secs` | `86400` | live | How long such a mark lasts |
| `[limits]` | `max_search_results` | `200` | live | Results per search, across all pages, best-sourced first. Ceiling 5000 |
| `[limits]` | `search_rank_scan` | `20000` | live | Candidates examined when ranking one search; must be ≥ `max_search_results` |
| `[limits]` | `index_subtokens` | `false` | restart | Also index letter/digit pieces of words (`S01E08` → `s01`, `e08`; `1080p` → `1080`) |
| `[limits]` | `search_drop_unknown_words` | `true` | live | Ignore query words no indexed file contains instead of returning nothing |

`config/config.vps.toml` carries all of them with the values the reference
server runs.

### IPv6

Opt-in support for clients with IPv6, following the extension already spoken by
eMuleQt and eNode-go. The wire contract is in README → *IPv6*.

- Separate IPv6-only TCP and UDP sockets, so the IPv4 path is byte-identical.
- A client's IPv6 is taken from the session it arrived on, or from login tag
  `0xAE`. Only globally usable addresses are kept.
- A source that is LowID on IPv4 but has a public IPv6 is published as an IPv6
  record (id `0xFFFFFFFF`, port, 16 bytes), over TCP and UDP. Only requesters
  that can parse it receive it: a TCP client that sent the tag or connected over
  IPv6, or a UDP query that arrived over IPv6.
- Answers carrying IPv6 records bypass the SmartSources cache, which is shared
  with clients that cannot parse them.
- An IPv6 session is LowID on IPv4 by construction and is never probed. Before,
  a probe of an IPv6 peer could leave a session holding a low id while flagged
  HighID.
- Status tab: IPv6-capable clients and IPv6 publishers. Clients tab: each
  client's IPv6.

### HighID check

HighID was decided by a bare TCP connect. That proves something listens on the
port, not that it is the client that logged in: behind a NAT shared by two eD2k
clients (two machines at home, or strangers behind a provider's CGNAT) the
forward leads to one of them, and the other got a HighID that sent every peer to
the wrong machine.

- The server can now send a client-to-client `OP_HELLO` and compare the user
  hash in the answer, obfuscated first when the client supports it.
- The check runs in the background. A synchronous version was measured in
  production and dropped: clients whose login is still pending mostly do not
  answer in time, so logins waited up to 3 s and most checks went unanswered.
- Verdict mode remembers a wrong hash per (IP, port, login hash). The client's
  next logins get LowID at once, and each re-checks in the background: its own
  hash again clears the mark, a wrong hash renews it.
- **No answer never costs HighID.** A silent close or a reset is usually the
  peer's IP filter dropping us. Only a positive answer from another client
  counts.
- The comparison ignores the two client-type marker bytes of the hash. Some
  clients send MLDonkey's markers in the hello and eMule's at login, and were
  miscounted as different clients.
- The hairpin path (`hairpin_lan_clients`) is unchanged.
- Measured on the reference server: about 1% of checked HighID logins answered
  with another client's hash; the answering client is almost never connected to
  this server.
- Status tab: verified / no answer (with reasons) / wrong hash / skipped, marks
  active, logins given LowID by a mark, marks cleared.
- New `GET /api/highid_mismatches[?anonymize=1]`: the last 1000 wrong-hash cases
  with a summary, so the check can be reviewed without enabling logs.
  Anonymised output shows each address as its /24 plus a salted tag.

### Search

- **Ranking by source count.** The cap used to keep whichever matches the index
  produced first. It now keeps the best-sourced, ties broken by file id, so the
  same query against the same index answers identically. Ranking examines at
  most `search_rank_scan` candidates, and the share of searches that hit the
  bound is shown on the Status tab (about 3–4% on the reference server).
- **Configurable result count** (`max_search_results`), one value for every
  client. Lugdunum varies it by zlib support and halves it for LowID; measured on
  a stock 17.15 server: 309 / 205 HighID, 153 / 101 LowID. The first result page
  follows the setting.
- **Sub-token indexing** (`index_subtokens`): runs of letters and digits and
  adjacent pairs of runs, so `S01E08` is found by `s01`, `01e` and `e08`. Pieces
  shorter than 3 characters, hex identifiers of 8+ characters and words of more
  than six runs are not split. Queries are not split. Measured cost on the
  reference index: under 2% more memory per file. Off by default because it
  changes what searches return.
- **Unknown words are dropped** (`search_drop_unknown_words`): a word no indexed
  file contains is ignored instead of emptying the search. A query of only
  unknown words still returns nothing. OR branches, negated words, and starred
  or anchored words are never rewritten. Stop-words are no longer miscounted as
  dropped.
- **Fix: `*` and `^` in multi-word queries.** Markers were read at the ends of
  the whole term rather than per word, so `<title> dvdr*` returned nothing and
  `<title> ^word` searched for the literal `^word`. They are now per word, and
  TCP and UDP share one candidate builder instead of two copies with the same
  bug.

### Fixes

- **Source ports ≥ 32768.** The completeness flag was stored in the port's top
  bit, and the port was masked to 15 bits. A source on port 33078 was published
  as 310. The flag now has its own field; the memory cost is zero, because
  alignment pads the record to 24 bytes either way.
- **Client capability table.** `CAPABLE_LARGEFILES` and `CAPABLE_SUPPORTCRYPT`
  had the wrong values in `opcodes.rs`. Login used a correct private copy, so
  0.9.75 behaved correctly. The table is fixed and is now the only definition,
  with `CAPABLE_REQUESTCRYPT`, `CAPABLE_REQUIRECRYPT` and `CAPABLE_IPV6` added
  and tests pinning each bit.

### Content filter

- Layer 2 name normalisation treats every non-alphanumeric character as a
  separator (brackets, parentheses, `&`, commas…), not only `.`, `_` and `-`.
  Letters and digits of any script are kept.
- A leading track number in a music title is no longer read as an age claim,
  and a few Spanish guard words were added.

### Other

- The whole tree is `rustfmt`-formatted and several clippy suggestions were
  applied, so many files show formatting-only changes.
- More tests: 375 unit tests and 9 integration tests, including end-to-end
  ranking, the first page following the cap, sub-tokens not bypassing the
  filter, unknown words, the HighID check against local listeners, and IPv6
  record layout.

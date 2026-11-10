# Changelog

Earlier releases are described in their release commit messages.

## 0.9.89

Four findings from an audit of 0.9.88 by itlezy.

### NAT-T token from the OS random source (issue #57)

The session's NAT-T token keys the HMAC of its `0x9F` proofs, and it came
from the obfuscation helper: a clock-and-counter seed expanded by a linear
congruential generator, not fit for a key. It now comes from `getrandom`.
If the OS source fails the session gets no token, and its `0x9F` is then
accepted from its own address only; there is no fallback to predictable
bytes. Wire format, length and the proof are unchanged. The same source now
also gives the obfuscation handshake's DH private exponent (falling back to
the old generator only if the OS source fails, as that is obfuscation, not
authentication) and the per-process salt of the anonymised exports.

### Search tree: node and text budget (issue #54)

The parser bounded depth (24) but not size: a balanced tree 12 deep could
hold 8,191 nodes, each a heap allocation, all made before the search waited
for its lane, and over UDP on the receive task. A tree now has at most 256
nodes and 4,096 bytes of text (terms, meta values, tag names), taken from
the budget before each node or string is allocated. A tree over either is
refused before admission: an empty result over TCP, nothing over UDP,
counted as `search_tree_over_budget`. eMule's own searches stay around 30
nodes even with every advanced field.

### Bounded candidate lookup for every query shape (issue #55)

Only a query of one plain word had its candidate list cut to what the
ranking examines; two words, an OR group or a repeated word built their
whole answer first, decoding, allocating and sorting postings far past
`search_rank_scan`. Now every shape returns the first ids in id order, as
the ranking reads them, with two bounds: the seed (the rarest group) is a
prefix of at most 262,144 ids, and at most 4,000,000 ids are decoded from
the other groups' postings. Within them the answer is exactly the first ids
of the old one; past them it is partial, never wrong (the caller checks
every file against the whole query). Repeated words and groups collapse
first, so `[[a], [a]]` takes the one-word path. Cut answers are counted as
`search_candidates_seed_cut` and `search_candidates_visits_cut`.

### Large OFFERFILES never runs on the runtime because the lane is full (issue #56)

A batch above 8 records went to one of the 4 offer slots on the blocking
pool, but with all four busy it ran inline on the runtime, which at the
default single thread stopped all networking exactly in the reconnect
storms the lane is for. It now waits for a slot, serving frames pushed at
the client meanwhile and reading nothing more from it, so TCP holds the
client back. A waiting batch holds only its frame as read, parsed once a
slot is free, and waiting frames are bounded to 64 MB in all; past that a
batch still runs inline, as a last resort. Counted as `offer_lane_waited`
and `offer_inline_overload`. The slot is held by the job itself and released
when the batch is done, on a panic too, whether or not its connection is
still there.

## 0.9.88

### Name history on disk

New `[name_db]`: every offered name of every file hash, blocked or not, goes
into an SQLite file, with the filter's verdict for that name (for a
whitelisted hash, the verdict without the whitelist), when it was first
offered, and its independent publishers counted by user hash and by /24
(IPv6 /48), stored as salted digests. It is the evidence a hash-list or
whitelist decision needs where today there is one name: a legal film
published once under an abuse name, or a whitelisted hash other publishers
name otherwise.

- Low cost by design: the offer path pushes into a bounded queue and never
  waits (a full queue drops and counts). One writer thread looks each offer
  up and keeps only changes: a new name, a new publisher of a stored name,
  a verdict on a clean name. They are written sorted, in one transaction,
  once `max_pending` (100 000, ~30 MB) have gathered or every `flush_secs`
  (3600). One table, publishers in the row, names keyed by a 64-bit digest,
  no last-seen time (it would rewrite every known name daily). SQLite WAL,
  `synchronous = NORMAL`, 16 MB page cache, no mmap. Measured: about 2.6 KB
  written per change at 100 000 per write (6.4 KB at 20 000), about 220
  bytes per name on disk.
- Status tab row; `GET /api/namedb?hash=` for one hash (flagged names never
  printed). Pending changes are written on SIGTERM/SIGINT before exit.
- rusqlite 0.31 with the bundled SQLite, pinned for Rust 1.75.

### IPv6 dial-back: a withdraw no longer resets the dial count (issue #53)

`OP_IPV6_UPDATE` with the zero address removed the session's probe entry,
and with it the count of dial-backs, so alternating withdraw and a new
address got past the cap of 4 per session and had the server dial every
address the client named. A withdraw now keeps the entry (address cleared,
verdict settled so the sweep leaves it alone); the count lasts the session.

### NAT-T token's proof (issue #40)

A plain `0x9F` with the token showed the token to anyone on the path, who
could then move the session's endpoint (and see its peers) for the rest of
the login. Agreed with aMule and eMuleQt (both send the proof now): next to
`ST_NATT_TOKEN`, `OP_SERVERIDENT` carries `ST_NATT_PROOF` (`0xA9`, u32 = 1),
and a `0x9F` that counts from any address is `<user hash 16><counter u32
LE><mac 16>` (36 bytes), mac = HMAC-SHA256 keyed with the token over user
hash and counter, first 16 bytes. Only with a counter higher than the last
accepted one for the session (a replay is ignored); it passes the rule that
ignores a plain `0x9F` after an obfuscated one. Counters `natt_9f_proof`,
`natt_9f_proof_other_ip`, `natt_9f_proof_bad`, `natt_9f_proof_replay`.

- **`0x61` carries the recipient's own UDP endpoint** when the server has
  accepted a `0x9F` from it: `own_ip(4) own_udp_port(2)` appended after the
  crypt byte, 36 bytes. A client whose UDP leaves from another public IPv4
  than its TCP keys its client UDP obfuscation toward the punched peer with
  it (found by aMule: in that case the transfer after the punch only worked
  with client UDP obfuscation off). Covers both peers split, which a peer's
  echo cannot. 30 bytes as before without such a `0x9F`.
- **The 0.9.87 token form is dropped.** `<user hash 16><token 16>` now
  counts as the user hash alone, accepted only from the session's address
  (`natt_9f_token_form_ignored`); `natt_9f_token`, `natt_9f_token_other_ip`
  and `natt_9f_bad_token` are gone.

### Obfuscated UDP with the key of a neighbouring exit (issue #40)

A client obfuscates with the key we gave the address its crypt ping came
from; we decoded with the key of the address the datagram comes from. Where
an ISP or VPN hands out a different exit per flow the two differ: live, a
few hundred global source requests in 15 hours, mostly from Cloudflare WARP
(104.28.x), each keyed by a neighbouring exit's crypt ping, all unanswered.
An undecodable datagram on portUDPobf (26..512 bytes) now gets, once a
minute per sender, the keys of nearby addresses: NAT-T sessions and
crypt-ping sources of the last two hours in its /16. A decoded `0x9F` goes
to its handler (the token decides); a global query (`0x9A`, `0x94`, `0x98`,
`0x92`, `0x90`) is answered, encoded with the same key, and the key is kept
for that sender's address (30 min), since a per-flow exit sends every
datagram from a new port (`udp_decoded_by_neighbour_key`). Counted as
`natt_undecodable_key_of_session_ip` / `_of_crypt_ping_ip`, and
`_none_nearby` for NAT-T sessions only; matches shown in `/api/natt`.

### server.met from the peer list

New `[server_met]`: every `interval_secs` (600) the server writes a
`server.met` to `path` (a file, or a folder for `server.met`), as Lugdunum's
`autoservlist` did. In it: the peers that are verified and whose ServerKey is
known, except those matching `exclude` (an address, a range or `ip:port`),
and this server first unless `include_self` is off. All live; off while
`path` is empty.

- One format for every reader: header `0xE0`, old-style tags with string and
  u32 values only (servermet.php does not read aMule's short tags), UTF-8
  with a BOM when not ASCII, exact tag counts (aMule refuses trailing
  bytes). `ST_PREFERENCE` 0, normal priority, for every server.
- Written to a temporary file and renamed; nothing is written while no peer
  qualifies, so a network outage does not empty the list.
- The peers' max users, file limits, UDP flags, LowID users and obfuscation
  ports are now kept from their extended `0x97` (the obfuscated handshake's
  reply included), and the handshake's round trip as their ping. The Peers
  tab shows max users and, while `path` is set, each peer's standing in
  server.met (in / excluded / —).
- **A ServerKey for every listed peer**, not only the seeds. Only the seeds
  get the gossip handshake; any other peer's key arrived when that peer
  gossiped with us on its own schedule, so after a restart many stayed
  "pending", without max users, for hours, and out of server.met. Each
  minute up to 16 listed peers without a key now get the seeds' OBF ping
  (TCP+12, from an ephemeral port, answer accepted only from the peer's
  address); one that does not answer is tried again after 10 minutes.

### Filter audit

- **A name the age rule (L2) blocked is never shown**, in the audit or in
  `format=audio`, whatever its extension. The age is the child signal
  itself, and an `.ogg` can be a film: on 02.11.2026 `format=audio` showed
  the name of a 405 MB `.ogg` the age rule had blocked, because for that
  rule the age was not counted as a second signal.
- The traditional form of the CJK age unit is recognised as an age.

## 0.9.87

From the first 14 hours of 0.9.86 on ed2k-rust (`/api/sizemismatch`).

### Identity probe and DLP (issue #50)

The probe's hello now carries `CT_EMULE_VERSION` (eMule 0.50a) after
`CT_NAME`, `CT_VERSION` and `CT_PORT`. Without it a peer whose hash has the
eMule marker shows as plain "eMule", which DLP bans as "Bad MODSTRING"
(`DLPCheckModstring_Hard`: `clientversion == "eMule"`, "the client did not
send client version"). emule-qt with Special DLP banned the probe, so its
IPv6 address never passed the dial-back. No mod string, as before.

### Cross-server callback and the crypt layer (issue #40)

A foreign `0xA6` for a target with the extension is no longer refused when
one side requires the crypt layer: there the requester dials, the `0xA7`
always carries the target's hash, and an obfuscated uTP dial opens with a key
frame the target answers without knowing the requester (aMule since
amule-org/amule#2148). Refused only when a side that requires the layer
meets one that does not support it (the requester's setting is the crypt
byte of its `0xA6`, none meaning none). A Lugdunum-only target still dials
the requester itself with no hash, so the old rule stays for it.

### Sizes (issue #45)

- **A size guessed from the part hashes is the same file.** Most size
  disagreements were exactly `(hashes - 1) × 9 728 000`, the lower bound a
  client uses for a download started from a bare hash before it learns the
  real size (55 of 63 publishers; most of them one emule-qt build). Such a
  size now agrees with the real one: its publisher is merged as a source,
  its source requests are answered (`getsources_size_part_estimate`), and a
  record that holds only the guess takes the real size when it arrives.
- **UDP `0x94` records with an impossible size** — the large-file sentinel 0
  followed by 8 bytes far above eMule's 256 GiB limit, for files that are
  not large (a quarter of all disagreements) — are answered by hash alone,
  as before 0.9.86, and counted (`udp_getsources2_bad_size`).
  `udp_getsources2_bad_size_realigned` counts those where the 16 bytes
  right after the 0 are a known hash — i.e. the sender wrote a plain 32-bit
  0 with no u64 after it. Diagnostic only; parsing is unchanged.
- What is still refused: sizes that are neither, such as the ~700 MB fakes
  with sizes a few MB off and links with digits dropped.

### NAT-T token (issue #40)

A `0x9F` used to be believed only from the session's own address, a user hash
being public. On ed2k-rust an emule-qt client behind a carrier NAT sent all
its `0x9F` from another IPv4 than its TCP (344 in 14 hours, all ignored), so
it got the 3 s wait and its announced port every time. Now each session that
may send `0x9F` (`0x100000`, `0x1000`, or a UDP port in `0xF9`) gets 16
random bytes in `OP_SERVERIDENT`, tag `ST_NATT_TOKEN` (`0xAC`); a client with
`0x100000` gets that `OP_SERVERIDENT` at login. A `0x9F` of
`<user hash 16><token 16>` is the session's own from any address, and that
address and port are what peers get in `0x61` and `0xA7` — for a session over
IPv6 too, which can then punch over IPv4 instead of getting reason 5. A wrong
token is ignored (`natt_9f_bad_token`); counted `natt_9f_token`,
`natt_9f_token_other_ip`. Checked against a running server: a token `0x9F`
from 127.0.0.2 for a session on 127.0.0.1 put 127.0.0.2 and its port in the
peer's `0x61`; the same without the token, or with a wrong one, was ignored.

### Filter audit

- **`format=hashlists`**: the list additions ready to paste, hashes only —
  `hash_banlist.txt`: every film, picture, archive or other file a term
  layer blocked in the window; `hash_filter.txt`: every indexed file under
  3+ unrelated names; commented out, the audio/document/software hits to
  look at first and ban-list files with 3+ unrelated names.
- **`format=audio`**: every blocked audio file by rule, with its name (a
  name with a child signal withheld): the false-positive leads.
- `hashlists` never lists a hash both for the ban list and as a decoy: one
  that some publisher named with a listed term goes to the ban list.
- Comic archives (`cbr`, `cbz`, `cb7`) count as archives and disc images
  (`iso`, `img`, `bin`, `nrg`, `mdf`) as other, no longer as documents and
  software whose clean names the audit shows; more audio extensions.
- **`format=terms`**: term leads — words in 5+ blocked files of the window,
  90%+ of whose files are blocked, that the filter does not block alone, with
  their blocked and served counts. Words only.
- **The second-marker signal** removes the rule's own term across
  separators. Removed from the raw name, a term the layers matched across
  "." or "_" stayed in and counted as a second marker: on 31.10 every L1 and
  L4 rule read "marker" and no name was shown.
- **Names are shown only for audio, documents and software**, under any
  rule, never for a film, picture or archive.
- The age rule on a film or a picture is never suggested for the whitelist any
more (`suggest` = `keep`), and its rules read "age alone (by design)" instead
of "likely false positive". Its unpaired notations block on the age alone, so
a missing second signal is the rule working: on 31.10.2026 the audit
suggested 1160 such hashes for the whitelist, every one a video or picture
with nothing but an age to judge it by.

### Server list

A server that registers with us (UDP `0xA0` `<ip><tcp port>[<challenge>]`)
is sent a `0x96` with a fresh challenge and listed only when a `0x97` echoing
it comes back from its TCP+4. Refused outright: an address that is not the
sender's, not public, ours, or a client's (connected, or seen in the last 30
minutes). An unproven registrant never enters the list, so it is never
handed out, takes no place under the 2048 cap and no slot of the 50-a-minute
verification probe. This keeps mldonkey out: an mldonkey client sends `0xA0`
with its own address to the servers it knows, and does not answer `0x96`;
nor can anyone list itself with a forged `0x97`, which must carry the
challenge. Registrations used to be answered and otherwise ignored, so a
server we knew only from its own registration never appeared: JEmuleServer,
whose registration Lugdunum does not take, was in nobody's list. Counted as
`gossip_registration_probed` / `_added` / `_refused`.

### Sessions

- `login_takeover_same_address`: live sessions replaced from their own
  address (a NAT reconnect, or two installs behind one NAT), to set beside
  `replaced_session_frame_refused` and see whether the fence of #46 makes
  such pairs take turns.

## 0.9.86

### Sources with crypt options (issue #42)

`OP_GETSOURCES_OBFU` (0x23) is answered with `OP_FOUNDSOURCES_OBFU` (0x44), as
Lugdunum does: per source `<id><port><crypt>[<user hash>]`, the crypt byte
being the source's `(CT_SERVER_FLAGS >> 9) & 7` (supports / requests /
requires the crypt layer) with 0x80 and the hash when it supports the layer;
a source whose client has left gets 0. IPv6 sentinel records carry the same
fields before the address. It used to get the plain 0x42, so a client
requiring obfuscation dropped every source from this server and no client
could obfuscate its first connection to one — NAT-T dials included. 0x19
still gets 0x42; the two replies are cached apart.

Every `OP_LOWID_HOLEPUNCH_INFO` (0x61) now carries the peer's crypt setting
in byte 29, not only between extension clients. With the user hash it has
always had (bytes 8–23), the dialler can obfuscate from its first datagram,
so a target that requires the crypt layer accepts the stream (got3nks: aMule
dialled plain uTP and such targets refused it). Parsers read by length, so
the 30-byte frame is safe for 29-byte readers.

Cross-server NAT callback (issue #40): two LowIDs on different servers reach
each other through the target's own server, with no registry. Same-hash
logins from another address no longer take a live session over (issue #41).
A filter audit that never shows a rightly blocked name, and an index check
against the current filter.
Two new keys, `network.holepunch_foreign` (on) and
`limits.hash_takeover_from_any_address` (off).

- **Request.** Lugdunum's UDP `0xA6` `<target_id><0>[<crypt>]` from a client
  not logged in here, server-key obfuscated. The key is bound to the
  sender's IP, so a datagram that decodes proves it; the source port is the
  requester's endpoint. Requester id 0 marks it foreign.
- **Wake.** The target, a logged-in LowID that set `0x1000`, gets the usual
  `0x37` (or `0xA7`) with requester id 0 and no hash. Nothing when one side
  requires the crypt layer.
- **Answer.** For a target with the extension, the requester gets UDP `0xA7`
  `<target_ip><target_udp_port><target_id><crypt><hash>` after the target's
  `0x9F`, or after 3 s with the port the server has, resent at +1.2 s and
  +3 s like `0x61`; the hash always, since
  the requester dials and obfuscates its first QUIC Initial with it. The
  target punches and is dialled; no `0x61` follows. Nothing else is ever
  answered: no oracle for who is online.
- **Requester ID 0** marks a foreign request on every path that wakes a
  target; a same-server forward never carries it (README).
- **Limits.** Per source IP: a burst of 10, then 1/s, and at most 60
  different target ids in 10 minutes. Per target: 6 foreign wake-ups a
  minute. One answer in flight per requester and target.
- **Announced** with `0x100000` in the UDP flags of the status reply (plain
  and obfuscated, to clients and servers) and in `ST_UDPFLAGS` at login.
- Status tab: foreign forwards and answers; Blocks tab: `natcb_foreign_*`.
- README: the wire contract and the limits; eNode-go's `0x200000` (NAT
  wake-up, PR_NAT) added to both flag tables, first free bit now `0x400000`.

### NAT-T counters, caches

- Client families in the counters carry the mod ("eMule/Xtreme9.1"): eMule
  mods all report as eMule.
- `/api/natt` also lists the last 60 NAT-T requests in detail: kind (0x60,
  0xA6, foreign 0xA6), both clients' software, login fingerprint, flags,
  UDP port and whether they sent a 0x9F, the target id's parity, outcome.
- **`/api/natt`**: every NAT-T counter since start plus live gauges (clients
  with 0x1000, with the extension, that sent 0x9F this session, obfuscated
  or not; pending extension waits; foreign sources tracked…). New counters:
  0x60 requests by client family, repeats for the same pair within 10
  minutes (the closest the server gets to a failure rate), the first answer
  per request (0x61 or each 0x62 reason — `holepunch_coordinated` also
  counts the resends); every 0x9F by outcome (obfuscated, plain, plain
  ignored, wrong IP, unknown hash); extension: time to the target's 0x9F in
  buckets, timeouts split by whether the target ever sent a 0x9F, late
  0x9F; bridges by client family; Lugdunum 0xA6: requests, refusals for a
  non-capable target split by even/odd LowID and by requester family,
  forwards by requester family; cross-server: requests, target with or
  without the extension.
- `/api/natt` "recent" also logs, once a minute per client, a 0x9F from
  another address than the client's session, with both addresses (166 in
  three hours from very few clients: the server can't use those ports).
- Status: "NAT-T clients" now counts clients that sent a 0x9F this session
  (and obfuscated ones); the old figure counted the UDP port announced at
  login, which stock clients send too.
- **Obfuscated UDP decode cache**: entries are aged out after 30 minutes
  (cap 262k, ~10 MB) instead of the map being cleared at 8192 every minute,
  which at 17k clients sent every obfuscated sender back to the cold path
  once a minute. A cold sender is first tried as a client — this server's
  key for its IP, direction 0x6B, one attempt — before the peer-server
  tables are scanned; it used to be the ninth attempt. Status shows decodes
  by the cached key, cold decodes, crypt pings answered (counted apart: they
  are not obfuscated eD2k) and undecodable datagrams. Most cold senders are
  clients of other servers sending a single global query, so cold decodes
  stay common; they are now cheap.
- **GETSOURCES cache** (the Status "Cache hits"): TTL 5 → 15 s, cap 4096 →
  65536, and a full cache skips the new entry instead of clearing itself —
  at several hundred requests a second the old cap was reached within
  seconds and the cache wiped about as fast as it filled. Status shows
  entries, misses on an expired entry with the entry's age (<30 s, 30–60 s,
  1–2 min, 2–5 min, >5 min: what a longer TTL would catch) and entries not
  stored. Cap 200k. New key `limits.getsources_cache_secs` (1–600, live),
  default 120 s: at 15 s about half of all misses (630k of 1.23M in three
  hours) came 30 s to 2 minutes after the entry was built. A changed TTL
  starts the cache statistics over; expired entries are swept every minute
  instead of piling up to the cap. The histogram counts how long past the
  TTL a request came (<1, 1–2, 2–5, 5–10, 10–20 min): by entry age, at a
  TTL of 300 s every expired miss fell into ">5 min". A swept entry leaves
  the map with its payload, but its key and insert time are remembered for
  20 more minutes (at most 400k, about 10 MB, outside the 200k cap), so a
  late request still lands in the histogram; dropped outright, every
  request later than one sweep read as a plain miss. "Entries" counts the
  fresh ones.

- **Undecodable UDP from a NAT-T client.** An obfuscated datagram no key
  decodes, from an address with a session here, is counted
  (`natt_udp_undecodable_from_session`); when the session set `0x1000`, also
  `natt_undecodable_from_natt_client` and an entry in `/api/natt` "recent"
  (once a minute per address). A keepalive obfuscated with a server key
  fetched for another address is unreadable and otherwise looks exactly
  like one never sent (#40).
- **`0x62` reason 5** for a `0x60` where either session is not over IPv4
  (an IPv6-only session is LowID too): the `0x61` would have carried
  `0.0.0.0` as the peer's address. No extension wake-up for such a pair.
  Counted as `holepunch_fail_no_ipv4`.

### IPv6 dial-back (issue #43)

A client's IPv6 is published as a source only after the server has dialled
`[address]:login port` with the HighID identity probe and got back the user
hash that logged in. Most dual-stack homes have a global address behind a
router that drops inbound IPv6; published on trust, it sent peers to an
address that never answered, and a client cannot test its own inbound IPv6.
Until the verdict the address is held (`ST_IPV6_STATUS` `0x01`); it comes in
a fresh `OP_SERVERIDENT`: `0x07` published, or `0x05` (`IPV6ST_PROBED` =
`0x04`) not published. The client stays able to receive IPv6 records. A new
address in `OP_IPV6_UPDATE` is dialled again, the same one keeps its verdict.
Shares the server-wide probe ceiling (a probe that finds it full is retried
a minute later), at most 4 dials per session since the client chooses where
they go. New key `network.ipv6_probe` (on, live); in force only with
`ipv6_publish_sources` and an IPv6 route on the host (checked at start and
every minute), and then announced with `0x400000` in `OP_IDCHANGE`.
Otherwise addresses are published on trust as before. Status tab: "IPv6
dial-back", with the failures by stage (connect timeout, refused, ICMP
unreachable, after the connect); Blocks tab: `ipv6_probe_*`. A probe whose
connect fails other than by a reset now reads "connect unreachable" instead
of "connect refused", in the HighID statistics too.

### Reported by itlezy (issues #44–#49)

- **HighID identity probe, obfuscated (#44).** The opening is
  `<marker><key part>RC4(<magic><methods supported><method preferred><padding
  length>)`, 12 bytes; it sent one method byte, so eMule and aMule read the
  first byte of the HELLO as the padding length and lost the stream. The HELLO
  now goes only after the peer's answer has been read and checked, and the
  answer's padding length is read as the whole byte: a client pads its answer
  to anyone but the server it is logging into with up to 254 bytes, which the
  4-bit mask cut short (the later re-checks and the IPv6 dial-back). Until now
  an obfuscated probe most likely succeeded only through its plain fallback,
  which a client requiring obfuscation refuses from any address but the
  server's own. Live, the HighID check's "no answer" fell from 19% of
  probes to under 5% (426 of 9.2k in eight hours). Tested against a peer that
  negotiates as aMule does.
- **One file, one size (#45).** A publisher whose size differs from the one
  stored for the hash is not merged into that file (`offer_size_mismatch`),
  and a sized source request for a hash stored with another size gets no
  sources (`getsources_size_mismatch_{tcp,udp}_{larger,smaller}`: which
  side asked for more), over TCP and in UDP `0x94`. The first size stays
  while the file has sources; once it has none, the next publisher's size
  replaces it, so a wrong size cannot hold a hash. Size 0 matches anything,
  and so does a size cut to 32 bits against the full one above 4 GiB (a
  client without large-file support): that is the same file, and the record
  takes the full size. A 64-bit `FT_FILESIZE` tag in `OP_OFFERFILES` is read
  whole (it used to be dropped, leaving size 0). Live: under 1% of source
  requests in eight hours asked with another size. **`/api/sizemismatch`**
  keeps the last 1000 disagreements (hash, stored and other size, the
  publisher's or requester's address, a publisher's software and whether its
  copy is complete; never a name) and groups them by file: every other size
  seen, with how many distinct addresses published or asked for it. No second record per (hash, size): the index stays one
  record per hash.
- **A replaced session is fenced (#46).** Once a newer login of the same user
  has taken over, the old socket's next frame closes it instead of being
  handled under a user hash it no longer owns (`replaced_session_frame_refused`).
  A silent one still goes after 10 minutes. Not for a shared hash (DLP's,
  mldonkey's, the operator's): its sessions are different installs, and
  fencing them sent each displaced one straight back to displace the other —
  live, shared-hash takeovers went from 1.2k in ten hours to 11k in eight.
- **Sources a requester can reach (#49).** Up to 800 of a file's sources are
  looked at (200 for UDP), HighID and departed ones first, LowID after, so the
  HighID sources are no longer hidden behind a reply's worth of LowIDs (nine
  sessions in ten are LowID). A stock LowID requester gets no LowID sources; a
  LowID requester with NAT traversal (`0x1000`, `0x100000` or the announced
  UDP port) gets the LowIDs that have it too; a HighID requester gets all of
  them for callbacks. Decided when the reply is served, so the cached payload
  still serves everyone.
- **Rust 1.75 (#48).** The lockfile had drifted onto releases that need Rust
  1.81–1.88 (`base64ct` 1.8, `zeroize` 1.9 and the ICU 2 line under `url`,
  several of them edition 2024). Pinned in `Cargo.toml` (`base64ct` =1.6.0,
  `zeroize` <1.9, `idna_adapter` =1.2.0, which selects ICU 1.5), the lockfile
  regenerated with the MSRV-aware resolver, and `.cargo/config.toml` sets
  `resolver.incompatible-rust-versions = "fallback"`. Every crate built on
  Linux now declares a rust-version of 1.75 or lower; the ones that do not
  are Windows / WASM only.
- **#47** (HighID only after the identity probe) is not taken: see the issue.

### OFFERFILES v1 (issue #19)

README: aMule's client side (PR #1715) is merged and on by default from its
next release; its 5 s wait for the login `OP_SERVERIDENT` and its re-offer
when the limits come late.

### Filter audit

- **`/api/review?format=audit` / `format=auditcsv`.** A false-positive audit
  that never shows a name the filter blocked rightly. Each blocked name is
  reduced to signals (explicit adult words, a child's age, a word for a
  child, a second listed term); a name is shown only with none of them, in
  a rule that is not a working marker. Per rule: hits, signal counts, file
  kinds, publishers and a verdict; the visible names; hashes withheld for
  explicit words only; L3 decoy candidates and alias leads with clean names
  only. The CSV adds a suggestion per hash (`whitelist?`, `review`, `keep`,
  `poison?`).
- **`/api/indexcheck`.** Every indexed file against the filter as it is now,
  hashes only, with whitelisted ones marked; `?purge=1` takes the blocked
  ones out of the index. Closes the gap where lists reloaded after a file was
  indexed were never applied to it.

### Same-hash logins (issue #41)

A login with a user hash that is already online used to replace that
session from any address. User hashes are public (every hello and source
exchange carries them), so anyone could take a live session over: its
shared files, its LowID callbacks, its hole-punch port. It now replaces the
session only when it is plausibly the same machine:

- the same IPv4, or the same IPv6 prefix (`admission.ipv6_source_prefix_bits`):
  the NAT-dropped reconnect, as before;
- a dual-stack move: an IPv4 session's own advertised IPv6 (`CT_MOD_IP_V6`),
  with the same listen port. Not the other way round;
- the old session is already gone.

Before refusing, the server holds the new login and probes the old
session (ModderMule's idea, refined by got3nks): the old socket gets a 10 s
`TCP_USER_TIMEOUT` and an `OP_SERVERSTATUS`. When the user has moved, the
old path is dead, nothing acknowledges the write, the kernel aborts the old
connection after ~10 s and the held login goes ahead — inside the 25 s
eMule-family clients wait for a login answer, so a real move succeeds on
the first attempt. An acknowledged write means the owner is there: the
login gets a server message ("This user hash is already connected from
another address") and is closed. One probe per session at a time, then a
10 s pause. A contender refused after a probe is refused without one for
ten minutes: two installs sharing a user hash retry every few seconds, and
probing the owner each time kept its socket on a 10 s fuse (the first four
hours live: 5.5k refusals, 1.4k probes). **A shared hash keeps the
old rule** — the newest login takes the session — when it is degenerate (12+
zero bytes, like the leecher mod's community hash
`00000000000E00000000000000006F00`; a random hash practically never is) or
on a built-in list — the 30 community, corrupt and invalid hashes of DLP's
antiLeech, plus mldonkey's `3649E68B070E85991648EF223A7F6FFD`, seen here from
many addresses in many countries at once (1.2k takeovers in ten hours once
listed, none refused) — or in the new `limits.shared_user_hashes` (live, added to the
built-in list). Such a hash
identifies no one; refusing all but one of its users locked them out (98%
of the refusals in the first hours came from three such hashes). Not by how
many addresses contest a hash: that is what a hijacker would produce
(got3nks) — `/api/takeover` only reports it (`looks_shared`). Counted as
`login_takeover_shared_hash`. Checked again just before the
session is stored. Counted in the Blocks tab (`login_hash_in_use`,
`login_takeover_probe`, `login_takeover_after_probe`,
`login_hash_in_use_known_contender`). **`/api/takeover`** lists the hashes
refused, worst first, with the contenders' addresses and the owner's
address and software: one or two contenders is a shared user hash, many is
a hash handed around. New key `limits.hash_takeover_from_any_address`
(off) restores the old rule.

## 0.9.85

Lugdunum's NAT callback (issue #39), so a client written for the original
eserver's NAT traversal works here unchanged, beside this server's own hole
punch; the hole-punch extension built on it with aMule and emule-qt; and a
bridge from `0x60` to clients that speak only Lugdunum's scheme. Two new
keys, `network.lugdunum_natt` and `network.holepunch_extension` (both on).

### Lugdunum's NAT callback

Read from Lugdunum's code and checked against aMule's implementation:

- **Login.** `0x1000` in the `OP_IDCHANGE` TCP flags, for every client, as
  Lugdunum sends it. A client that set `0x1000` in `CT_SERVER_FLAGS` gets an
  odd LowID and four more `OP_IDCHANGE` bytes: its TCP port as the server
  sees it (the source port of its connection for a LowID, its own port for a
  HighID). aMule turns the callback on only with both. Other clients get
  even LowIDs, so an odd LowID always means a capable client.
- **Request.** UDP `0xA6` `<target_id><requester_id>`, server-key
  obfuscated, from a logged-in LowID at the address of its TCP session. The
  datagram's source port is the requester's endpoint as the server sees it.
- **Forward.** `<ip><udp_port><requester_id><crypt>`, plus the requester's
  user hash and bit `0x80` when both support the crypt layer and one asks for
  it; nothing when one side requires it and the other can't. By UDP `0xA7`
  to the target's own endpoint when the target sent `0xA6` itself less than
  20 s ago, else by TCP `0x37`. The requester gets no answer, as on Lugdunum.
- **Stricter than Lugdunum**: the target must have set `0x1000` (Lugdunum
  also forwards to stock clients, which don't know `0x37`), and each
  requester gets a burst of 10 requests, then one a second.
- **No conflict.** The two schemes share no opcode or state: `0x60`-`0x62`,
  `0x9F` and `0x20000` are unchanged, and a client may use either. `0xA6` is
  server-to-client only in eNode-go's dialect, and `0xA7` goes only to a
  client that itself sent `0xA6`. Stock eMule ignores the `0x1000` server bit
  and reads `OP_IDCHANGE` only up to byte 20, as with Lugdunum.
- Status tab: forwards (TCP, UDP), refusals and capable clients; reasons in
  the Blocks tab as `natcb_*`.
- The config template sets `highid_verify_observe = false`: the verdict
  mode feeds the same counters.

### Hole-punch extension (flag `0x100000`)

`0x60` with fresh ports and no standing keepalive. Only between two clients
that both set `0x100000` with `0x1000` in `CT_SERVER_FLAGS`; the server sets
`0x100000` in `OP_IDCHANGE`. Every other pair gets today's punch byte for
byte.

- The target is woken with Lugdunum's `0x37`, carrying the requester's port.
  The server waits up to 3 s for the target's `0x9F`, then sends `0x61` to
  both with that fresh port, 30 bytes: `peer_crypt` (the peer's
  `(CT_SERVER_FLAGS >> 9) & 7`) appended. Resends at +1.2 s and +3 s.
- No `0x9F` within 3 s: the same `0x61` with the ports used today. A lost
  `0x9F` costs the wait, not the punch. No new failure reason.
- A repeated `0x60` while one waits adds nothing.
- On a server with the extension, a session that sent an obfuscated `0x9F`
  has its plain ones ignored (counted as `natt_keepalive_plain_ignored`).
- Status tab: coordinations started, released by a fresh `0x9F`, timed out;
  clients with the extension.

### Bridge to Lugdunum-only targets

A client that implements Lugdunum's callback but not `0x61` (NeoMule's
"CanLow2Low") could not be reached by `0x60`. A `0x60` whose target set
`0x1000`, did not announce the extension and has sent no `0x9F` in its
session now also sends that target Lugdunum's `0x37` (same crypt rule as on
the `0xA6` path), so it dials the requester. The requester's side is
unchanged. Status tab: "bridged".

### README

- A table of the `OP_IDCHANGE` TCP flag bits taken by eMule, Lugdunum,
  NeoLoader/ed2kNET, the IPv6 extension, eNode-go and this server (first free
  bit now `0x200000`), and one of the client's `CT_SERVER_FLAGS` bits.
- The extension and the bridge described next to the `0x60` contract.

## 0.9.84

Bot rules built from a day of live traffic: list scanners and hammering
clients caught over TCP and UDP, ordinary users (jdonkey included) left
alone, search services exempt, scanners into the IP filter for good and off
their TCP sessions. Search by file hash (`ed2k::HASH`) as Lugdunum does. LowID
hole punching: the support flag (issue #35), the right UDP port for two
clients behind one IP (#37), the peer ID in 0x61 (#38). One new optional
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
- The Bots tab shows THROTTLED and IP FILTER next to BANNED, and can be
  filtered by state (in the IP filter, banned 24 h, throttled 24 h, sanction
  over) and by rule (scanner, hammer, flood/uniform timing), searched by
  IP, country, provider, client or reason, and sorted by last sanction
  (the default), first seen, datagrams dropped since, files asked, rate or
  IP. A tally of each state sits next to the filters.
- **Detections no longer pile up in memory.** A detection, with up to its
  hashes, stayed until restart. It is now dropped a day after its ban or
  throttle ended and it went quiet; the ledger on disk keeps it. The hashes
  kept per bot are capped at 2 000 instead of 20 000 (up to ~0.5 MB per
  scanner before), and `/api/memsize` now counts them.

### Scanners and hammers, over TCP too

Seven hours of `/api/activity` (91 000 sources) showed where the rate rules
fall short. An ordinary eMule asks its server for sources of 15 files every
5 minutes, about 180 an hour, however long its download list; the busiest
ordinary source stayed under 1 000. Two kinds of source did not, and nearly
all of them over TCP, where nothing was judged before:

- **Scanners**, walking a list: 2 000 to 20 000 files an hour, nearly all
  different, each about once. Rule: at least `bots.scan_min_files` (2 000)
  files in an hour, at least `scan_min_distinct` (1 000) different, each
  asked at most `scan_max_repeats` (3) times on average, judged no sooner
  than `scan_min_minutes` (10) into the hour → `scan_action` ("ban").
- **Hammers**: the same file or two 5 to 600 times a minute, mostly a
  program built on jed2k with its default nick. Rule: at least
  `hammer_min_files` (3 000) in an hour, each file at least
  `hammer_min_rate` (5) times a minute on average → `hammer_action`
  ("throttle": `throttle_qpm` answers a minute, the session stays).
- **Not bots: jdonkey users.** The Android client asks for every download
  without a peer once a minute. A first version of these rules, run for a
  day on the live server, flagged 80 sources. It banned as scanners 5
  sources in their first 1 to 6 minutes (2 000 new downloads look like a
  list then) and 2 that asked each of ~1 000 files 4 to 9 times, and
  throttled as hammers 12 jdonkey users with 50 to 90 stalled downloads,
  each asked about once a minute. Under the rules above the 2 and the 12
  are left alone and the 5 are judged at minute 10; the 6 scanners that
  asked each file about once and 55 hammers remain.
- **`bots.exempt`**: addresses never judged, banned or written to the IP
  filter. Default `178.250.170.0/28`, ed2k.shortypower.org, which sends
  about 2 600 UDP searches a day from each of 11 addresses.
- Both count TCP `OP_GETSOURCES` and UDP source requests by file, per
  source, over an hour from its first request. Different files are
  estimated from the 200th file on, so most sources cost a counter only.
- A bot ban now covers TCP: its sessions are closed and it can't log in for
  the 24 hours (`bot_kick`, `bot_tcp_refused`). A throttled source's TCP
  source requests beyond its allowance go unanswered.
- `"log"` as an action only writes the match to the log and the ledger.

### Search activity

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
- `bots.activity_stats` (off by default) and `bots.activity_max_sources`
  (100 000 records, about 200 bytes each; further sources only in the
  totals). Both apply from the Settings tab without a restart. On for a day
  on the live server it took ~25 MB and a record update on each of 21
  million requests, so it is meant for tuning, not to stay on; switched
  off, the table is cleared within a minute.

### LowID hole punch flag (issue #35)

- `OP_IDCHANGE` TCP flags carry `0x20000` (`SRVFLG_LOWID_HOLEPUNCH`): this
  server accepts `OP_LOWID_HOLEPUNCH_REQUEST` (0x60). A client that knows
  both this scheme and Lugdunum's NAT callback (`0x1000`) can now tell which
  one a server runs, and send 0x60 only where it is understood. Free of every
  bit in use: 0x05DD, 0x1000, 0x4000, 0x8000, 0x10000.
- The IPv6 contract in the README no longer lists `CT_SERVER_FLAGS` `0x1000`.
  On Lugdunum that bit is `SRVCAP_NATTRAVERSAL`; eMuleQt withdrew it and aMule
  stops sending it. This server only ever keyed on the `CT_MOD_IP_V6` tag.

### Search by file hash

- A search string that names a file by hash is answered from the hash
  index, as Lugdunum's `Is_ed2k_search` does: `ed2k::HASH`,
  `ed2k:SIZE:HASH`, `ed2k://|file|NAME|SIZE|HASH|…`,
  `magnet:?xt=urn:ed2k:HASH`, `magnet:?xt=urn:ed2khash:HASH`. With a size,
  the size must match. TCP and UDP alike; the result obeys the content
  filter like any other.
- ed2k.shortypower.org looks files up with `ed2k::HASH` in a UDP search
  (0x90) from 11 addresses, about 8 000 a day. Every one returned nothing
  here, because the string was searched as a word (and then dropped as one
  no file has), so the service found no file on servers running this
  software while Lugdunum servers answered.
- Counted in the Health tab ("Searches by file hash").
- Integers in search results (size, sources, complete sources, type,
  length, bitrate) are written in the narrowest type, UINT8 up to 255 and
  UINT16 up to 65 535, as Lugdunum writes them. ed2k.shortypower.org read
  every tag of this server's answer except the source counts, which it
  takes only in the narrow forms; eMule and aMule read every width.

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

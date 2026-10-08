# OFFERFILES v1 draft verification

`offerfiles_v1.rs` checks production code in this checkout. It includes focused
unit tests and loopback TCP tests: the latter exercise the real connection
handler, codec, welcome generator, filter and index. The fake publisher is a
protocol fixture; it is not aMule and does not establish aMule interoperability.
All listeners use loopback and ephemeral ports. No public server is contacted.

## Run

```sh
cargo test --locked --test offerfiles_v1
```

The current v0.9.78 baseline has no OFFERFILES v1 advertisement or negotiated
record pacing. Future-feature tests are marked `#[ignore]` with explicit reasons.
To expose those gaps:

```sh
cargo test --locked --test offerfiles_v1 -- --ignored
```

That command is **expected to fail** today. Every draft first requires the real
server's `offerfiles_v=1` advertisement. Merely ignoring unknown configuration
keys, running the legacy handler, or checking a fabricated advertisement cannot
make a draft pass. Remove an ignore only after its behavior is implemented and
verified. All eight drafts currently stop at the missing advertisement; their
later pacing/limit assertions have compiled but have not executed successfully.

## Coverage

| Concern | Check | Current status |
|---|---|---|
| Default off and explicit off, even with large soft limits | Actual welcome tags for old/new tag client flags | Runnable |
| Correct file count and framing for plain/compressed offers | Real codec and parser, including fragmentation and coalescing | Runnable |
| Strict `count < ST_HARDFILES` | Codec checks plus real TCP rejection before parsing or indexing | Runnable |
| Distinct soft budget across batches, duplicate refreshes | Wire records through actual indexing handler and counters | Runnable |
| Independent publisher budgets | Concurrent production handlers and exact per-user counts | Runnable |
| Connection survives ordinary coalesced offers | Real TCP publication followed by search ordering barrier | Runnable |
| Disconnect clears source accounting; same-hash reconnect gets a fresh budget | Real TCP disconnect/re-login and reverse index checks | Runnable |
| Exactly one unsolicited, complete, uint32 v1 advertisement | Production welcome builder and actual TCP login | Draft / ignored |
| Invalid configuration emits no partial capability | Valid positive control, then zero/inconsistent field combinations | Draft / ignored |
| Coalesced packets wait for record tokens rather than being dropped | Plain and packed frames written together, elapsed-time bound, exact indexed count | Draft / ignored |
| Oversized batch below hard boundary is rejected without closing session | Index remains empty, following compliant batch succeeds | Draft / ignored |
| Soft/hard snapshot survives live reload; new login receives updated policy | Old session retains soft/hard limits; new login advertises new soft/hard/batch/interval values; new hard boundary disconnects | Draft / ignored |
| Concurrent publishers and reconnect waves lose no compliant records | Eight loopback publishers, two waves, exact per-user counts and cleanup | Draft / ignored |
| Global ceiling slows publishers without starvation or silent loss | Shared rate fixture, minimum drain time, all eight publishers finish | Draft / ignored |

The global-ceiling draft uses a proposed
`limits.offerfiles_global_records_per_second` configuration key and assumes one
200-record initial global bucket. Those are **test fixture choices**, not part of
the agreed wire contract or implemented configuration. Adapt the key and explicit
bucket-capacity setup to the eventual server implementation. The other capability
configuration spellings follow the proposal and are also not implemented here.

Timing assertions use generous completion deadlines and small lower-bound
tolerances. Search replies act as processing-order barriers; tests do not assume
OFFERFILES has acknowledgements or use arbitrary sleeps to infer indexing.

## Remaining system checks

Passing this suite alone will not resolve all review concerns:

- Run the actual aMule build with the experimental setting off/on. Confirm that
  missing or malformed support retains legacy pacing and valid support activates
  bounded publication. Record both server and client revisions and packet traces.
- Measure actual aMule packet emission for a 500 ms advertisement. Its current
  approximately one-second processing loop does not verify sub-second scheduling.
- Verify aMule updates its shared live soft/hard metadata atomically from
  SERVERIDENT. Its policy-helper unit tests do not exercise that socket path.
- Exercise global saturation at larger scales, slow indexing, paused readers,
  fragmented writes and reconnect storms. Measure RSS, open sockets, pending work,
  processing rate, queue bounds and recovery. The small concurrent tests here do
  not establish memory bounds, production capacity or strict FIFO fairness.
- Check advertised values equal enforcement values on the released server source,
  including retained snapshot values after reload. Do not infer this from matching
  configuration names alone.

`contrib/overload_test.py` already tests admission limits. It does not currently
validate the proposed OFFERFILES v1 record-rate policy, and should not be reported
as that validation.

Contract and review references:

- [Server contract discussion](https://github.com/andrey23127/ed2k-server/issues/19#issuecomment-5930455238)
- [aMule request](https://github.com/amule-org/amule/issues/1699)
- [Maintainer's real-server review requirement](https://github.com/amule-org/amule/pull/1715#issuecomment-6048405817)

# CPU tuning: `target-cpu` in `.cargo/config.toml`

The repository's `.cargo/config.toml` contains a commented-out line such as:

```toml
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "target-cpu=znver3", "-C", "link-arg=-Wl,--gc-sections"]
```

This page explains what it does, which value to pick for which processor, and
what it can and cannot fix.

## What the two flags do

| Flag | Effect |
|---|---|
| `-C target-cpu=<cpu>` | Lets the compiler use every instruction that CPU has (AVX2, BMI2, POPCNT, …) and tune instruction scheduling for it. The binary then **requires** those instructions: on an older CPU, or on a VPS that hides them, it stops with `Illegal instruction` (SIGILL) at the first one it hits — possibly at startup, possibly hours later. |
| `-C link-arg=-Wl,--gc-sections` | Drops unused code at link time. A slightly smaller binary, no runtime effect, safe everywhere. Keep it. |

Without any `target-cpu` the binary is built for plain `x86-64` (2003-era
instructions plus SSE2) and runs on every 64-bit x86 machine. **That is the safe
default.** The gain from tuning is real but modest — a few percent of CPU in the
hot paths (hashing, keyword matching, search ranking). It does not change
memory use, and it does not cause or cure load spikes (see the last section).

## Step 1 — find out what the *running* machine supports

Run these on the machine that will **run** the binary, not the one that builds
it:

```bash
# CPU model
lscpu | grep -E 'Model name|Hypervisor vendor|Virtualization'

# Which x86-64 level the CPU (as this OS sees it) supports — glibc 2.33+:
/lib64/ld-linux-x86-64.so.2 --help | grep supported
#   x86-64-v4  (AVX-512)
#   x86-64-v3 (supported, searched)   <- this machine can run v3
#   x86-64-v2 (supported, searched)

# What Rust thinks the host is
rustc --print target-cpus | head -3      # "native ... (currently znver3)"
```

On a **VPS**, the hypervisor decides which instructions the guest sees. It often
hides some (to allow live migration between different hosts), so the model
name can say "EPYC 7003" while AVX2 or other features are masked. Trust the
`ld-linux --help` output and `/proc/cpuinfo` flags, not the model name:

```bash
grep -o -w -E 'avx2|bmi2|fma|avx512f|vaes|vpclmulqdq' /proc/cpuinfo | sort | uniq -c
```

## Step 2 — pick a value

**Rule of thumb:**

- **VPS or cloud instance** — use an **`x86-64-vN` level**, not a model name.
- **Dedicated server you control, building on the same machine** — a model name
  or `native` is fine.

### Portable levels (recommended for VPS)

| Value | Needs | Runs on |
|---|---|---|
| *(none)* / `x86-64` | — | everything |
| `x86-64-v2` | SSE4.2, POPCNT | Intel since 2009 (Nehalem), AMD since 2011 (Bulldozer) |
| `x86-64-v3` | AVX2, BMI2, FMA | Intel since 2013 (Haswell; not Atom/Celeron/Pentium before 2021), AMD since 2015 (Excavator) and every Zen. **Best choice for almost every VPS.** |
| `x86-64-v4` | AVX-512 F/BW/CD/DQ/VL | Intel Xeon Scalable (Skylake-SP and newer), AMD Zen 4 and Zen 5. Not on consumer Intel 12th–14th gen. Rarely worth it here. |

### AMD

| Value | Processors |
|---|---|
| `znver1` | Ryzen 1000/2000, Threadripper 1000/2000, EPYC 7001 |
| `znver2` | Ryzen 3000 and Ryzen 4000/5000 mobile APUs with Zen 2, Threadripper 3000, EPYC 7002 |
| `znver3` | Ryzen 5000, Threadripper 5000, EPYC 7003 (Milan) |
| `znver4` | Ryzen 7000/8000, Threadripper 7000, EPYC 9004 (Genoa), EPYC 8004 |
| `znver5` | Ryzen 9000, EPYC 9005 (Turin). Needs Rust 1.82 or newer |

### Intel

| Value | Processors |
|---|---|
| `haswell` | Core 4th gen, Xeon E3/E5 v3 |
| `skylake` | Core 6th–10th gen desktop, Xeon E3 v5/v6 |
| `skylake-avx512` | Xeon Scalable 1st gen (Skylake-SP), Xeon W-2100 |
| `cascadelake` | Xeon Scalable 2nd gen |
| `icelake-server` | Xeon Scalable 3rd gen (Ice Lake-SP) |
| `sapphirerapids` | Xeon Scalable 4th gen; `emeraldrapids` 5th gen |
| `alderlake` | Core 12th–14th gen desktop/laptop |

### ARM (aarch64 build target)

| Value | Processors |
|---|---|
| `neoverse-n1` | AWS Graviton2, Ampere Altra, Oracle A1 |
| `neoverse-v1` | AWS Graviton3 |
| `neoverse-v2` | AWS Graviton4, NVIDIA Grace |

For aarch64 the section header is `[target.aarch64-unknown-linux-gnu]`.

The full list for your toolchain: `rustc --print target-cpus`.

### `native`

`target-cpu=native` means "whatever the build machine reports". It is right
only when you build and run on the **same** machine. On a VPS it captures what
the hypervisor shows *today*; after a migration to another host the binary can
die with SIGILL. Prefer `x86-64-v3` there.

## Step 3 — write it and rebuild

Uncomment **one** block in `.cargo/config.toml`, for example for a VPS:

```toml
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "target-cpu=x86-64-v3", "-C", "link-arg=-Wl,--gc-sections"]
```

Then rebuild from scratch, so nothing compiled with the old flags remains:

```bash
cargo clean
cargo build --release
```

Check that the result starts and stays up on the target machine. A wrong
`target-cpu` shows up as `Illegal instruction` / `status=4/ILL` in
`systemctl status ed2k-server` or the journal — not as slowness.

A `RUSTFLAGS` environment variable **replaces** the `rustflags` from
`.cargo/config.toml` entirely; unset it if the tuning seems not to apply.

## What `target-cpu` does *not* explain: periodic CPU spikes

A wrong `target-cpu` crashes the server; it does not make CPU load jump up and
down. A server whose load rises in regular bursts is usually doing one of its
periodic jobs, or the machine is being slowed by something outside the server.

**Periodic work in the server** (and when it shows):

| Interval | Work | Grows with |
|---|---|---|
| every `limits.ping_delay_seconds` (300 s in the VPS template) | `OP_SERVERSTATUS` to every connected client | number of clients |
| every 10 min (first run 30 min after start) | sweep of the whole file index for entries left without sources | number of indexed files — the largest periodic job on a big server |
| every 60 s | housekeeping: expired bans, bot trackers, stale server-list entries, peer descriptions | small |
| every 30 s | change checks of the filter lists and other data files; a changed file is re-read and re-parsed (the IP filter and GeoIP database are the large ones) | file size, only when a file changed |
| on demand | login storms after a restart or a network blip, UDP global-search waves from other servers' users | clients, other servers |

The memory allocator also returns freed memory to the OS in the background
(`jemalloc_bg_thd` thread, about once a second); that is steady, not bursty.

**Outside the server** — common on AMD machines and VPS:

- **CPU frequency scaling.** With `amd-pstate`/`schedutil` or the `powersave`
  governor the core clock drops when idle, so the same work shows as a higher
  percentage. Check `cpupower frequency-info`; on a dedicated server
  `cpupower frequency-set -g performance` removes that effect.
- **Steal time on a VPS.** The `st` value in `top` is CPU time taken by other
  guests on the same host. Spikes with high `st` are the neighbours, not the
  server.

**Finding out which it is.** During a spike:

```bash
# Which threads are busy: tokio-runtime-w runs both the network/protocol work
# and the blocking jobs (searches, the index sweep); jemalloc_bg_thd is the
# allocator. One thread at 100% for a second or two = one blocking job.
top -H -p $(pgrep -f ed2k-server)

# Per-thread CPU once a second; note the interval between bursts
pidstat -t -p $(pgrep -f ed2k-server) 1

# What code is running (needs linux-perf)
perf top -p $(pgrep -f ed2k-server)
```

The admin panel helps to match a burst with a cause: the *Status* tab
(searches, admission pools and queues, clients), *Bots* and *Health*. A burst
every 5 minutes points at the client keepalive, one every 10 minutes at the
index sweep, an irregular one with many refused or queued searches at search
load.

When you report such a problem, please include: the CPU model and whether it is
a VPS, `uptime`/load average, the interval between spikes, the `top -H` output
during one, the number of clients and files from the Status tab, and the
`target-cpu` (if any) the binary was built with.

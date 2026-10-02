#!/usr/bin/env python3
"""Overload test for the [admission] limits (issue #25).

Drives a RUNNING server with more work than its admission ceilings allow, on
every path the ceilings cover, and checks that it stays bounded and recovers:

  1. setup flood      more silent sockets than max_pending_logins
  2. search load      many established sessions searching back to back
  3. UDP flood        searches, source requests and status queries on every
                      UDP listener, from rotating source addresses
  4. relay flood      callback and hole-punch requests from one session
  5. gossip flood     server-list requests (0xA0) on every UDP listener
  6. recovery         after traffic stops: pools drain, readiness returns,
                      a fresh login and search succeed without a restart

During each phase it samples /api/admission and the process RSS and asserts:
gauges never exceed their ceilings, the admin endpoint keeps answering,
existing sessions keep getting answers, the rejection counters name the
saturated path, readiness reports sustained saturation, and RSS plateaus.

Use the matching small-capacity config so the ceilings are reachable from one
machine:

    ed2k-server --config contrib/overload_test.toml &
    python3 contrib/overload_test.py --pid $!

Source rotation uses 127.0.0.0/8, which Linux routes to loopback. Note that
loopback is exempt from max_clients_per_ip, so the per-IP TCP limit is not
exercised here (it has unit tests).
"""

import argparse
import json
import socket
import struct
import sys
import threading
import time
import urllib.request

FAILS = []


def check(cond, what):
    print(("  ok   " if cond else "  FAIL ") + what)
    if not cond:
        FAILS.append(what)


# ── eD2k framing ─────────────────────────────────────────────────────────────

def frame(opcode, payload=b""):
    body = bytes([opcode]) + payload
    return b"\xe3" + struct.pack("<I", len(body)) + body


def string_tag(tag_id, text):
    t = text.encode()
    return b"\x02" + struct.pack("<H", 1) + bytes([tag_id]) + struct.pack("<H", len(t)) + t


def u32_tag(tag_id, v):
    return b"\x03" + struct.pack("<H", 1) + bytes([tag_id]) + struct.pack("<I", v)


def login_frame(n):
    user_hash = struct.pack("<I", n) + bytes([0x5A]) * 12
    tags = string_tag(0x01, f"load{n}")
    return frame(0x01, user_hash + struct.pack("<IHI", 0, 4662, 1) + tags)


def offer_frame(first, count):
    recs = b""
    for i in range(first, first + count):
        h = struct.pack("<I", i) + b"\x77" * 12
        tags = string_tag(0x01, f"overload sample file {i % 50} part {i}.avi") + u32_tag(0x02, 1_000_000 + i)
        recs += h + struct.pack("<IHI", 0xFBFBFBFB, 0xFBFB, 2) + tags
    return frame(0x15, struct.pack("<I", count) + recs)


def search_tree(text):
    t = text.encode()
    return b"\x01" + struct.pack("<H", len(t)) + t


class Reader:
    """Counts frames arriving on a TCP socket, by opcode, in the background."""

    def __init__(self, sock):
        self.sock = sock
        # Block indefinitely: a read timeout would end the thread and look
        # like a closed session.
        sock.settimeout(None)
        self.counts = {}
        self.closed = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        buf = b""
        try:
            while True:
                d = self.sock.recv(65536)
                if not d:
                    break
                buf += d
                while len(buf) >= 6:
                    ln = struct.unpack("<I", buf[1:5])[0]
                    if len(buf) < 5 + ln:
                        break
                    op = buf[5]
                    self.counts[op] = self.counts.get(op, 0) + 1
                    buf = buf[5 + ln:]
        except OSError:
            pass
        self.closed = True


# ── server-side observation ──────────────────────────────────────────────────

class Server:
    def __init__(self, args):
        self.a = args

    def admission(self, timeout=2.0):
        t0 = time.time()
        with urllib.request.urlopen(f"http://127.0.0.1:{self.a.admin_port}/api/admission", timeout=timeout) as r:
            body = json.load(r)
        return body, time.time() - t0

    def ready(self):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.a.admin_port}/api/ready", timeout=2) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def rss_mb(self):
        if not self.a.pid:
            return None
        with open(f"/proc/{self.a.pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS"):
                    return int(line.split()[1]) / 1024
        return None

    def connect(self, src="127.0.0.1"):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.bind((src, 0))
        s.connect((self.a.host, self.a.tcp_port))
        return s


class Sampler:
    """Polls /api/admission while a phase runs; keeps the worst values."""

    POOLS = ["open_tcp", "pending_login", "probes", "retries", "search_jobs", "search_queue"]

    def __init__(self, srv):
        self.srv = srv
        self.max_in_use = {p: 0 for p in self.POOLS}
        self.caps = {}
        self.max_latency = 0.0
        self.max_src = 0
        self.src_cap = 0
        self.errors = 0
        self.max_rss = 0.0
        self.stop = threading.Event()
        self.t = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self.stop.is_set():
            try:
                m, lat = self.srv.admission()
                self.max_latency = max(self.max_latency, lat)
                for p in self.POOLS:
                    self.max_in_use[p] = max(self.max_in_use[p], m[p]["in_use"])
                    self.caps[p] = m[p]["cap"]
                self.max_src = max(self.max_src, m["udp"]["source_entries"])
                self.src_cap = m["udp"]["source_entries_cap"]
            except Exception:
                self.errors += 1
            rss = self.srv.rss_mb()
            if rss:
                self.max_rss = max(self.max_rss, rss)
            time.sleep(0.1)

    def __enter__(self):
        self.t.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.t.join()

    def assert_bounded(self):
        for p in self.POOLS:
            if p in self.caps:
                check(self.max_in_use[p] <= self.caps[p],
                      f"{p}: peak {self.max_in_use[p]} within cap {self.caps[p]}")
        check(self.max_src <= self.src_cap, f"UDP source table: peak {self.max_src} within cap {self.src_cap}")
        check(self.errors == 0 and self.max_latency < 1.0,
              f"admin endpoint responsive (worst {self.max_latency * 1000:.0f} ms, {self.errors} errors)")


def counter(m, *path):
    for p in path:
        m = m[p]
    return m


# ── phases ───────────────────────────────────────────────────────────────────

def phase_setup_flood(srv):
    print("1. setup flood")
    m0, _ = srv.admission()
    cap = m0["pending_login"]["cap"]
    socks = []
    with Sampler(srv) as smp:
        for i in range(cap * 2):
            try:
                socks.append(srv.connect())
            except OSError:
                pass
        # Silent sockets live until the setup timeout (5 s); readiness needs
        # the pool full for readiness_window_secs.
        time.sleep(2.5)
        code, body = srv.ready()
        m1, _ = srv.admission()
    for s in socks:
        s.close()
    smp.assert_bounded()
    check(counter(m1, "pending_login", "rejected") > counter(m0, "pending_login", "rejected"),
          "pending_login refusals counted")
    check(code == 503 and "pending_login" in body["saturated"],
          f"readiness reports the saturated pool (HTTP {code}, {body['saturated']})")


def login(srv, n, src="127.0.0.1"):
    s = srv.connect(src)
    s.sendall(login_frame(n))
    r = Reader(s)
    deadline = time.time() + 5
    while time.time() < deadline and 0x40 not in r.counts and not r.closed:
        time.sleep(0.02)
    return s, r


def phase_search_load(srv, sessions):
    print("2. search load from established sessions")
    m0, _ = srv.admission()
    conns = []
    for i in range(sessions):
        s, r = login(srv, 1000 + i)
        if 0x40 in r.counts:
            conns.append((s, r))
    check(len(conns) == sessions, f"{len(conns)}/{sessions} sessions logged in")
    for i, (s, _) in enumerate(conns[:5]):
        s.sendall(offer_frame(i * 200, 200))
    time.sleep(1)
    per = 40
    with Sampler(srv) as smp:
        for _ in range(per):
            for s, _ in conns:
                try:
                    s.sendall(frame(0x16, search_tree("overload sample")))
                except OSError:
                    pass
        deadline = time.time() + 15
        while time.time() < deadline:
            got = sum(r.counts.get(0x33, 0) for _, r in conns)
            if got >= per * len(conns):
                break
            time.sleep(0.2)
    m1, _ = srv.admission()
    smp.assert_bounded()
    got = sum(r.counts.get(0x33, 0) for _, r in conns)
    check(got == per * len(conns), f"every search answered ({got}/{per * len(conns)})")
    shed = counter(m1, "tcp_search_shed") - counter(m0, "tcp_search_shed")
    print(f"       searches answered empty under load: {shed}; worst wait {m1['search_wait_ms']['max']} ms")
    return conns


def udp_flood(srv, payloads, seconds, sources):
    ports = [srv.a.tcp_port + d for d in (4, 8, 12, 14)]
    socks = []
    for i in range(sources):
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.bind((f"127.0.{(i >> 8) & 255}.{(i & 255) or 1}", 0))
        socks.append(u)
    end = time.time() + seconds
    sent = 0
    while time.time() < end:
        for u in socks:
            for port in ports:
                for p in payloads:
                    try:
                        u.sendto(p, (srv.a.host, port))
                        sent += 1
                    except OSError:
                        pass
    for u in socks:
        u.close()
    return sent


def phase_udp_flood(srv):
    print("3. UDP flood on every listener, rotating sources")
    m0, _ = srv.admission()
    payloads = [
        b"\xe3\x98" + search_tree("overload sample"),
        b"\xe3\x9a" + struct.pack("<I", 3) + b"\x77" * 12,
        b"\xe3\x96" + struct.pack("<I", 0x55AA55AA),
    ]
    with Sampler(srv) as smp:
        sent = udp_flood(srv, payloads, 4, sources=600)
    m1, _ = srv.admission()
    smp.assert_bounded()
    d = lambda k: counter(m1, "udp", k) - counter(m0, "udp", k)
    print(f"       sent {sent}; refused global {d('refused_global')}, source {d('refused_source')}, "
          f"table {d('refused_table_full')}; search shed {counter(m1, 'udp_search_shed') - counter(m0, 'udp_search_shed')}")
    check(d("refused_global") + d("refused_source") + d("refused_table_full") > 0,
          "UDP refusals counted")


def phase_relay_flood(srv, conns):
    print("4. callback / hole-punch flood from one session")
    m0, _ = srv.admission()
    s, r = conns[0]
    before_fail = r.counts.get(0x36, 0)
    with Sampler(srv) as smp:
        for i in range(500):
            s.sendall(frame(0x1C, struct.pack("<I", 7 + i)))
            s.sendall(frame(0x60, struct.pack("<IH", 9 + i, 4672)))
        time.sleep(1)
    m1, _ = srv.admission()
    smp.assert_bounded()
    check(counter(m1, "relay_rejected") > counter(m0, "relay_rejected"), "relay refusals counted")
    check(r.counts.get(0x36, 0) > before_fail, "callbacks over the budget get OP_CALLBACK_FAIL")
    check(counter(m1, "retries", "in_use") <= counter(m1, "retries", "cap"), "retry tasks within cap")
    check(not r.closed, "the flooding session itself is still served")


def phase_gossip_flood(srv):
    print("5. gossip flood (server-list requests)")
    m0, _ = srv.admission()
    with Sampler(srv) as smp:
        udp_flood(srv, [b"\xe3\xa0"], 2, sources=50)
    m1, _ = srv.admission()
    smp.assert_bounded()
    refused = sum(counter(m1, "udp", k) - counter(m0, "udp", k)
                  for k in ("refused_global", "refused_source", "refused_table_full"))
    check(refused > 0, "server-list requests charged to the UDP budget")


def phase_recovery(srv, conns):
    print("6. recovery")
    for s, _ in conns:
        s.close()
    deadline = time.time() + 15
    m = None
    while time.time() < deadline:
        m, _ = srv.admission()
        busy = [p for p in ("pending_login", "search_jobs", "search_queue", "retries") if m[p]["in_use"]]
        if not busy and srv.ready()[0] == 200:
            break
        time.sleep(0.5)
    check(all(m[p]["in_use"] == 0 for p in ("pending_login", "search_jobs", "search_queue", "retries")),
          "pools drained")
    check(srv.ready()[0] == 200, "ready again")
    s, r = login(srv, 99_999)
    check(0x40 in r.counts, "a fresh login succeeds")
    s.sendall(frame(0x16, search_tree("overload sample")))
    deadline = time.time() + 5
    while time.time() < deadline and 0x33 not in r.counts:
        time.sleep(0.05)
    check(0x33 in r.counts, "a fresh search is answered")
    s.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--tcp-port", type=int, default=24661)
    ap.add_argument("--admin-port", type=int, default=28080)
    ap.add_argument("--pid", type=int, help="server pid, to sample RSS")
    ap.add_argument("--sessions", type=int, default=40)
    args = ap.parse_args()
    srv = Server(args)

    rss0 = srv.rss_mb()
    phase_setup_flood(srv)
    conns = phase_search_load(srv, args.sessions)
    phase_udp_flood(srv)
    phase_relay_flood(srv, conns)
    rss_mid = srv.rss_mb()
    phase_gossip_flood(srv)
    phase_udp_flood(srv)  # the same load again: memory must not keep growing
    rss_end = srv.rss_mb()
    phase_recovery(srv, conns)
    if rss0:
        print(f"RSS: start {rss0:.1f} MB, mid {rss_mid:.1f} MB, end {rss_end:.1f} MB")
        check(rss_end - rss_mid < 16, "RSS plateaus under repeated load")

    print()
    if FAILS:
        print(f"{len(FAILS)} check(s) FAILED")
        sys.exit(1)
    print("all checks passed")


if __name__ == "__main__":
    main()

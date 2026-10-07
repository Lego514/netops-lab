"""Measure this machine's network, one layer at a time, and say which layer is at fault.

"The internet is down" can mean four different things with four different fixes:

    1. gateway   can't reach the local router         -> Wi-Fi / cable / router
    2. internet  router fine, public IPs unreachable  -> the ISP
    3. dns       IPs reachable, names don't resolve   -> the DNS resolver
    4. service   names resolve, the site won't answer -> that one service

Each layer only means something if the layers below it work, so the probe
checks bottom-up and reports the first layer that is down or degraded. Results
go into SQLite so a slow evening can be compared with a normal one.
"""

from __future__ import annotations

import argparse
import platform
import re
import socket
import sqlite3
import statistics
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

INTERNET_IPS = ["1.1.1.1", "8.8.8.8"]
DNS_NAMES = ["www.udel.edu", "github.com"]
SERVICES = [("www.udel.edu", 443), ("github.com", 443)]

# A layer is "degraded" above these (not down, but worth knowing about).
MAX_LOSS_PCT = 5.0
MAX_P95_MS = 150.0
WINDOWS = platform.system() == "Windows"


# ---------------------------------------------------------------------------
# Raw measurements. Each returns milliseconds, or None on failure.

_RTT = re.compile(r"[=<]\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)


def parse_ping(output: str) -> float | None:
    """RTT from one ping's output (Windows or Linux, any UI language), None if no reply.

    A reply line always carries a TTL, in every language Windows ships; the
    "Request timed out" and "Destination host unreachable" lines never do.
    """
    for line in output.splitlines():
        if "ttl" in line.lower():
            m = _RTT.search(line)
            if m:
                return float(m.group(1))
    return None


def ping_once(host: str, timeout_s: float = 1.0) -> float | None:
    if WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_s))), host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 2, errors="replace")
    except subprocess.TimeoutExpired:
        return None
    return parse_ping(out.stdout)


def dns_once(name: str) -> float | None:
    start = time.perf_counter()
    try:
        socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return None
    return (time.perf_counter() - start) * 1000


def tcp_once(host: str, port: int, timeout_s: float = 3.0) -> float | None:
    """Time to complete a TCP handshake (includes the name lookup's cached answer)."""
    try:
        addr = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)[0][4]
    except OSError:
        return None
    start = time.perf_counter()
    try:
        with socket.create_connection(addr[:2], timeout=timeout_s):
            return (time.perf_counter() - start) * 1000
    except OSError:
        return None


_ROUTE_PRINT = re.compile(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", re.MULTILINE)
_IP_ROUTE = re.compile(r"default via (\d+\.\d+\.\d+\.\d+)")


def parse_gateway(output: str) -> str | None:
    m = _ROUTE_PRINT.search(output) or _IP_ROUTE.search(output)
    return m.group(1) if m else None


def default_gateway() -> str | None:
    cmd = ["route", "print", "-4", "0.0.0.0"] if WINDOWS else ["ip", "route", "show", "default"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5, errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        return None
    return parse_gateway(out.stdout)


# ---------------------------------------------------------------------------
# Statistics.


@dataclass
class Stats:
    target: str
    sent: int
    rtts: list[float] = field(default_factory=list)  # successful samples only

    @property
    def received(self) -> int:
        return len(self.rtts)

    @property
    def loss_pct(self) -> float:
        return 100.0 * (self.sent - self.received) / self.sent if self.sent else 100.0

    @property
    def avg_ms(self) -> float | None:
        return statistics.fmean(self.rtts) if self.rtts else None

    @property
    def p95_ms(self) -> float | None:
        if not self.rtts:
            return None
        s = sorted(self.rtts)
        return s[max(0, -(-95 * len(s) // 100) - 1)]  # nearest rank

    @property
    def jitter_ms(self) -> float | None:
        """Mean absolute difference between consecutive samples (the RFC 3550 idea, unsmoothed)."""
        if len(self.rtts) < 2:
            return None
        return statistics.fmean(abs(b - a) for a, b in zip(self.rtts, self.rtts[1:]))


def collect(target: str, fn, count: int, pause_s: float = 0.2) -> Stats:
    st = Stats(target, count)
    for i in range(count):
        ms = fn()
        if ms is not None:
            st.rtts.append(ms)
        if i < count - 1:
            time.sleep(pause_s)
    return st


# ---------------------------------------------------------------------------
# Layers and diagnosis.

LAYERS = ["gateway", "internet", "dns", "service"]
FIXES = {
    "gateway": "Local network: check Wi-Fi signal, the cable, or restart the router.",
    "internet": "The local router is fine but public IPs are unreachable: likely the ISP.",
    "dns": "IPs are reachable but names don't resolve: switch DNS (e.g. 1.1.1.1) or restart the router.",
    "service": "The network is fine; that service itself is down or blocking you.",
}


@dataclass
class LayerResult:
    layer: str
    stats: list[Stats]

    @property
    def status(self) -> str:
        """down: nothing answered on any target. degraded: loss or latency over the line."""
        if not self.stats or all(s.received == 0 for s in self.stats):
            return "down"
        for s in self.stats:
            if s.loss_pct > MAX_LOSS_PCT or (s.p95_ms or 0) > MAX_P95_MS:
                return "degraded"
        return "ok"


def diagnose(results: list[LayerResult]) -> tuple[str, str | None]:
    """(overall status, faulty layer): the lowest layer that isn't ok."""
    for r in results:
        if r.status != "ok":
            return r.status, r.layer
    return "ok", None


def measure(count: int) -> list[LayerResult]:
    gw = default_gateway()
    gateway = [collect(gw, lambda: ping_once(gw), count)] if gw else []
    internet = [collect(ip, lambda ip=ip: ping_once(ip), count) for ip in INTERNET_IPS]
    dns = [collect(n, lambda n=n: dns_once(n), max(3, count // 3)) for n in DNS_NAMES]
    service = [collect(f"{h}:{p}", lambda h=h, p=p: tcp_once(h, p), max(3, count // 3)) for h, p in SERVICES]
    return [
        LayerResult("gateway", gateway),
        LayerResult("internet", internet),
        LayerResult("dns", dns),
        LayerResult("service", service),
    ]


# ---------------------------------------------------------------------------
# Storage and reporting.

SCHEMA = """
create table if not exists probe (
  at        text not null,
  layer     text not null,
  target    text not null,
  sent      integer not null,
  received  integer not null,
  loss_pct  real not null,
  avg_ms    real,
  p95_ms    real,
  jitter_ms real,
  status    text not null
);
create table if not exists verdict (
  at     text not null,
  status text not null,
  layer  text
);
"""


def save(db: sqlite3.Connection, at: str, results: list[LayerResult], verdict: tuple[str, str | None]) -> None:
    db.executescript(SCHEMA)
    for r in results:
        for s in r.stats:
            db.execute(
                "insert into probe values (?,?,?,?,?,?,?,?,?,?)",
                (at, r.layer, s.target, s.sent, s.received, s.loss_pct, s.avg_ms, s.p95_ms, s.jitter_ms, r.status),
            )
    db.execute("insert into verdict values (?,?,?)", (at, *verdict))
    db.commit()


def previous_verdict(db: sqlite3.Connection) -> tuple[str, str | None] | None:
    db.executescript(SCHEMA)
    row = db.execute("select status, layer from verdict order by rowid desc limit 1").fetchone()
    return (row[0], row[1]) if row else None


def report(results: list[LayerResult], verdict: tuple[str, str | None]) -> str:
    fmt = lambda v: "-" if v is None else f"{v:.1f}"  # noqa: E731
    lines = [f"{'layer':<9} {'target':<20} {'loss%':>6} {'avg':>7} {'p95':>7} {'jitter':>7}  status"]
    for r in results:
        if not r.stats:
            lines.append(f"{r.layer:<9} {'(not found)':<20} {'':>6} {'':>7} {'':>7} {'':>7}  {r.status}")
        for s in r.stats:
            lines.append(
                f"{r.layer:<9} {s.target:<20} {s.loss_pct:>6.1f} {fmt(s.avg_ms):>7} {fmt(s.p95_ms):>7} "
                f"{fmt(s.jitter_ms):>7}  {r.status}"
            )
    status, layer = verdict
    lines.append("")
    lines.append("verdict: all layers ok" if status == "ok" else f"verdict: {layer} {status}. {FIXES[layer or 'service']}")
    return "\n".join(lines)


def alert_text(before: tuple[str, str | None] | None, now: tuple[str, str | None]) -> str | None:
    """An alert only when the verdict changes, so a long outage is one message, not hundreds."""
    if before is None or before == now:
        return None
    if now[0] == "ok":
        return f"RECOVERED: all layers ok (was {before[1]} {before[0]})"
    return f"ALERT: {now[1]} {now[0]}. {FIXES[now[1] or 'service']}"


def run_cli(args: argparse.Namespace) -> int:
    with sqlite3.connect(args.db) as db:
        while True:
            at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            results = measure(args.count)
            verdict = diagnose(results)
            before = previous_verdict(db)
            save(db, at, results, verdict)
            print(f"[{at}]")
            print(report(results, verdict))
            alert = alert_text(before, verdict)
            if alert:
                print(alert)
            if not args.watch:
                return 0 if verdict[0] == "ok" else 1
            time.sleep(args.watch)

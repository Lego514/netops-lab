import sqlite3

import pytest

from netops.probe import (
    LayerResult,
    Stats,
    alert_text,
    diagnose,
    parse_gateway,
    parse_ping,
    previous_verdict,
    save,
)

WINDOWS_REPLY = """
Pinging 1.1.1.1 with 32 bytes of data:
Reply from 1.1.1.1: bytes=32 time=17ms TTL=57

Ping statistics for 1.1.1.1:
"""
WINDOWS_LAN = "Reply from 10.0.0.1: bytes=32 time<1ms TTL=64"
WINDOWS_TIMEOUT = "Pinging 10.9.9.9 with 32 bytes of data:\nRequest timed out.\n"
# A reply from a router saying it can't reach the host is not a reply from the host.
WINDOWS_UNREACHABLE = "Reply from 10.0.0.1: Destination host unreachable.\n"
WINDOWS_ZH = "回覆自 8.8.8.8: 位元組=32 時間=21ms TTL=117"
LINUX_REPLY = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=16.8 ms"


@pytest.mark.parametrize(
    "output, rtt",
    [
        (WINDOWS_REPLY, 17.0),
        (WINDOWS_LAN, 1.0),
        (WINDOWS_ZH, 21.0),
        (LINUX_REPLY, 16.8),
        (WINDOWS_TIMEOUT, None),
        (WINDOWS_UNREACHABLE, None),
    ],
)
def test_parse_ping(output, rtt):
    assert parse_ping(output) == rtt


def test_parse_gateway():
    route_print = """
IPv4 Route Table
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0         10.0.0.1      10.0.0.23     35
"""
    assert parse_gateway(route_print) == "10.0.0.1"
    assert parse_gateway("default via 192.168.1.1 dev wlan0 proto dhcp") == "192.168.1.1"
    assert parse_gateway("no route") is None


def test_stats():
    s = Stats("x", sent=5, rtts=[10, 20, 10, 40])
    assert s.loss_pct == 20.0
    assert s.avg_ms == 20.0
    assert s.p95_ms == 40
    assert s.jitter_ms == pytest.approx((10 + 10 + 30) / 3)
    assert Stats("y", sent=3).loss_pct == 100.0 and Stats("y", sent=3).jitter_ms is None


def layer(name, *stats):
    return LayerResult(name, list(stats))


GOOD = Stats("t", 10, [10.0] * 10)
DEAD = Stats("t", 10, [])
LOSSY = Stats("t", 10, [10.0] * 8)
SLOW = Stats("t", 10, [10.0] * 9 + [400.0])


def test_layer_status():
    assert layer("x", GOOD).status == "ok"
    assert layer("x", DEAD).status == "down"
    assert layer("x", GOOD, DEAD).status == "degraded"  # one of two targets gone
    assert layer("x", LOSSY).status == "degraded"
    assert layer("x", SLOW).status == "degraded"
    assert layer("x").status == "down"  # e.g. no default gateway at all


def test_diagnose_blames_the_lowest_failing_layer():
    ok = [layer(n, GOOD) for n in ("gateway", "internet", "dns", "service")]
    assert diagnose(ok) == ("ok", None)
    # The ISP is down: DNS and services fail too, but they are not the cause.
    isp_down = [layer("gateway", GOOD), layer("internet", DEAD), layer("dns", DEAD), layer("service", DEAD)]
    assert diagnose(isp_down) == ("down", "internet")
    dns_only = [layer("gateway", GOOD), layer("internet", GOOD), layer("dns", DEAD), layer("service", DEAD)]
    assert diagnose(dns_only) == ("down", "dns")
    wifi = [layer("gateway", LOSSY), layer("internet", LOSSY), layer("dns", GOOD), layer("service", GOOD)]
    assert diagnose(wifi) == ("degraded", "gateway")


def test_alerts_only_on_change():
    assert alert_text(None, ("ok", None)) is None
    assert alert_text(("ok", None), ("ok", None)) is None
    assert alert_text(("ok", None), ("down", "internet")).startswith("ALERT: internet down")
    assert alert_text(("down", "internet"), ("down", "internet")) is None
    assert alert_text(("down", "internet"), ("ok", None)).startswith("RECOVERED")


def test_history_round_trip(tmp_path):
    with sqlite3.connect(tmp_path / "p.sqlite") as db:
        assert previous_verdict(db) is None
        save(db, "2026-10-07T00:00:00+00:00", [layer("internet", LOSSY)], ("degraded", "internet"))
        assert previous_verdict(db) == ("degraded", "internet")
        row = db.execute("select layer, target, loss_pct, status from probe").fetchone()
        assert row == ("internet", "t", 20.0, "degraded")

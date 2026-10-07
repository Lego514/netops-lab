"""Load and validate the site inventory (inventory/site.yaml).

Validation happens here, once, so every later stage can trust the model: a typo
in a segment name or a policy rule pointing at a segment that doesn't exist is
an error with a clear message, not a silently missing firewall rule.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

import yaml


class InventoryError(ValueError):
    """The inventory file is wrong. The message says how."""


@dataclass(frozen=True)
class Segment:
    name: str
    vlan: int
    hosts: int  # hosts that need an address, not counting the gateway
    router: str


@dataclass(frozen=True)
class Rule:
    src: str  # segment name
    dst: str  # segment name, or "any"
    proto: str  # "tcp", "udp" or "any"
    ports: tuple[int, ...] = ()  # empty means every port


@dataclass(frozen=True)
class Site:
    name: str
    asn: int
    supernet: ipaddress.IPv4Network
    loopbacks: ipaddress.IPv4Network
    p2p: ipaddress.IPv4Network
    isp_name: str
    isp_asn: int
    isp_link: ipaddress.IPv4Network
    internet: ipaddress.IPv4Network
    routers: tuple[str, ...]
    edge_router: str
    links: tuple[tuple[str, str], ...]
    segments: tuple[Segment, ...]
    rules: tuple[Rule, ...]
    internet_allowed: frozenset[str] = field(default_factory=frozenset)

    def segment(self, name: str) -> Segment:
        for s in self.segments:
            if s.name == name:
                return s
        raise KeyError(name)


def _net(value: object, what: str) -> ipaddress.IPv4Network:
    try:
        return ipaddress.IPv4Network(str(value))
    except ValueError as e:
        raise InventoryError(f"{what}: {e}") from None


def parse(data: dict) -> Site:
    """Build a validated Site from the parsed YAML."""
    try:
        site, isp, policy = data["site"], data["isp"], data["policy"]
        routers = tuple(data["routers"])
        segments = tuple(
            Segment(s["name"], int(s["vlan"]), int(s["hosts"]), s["router"]) for s in data["segments"]
        )
        links = tuple((a, b) for a, b in data["links"])
        rules = tuple(
            Rule(
                r["from"],
                r["to"],
                r.get("proto", "any"),
                tuple(sorted(int(p) for p in r.get("ports", []))),
            )
            for r in policy.get("allow", [])
        )
        result = Site(
            name=site["name"],
            asn=int(site["asn"]),
            supernet=_net(site["supernet"], "site.supernet"),
            loopbacks=_net(site["loopbacks"], "site.loopbacks"),
            p2p=_net(site["p2p"], "site.p2p"),
            isp_name=isp["name"],
            isp_asn=int(isp["asn"]),
            isp_link=_net(isp["link"], "isp.link"),
            internet=_net(isp["internet"], "isp.internet"),
            routers=routers,
            edge_router=data["edge_router"],
            links=links,
            segments=segments,
            rules=rules,
            internet_allowed=frozenset(policy.get("internet", [])),
        )
    except KeyError as e:
        raise InventoryError(f"missing key {e}") from None
    _validate(result)
    return result


def _validate(s: Site) -> None:
    routers = set(s.routers)
    seg_names = [x.name for x in s.segments]
    if len(set(seg_names)) != len(seg_names):
        raise InventoryError("segment names must be unique")
    vlans = [x.vlan for x in s.segments]
    if len(set(vlans)) != len(vlans):
        raise InventoryError("VLAN IDs must be unique")
    for v in vlans:
        if not 1 <= v <= 4094:
            raise InventoryError(f"VLAN {v} is outside 1-4094")
    if s.edge_router not in routers:
        raise InventoryError(f"edge_router {s.edge_router!r} is not in routers")
    for a, b in s.links:
        if a not in routers or b not in routers or a == b:
            raise InventoryError(f"link {a}-{b} must join two different known routers")
    if len({frozenset(link) for link in s.links}) != len(s.links):
        raise InventoryError("duplicate link")
    for seg in s.segments:
        if seg.router not in routers:
            raise InventoryError(f"segment {seg.name}: unknown router {seg.router!r}")
        if seg.hosts < 1:
            raise InventoryError(f"segment {seg.name}: hosts must be at least 1")
    for pool, label in ((s.loopbacks, "loopbacks"), (s.p2p, "p2p")):
        if not pool.subnet_of(s.supernet):
            raise InventoryError(f"site.{label} must sit inside site.supernet")
    if s.loopbacks.overlaps(s.p2p):
        raise InventoryError("site.loopbacks and site.p2p overlap")
    known = set(seg_names)
    for r in s.rules:
        if r.src not in known:
            raise InventoryError(f"policy rule from unknown segment {r.src!r}")
        if r.dst != "any" and r.dst not in known:
            raise InventoryError(f"policy rule to unknown segment {r.dst!r}")
        if r.proto not in ("tcp", "udp", "any"):
            raise InventoryError(f"policy rule proto must be tcp, udp or any, not {r.proto!r}")
        if r.proto == "any" and r.ports:
            raise InventoryError("a rule with proto any cannot list ports")
        for p in r.ports:
            if not 1 <= p <= 65535:
                raise InventoryError(f"port {p} is outside 1-65535")
    for name in s.internet_allowed:
        if name not in known:
            raise InventoryError(f"policy.internet names unknown segment {name!r}")


def load(path: str | Path) -> Site:
    with open(path, encoding="utf-8") as f:
        return parse(yaml.safe_load(f))

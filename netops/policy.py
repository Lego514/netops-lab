"""Segmentation policy: what the inventory intends, and the firewall that enforces it.

There are two independent answers to "is this flow allowed?":

- `intended()` reads the policy straight from the inventory.
- `compile_policy()` turns the policy into ordered firewall rules per router,
  and `simulate()` walks a flow through those rules the way nftables would.

The tests check that both answers agree for every pair of segments and every
port that matters. A rule rendered in the wrong order, or a missing rule, shows
up as a disagreement before anything is deployed. The live lab then checks the
same flows on real packets.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .interfaces import Interface, isp_interface, segment_interface
from .ipam import Net, Plan
from .model import Site

INTERNET = "internet"


@dataclass(frozen=True)
class Flow:
    src: str  # segment name, or "internet"
    dst: str  # segment name, or "internet"
    proto: str  # "tcp", "udp" or "icmp"
    port: int | None = None


def intended(site: Site, flow: Flow) -> bool:
    """Is this new connection allowed, according to the inventory?"""
    if flow.src == flow.dst:
        return True  # same segment: never crosses a router
    if flow.dst == INTERNET:
        return flow.src in site.internet_allowed
    if flow.src == INTERNET:
        return False  # nothing on the internet may open a connection inward
    for r in site.rules:
        if r.src != flow.src or r.dst not in (flow.dst, "any"):
            continue
        if r.proto == "any":
            return True
        if r.proto == flow.proto and (not r.ports or flow.port in r.ports):
            return True
    return False


# ---------------------------------------------------------------------------
# Compiled rules.


@dataclass(frozen=True)
class FwRule:
    action: str  # "accept" or "drop"
    saddr: Net | None = None  # None matches any source
    proto: str | None = None  # None matches any protocol
    dports: tuple[int, ...] = ()  # empty matches any port
    comment: str = ""

    def matches(self, src_ip: ipaddress.IPv4Address, proto: str, port: int | None) -> bool:
        if self.saddr is not None and src_ip not in self.saddr:
            return False
        if self.proto is not None and self.proto != proto:
            return False
        if self.dports and port not in self.dports:
            return False
        return True


@dataclass(frozen=True)
class Chain:
    name: str  # e.g. "to_office"
    oif: str  # interface whose outbound traffic jumps here
    rules: tuple[FwRule, ...]


def compile_policy(site: Site, plan: Plan, ifaces: dict[str, list[Interface]]) -> dict[str, list[Chain]]:
    """Firewall chains per router. Each segment is guarded on its own gateway,
    on traffic leaving the router toward it; internet egress is guarded on the edge."""
    chains: dict[str, list[Chain]] = {r: [] for r in site.routers}

    for seg in plan.segments:
        rules: list[FwRule] = []
        for r in site.rules:
            if r.dst not in (seg.name, "any") or r.src == seg.name:
                continue
            src_net = plan.segment(r.src).network
            proto = None if r.proto == "any" else r.proto
            rules.append(FwRule("accept", src_net, proto, r.ports, f"{r.src} -> {r.dst}"))
        rules.append(FwRule("drop", comment=f"everything else to {seg.name}"))
        oif = segment_interface(ifaces, seg.router, seg.name).name
        chains[seg.router].append(Chain(f"to_{seg.name}", oif, tuple(rules)))

    egress: list[FwRule] = [
        FwRule("drop", plan.segment(name).network, comment=f"{name} may not reach the internet")
        for name in (s.name for s in site.segments)
        if name not in site.internet_allowed
    ]
    egress.append(FwRule("accept", site.supernet, comment="site to internet"))
    egress.append(FwRule("drop", comment="anything else"))
    oif = isp_interface(ifaces, site.edge_router).name
    chains[site.edge_router].append(Chain(f"to_{INTERNET}", oif, tuple(egress)))
    return chains


def simulate(site: Site, plan: Plan, chains: dict[str, list[Chain]], flow: Flow) -> bool:
    """Walk a new connection through the compiled chains, first match wins."""
    if flow.src == flow.dst:
        return True
    src_ip = (
        plan.segment(flow.src).first_host if flow.src != INTERNET else site.internet.network_address
    )
    if flow.dst == INTERNET:
        chain = _chain(chains[site.edge_router], f"to_{INTERNET}")
    else:
        seg = plan.segment(flow.dst)
        chain = _chain(chains[seg.router], f"to_{seg.name}")
    for rule in chain.rules:
        if rule.matches(src_ip, flow.proto, flow.port):
            return rule.action == "accept"
    return True  # the base chain's policy is accept: unmatched traffic passes


def _chain(chains: list[Chain], name: str) -> Chain:
    for c in chains:
        if c.name == name:
            return c
    raise KeyError(name)


def flows_to_check(site: Site) -> list[Flow]:
    """Every pair of endpoints, on every port the policy mentions plus one it doesn't."""
    ports = sorted({p for r in site.rules for p in r.ports} | {8080})
    endpoints = [s.name for s in site.segments] + [INTERNET]
    flows: list[Flow] = []
    for src in endpoints:
        for dst in endpoints:
            if src == dst:
                continue
            flows.append(Flow(src, dst, "icmp"))
            flows.extend(Flow(src, dst, "tcp", p) for p in ports)
    return flows

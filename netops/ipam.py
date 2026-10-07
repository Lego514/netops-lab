"""IP address management: turn the inventory into concrete addresses.

Deterministic on purpose: the same inventory always yields the same plan, so
re-running the build is safe (idempotent) and a diff of the generated configs
shows exactly what a change to site.yaml does.
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass

from .model import InventoryError, Site

Net = ipaddress.IPv4Network
Addr = ipaddress.IPv4Address


@dataclass(frozen=True)
class SegmentPlan:
    name: str
    vlan: int
    router: str
    network: Net
    gateway: Addr  # first usable address, configured on the router
    hosts: int  # how many hosts were asked for

    @property
    def usable(self) -> int:
        return self.network.num_addresses - 2  # minus network and broadcast

    @property
    def first_host(self) -> Addr:
        return self.network.network_address + 2  # +1 is the gateway

    @property
    def last_host(self) -> Addr:
        return self.network.broadcast_address - 1


@dataclass(frozen=True)
class LinkPlan:
    a: str
    b: str
    network: Net  # a /31: two addresses, no network or broadcast (RFC 3021)
    a_ip: Addr
    b_ip: Addr


@dataclass(frozen=True)
class Plan:
    segments: tuple[SegmentPlan, ...]
    links: tuple[LinkPlan, ...]
    loopbacks: dict[str, Addr]
    isp_link: LinkPlan  # a = edge router, b = ISP

    def segment(self, name: str) -> SegmentPlan:
        for s in self.segments:
            if s.name == name:
                return s
        raise KeyError(name)


def prefix_for(hosts: int) -> int:
    """Smallest prefix with room for `hosts` plus a gateway, network and broadcast."""
    needed = hosts + 3
    return 32 - math.ceil(math.log2(needed))


def allocate(site: Site) -> Plan:
    reserved = [site.loopbacks, site.p2p]
    taken: list[Net] = []

    # Largest first: allocating big blocks before small ones keeps every block
    # aligned without leaving gaps that nothing can use.
    by_size = sorted(site.segments, key=lambda s: (-s.hosts, s.name))
    placed: dict[str, SegmentPlan] = {}
    for seg in by_size:
        prefix = prefix_for(seg.hosts)
        if prefix < site.supernet.prefixlen:
            raise InventoryError(f"no room for segment {seg.name} (/{prefix}) in {site.supernet}")
        net = _first_free(site.supernet, prefix, reserved + taken)
        if net is None:
            raise InventoryError(f"no room for segment {seg.name} (/{prefix}) in {site.supernet}")
        taken.append(net)
        placed[seg.name] = SegmentPlan(
            seg.name, seg.vlan, seg.router, net, net.network_address + 1, seg.hosts
        )

    p2p_blocks = list(site.p2p.subnets(new_prefix=31))
    if len(p2p_blocks) < len(site.links):
        raise InventoryError(f"site.p2p has room for {len(p2p_blocks)} links, need {len(site.links)}")
    links = tuple(
        LinkPlan(a, b, net, net.network_address, net.network_address + 1)
        for (a, b), net in zip(site.links, p2p_blocks)
    )

    lo_hosts = list(site.loopbacks.hosts())
    loopbacks = {r: lo_hosts[i] for i, r in enumerate(site.routers)}

    isp = site.isp_link
    if isp.prefixlen != 31:
        raise InventoryError("isp.link must be a /31")
    isp_link = LinkPlan(site.edge_router, site.isp_name, isp, isp.network_address + 1, isp.network_address)

    # Keep the inventory's order in the plan, not the allocation order.
    ordered = tuple(placed[s.name] for s in site.segments)
    return Plan(ordered, links, loopbacks, isp_link)


def _first_free(supernet: Net, prefix: int, used: list[Net]) -> Net | None:
    for candidate in supernet.subnets(new_prefix=prefix):
        if not any(candidate.overlaps(u) for u in used):
            return candidate
    return None

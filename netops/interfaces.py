"""Which interface on which device connects to what.

Containerlab gives every container eth0 for management and wires the data plane
as eth1, eth2, ... in the order the topology lists the links. This module is the
single place that decides that order, so the router configs, the firewall rules
and the topology file can never disagree about which interface is which.
"""

from __future__ import annotations

from dataclasses import dataclass

from .ipam import Addr, Net, Plan
from .model import Site


@dataclass(frozen=True)
class Interface:
    device: str
    name: str  # eth1, eth2, ...
    address: Addr
    network: Net
    peer: str  # device on the other end
    kind: str  # "p2p", "isp" or "segment"
    segment: str | None = None


def host_name(segment: str) -> str:
    return f"h-{segment.replace('_', '-')}"


def assign(site: Site, plan: Plan) -> dict[str, list[Interface]]:
    """Interfaces per device: routers, the ISP router and one test host per segment."""
    out: dict[str, list[Interface]] = {r: [] for r in (*site.routers, site.isp_name)}

    def add(device: str, **kw) -> None:
        out.setdefault(device, [])
        out[device].append(Interface(device=device, name=f"eth{len(out[device]) + 1}", **kw))

    for link in plan.links:
        add(link.a, address=link.a_ip, network=link.network, peer=link.b, kind="p2p")
        add(link.b, address=link.b_ip, network=link.network, peer=link.a, kind="p2p")

    isp = plan.isp_link
    add(isp.a, address=isp.a_ip, network=isp.network, peer=isp.b, kind="isp")
    add(isp.b, address=isp.b_ip, network=isp.network, peer=isp.a, kind="isp")

    for seg in plan.segments:
        host = host_name(seg.name)
        add(seg.router, address=seg.gateway, network=seg.network, peer=host, kind="segment", segment=seg.name)
        add(host, address=seg.first_host, network=seg.network, peer=seg.router, kind="segment", segment=seg.name)
    return out


def segment_interface(ifaces: dict[str, list[Interface]], router: str, segment: str) -> Interface:
    for i in ifaces[router]:
        if i.kind == "segment" and i.segment == segment:
            return i
    raise KeyError((router, segment))


def isp_interface(ifaces: dict[str, list[Interface]], router: str) -> Interface:
    for i in ifaces[router]:
        if i.kind == "isp":
            return i
    raise KeyError(router)

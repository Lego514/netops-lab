"""Render device configs and the lab topology from the inventory.

Configs come from Jinja2 templates (netops/templates/), the same templating
Ansible uses: data in YAML, structure in a template, and the code in between only
decides which data goes where.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .interfaces import Interface, assign, host_name
from .ipam import Plan, allocate
from .model import Site
from .policy import Chain, FwRule, compile_policy

TEMPLATES = Path(__file__).parent / "templates"
FRR_IMAGE = "frrouting/frr:v8.4.1"
HOST_IMAGE = "nicolaka/netshoot:v0.13"
DAEMONS = """# Generated. Which FRR daemons run on this node.
zebra=yes
bgpd=yes
ospfd=yes
staticd=yes
vtysh_enable=yes
zebra_options="  -A 127.0.0.1 -s 90000000"
bgpd_options="   -A 127.0.0.1"
ospfd_options="  -A 127.0.0.1"
staticd_options="-A 127.0.0.1"
"""


VTYSH = "service integrated-vtysh-config\n"


def nft_rule(r: FwRule) -> str:
    """One FwRule as an nftables rule line."""
    parts: list[str] = []
    if r.saddr is not None:
        parts.append(f"ip saddr {r.saddr}")
    if r.proto is not None:
        if r.dports:
            ports = ", ".join(str(p) for p in r.dports)
            parts.append(f"{r.proto} dport {{ {ports} }}")
        else:
            parts.append(f"meta l4proto {r.proto}")
    parts.append("counter")
    parts.append(r.action)
    line = " ".join(parts)
    return f'{line} comment "{r.comment}"' if r.comment else line


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATES),
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=StrictUndefined,
        keep_trailing_newline=True,
    )
    env.filters["nft"] = nft_rule
    return env


@dataclass(frozen=True)
class IfaceView:
    name: str
    address: object
    network: object
    kind: str
    description: str


def _describe(i: Interface, site: Site) -> str:
    if i.kind == "segment":
        seg = site.segment(i.segment)  # type: ignore[arg-type]
        return f"{seg.name} segment, VLAN {seg.vlan}"
    if i.kind == "isp":
        return f"to {i.peer} (eBGP)"
    return f"to {i.peer} (OSPF area 0)"


def router_config(site: Site, plan: Plan, ifaces: dict[str, list[Interface]], router: str) -> str:
    views = [IfaceView(i.name, i.address, i.network, i.kind, _describe(i, site)) for i in ifaces[router]]
    loopback = plan.loopbacks[router]
    networks = [f"{loopback}/32"] + [str(i.network) for i in ifaces[router] if i.kind in ("p2p", "segment")]
    bgp = None
    if router == site.edge_router:
        isp = plan.isp_link
        bgp = {
            "asn": site.asn,
            "router_id": loopback,
            "neighbor_ip": isp.b_ip,
            "neighbor_asn": site.isp_asn,
            "neighbor_name": site.isp_name,
            "networks": [str(site.supernet)],
            # BGP only announces prefixes that are in the routing table. The
            # blackhole route puts the site summary there; the more specific
            # OSPF routes still win for real traffic.
            "static_blackholes": [str(site.supernet)],
        }
    return _env().get_template("frr.conf.j2").render(
        name=router,
        lo_address=f"{loopback}/32",
        router_id=loopback,
        interfaces=views,
        ospf={"networks": networks, "originate_default": router == site.edge_router},
        bgp=bgp,
    )


def isp_config(site: Site, plan: Plan, ifaces: dict[str, list[Interface]]) -> str:
    """The lab's stand-in ISP: one eBGP session, announcing the 'internet' prefix."""
    views = [IfaceView(i.name, i.address, i.network, i.kind, _describe(i, site)) for i in ifaces[site.isp_name]]
    isp = plan.isp_link
    return _env().get_template("frr.conf.j2").render(
        name=site.isp_name,
        lo_address=str(site.internet),
        router_id=site.internet.network_address,
        interfaces=views,
        ospf=None,
        bgp={
            "asn": site.isp_asn,
            "router_id": site.internet.network_address,
            "neighbor_ip": isp.a_ip,
            "neighbor_asn": site.asn,
            "neighbor_name": site.edge_router,
            "networks": [str(site.internet)],
            "static_blackholes": [],
        },
    )


def firewall_config(router: str, chains: list[Chain], has_internet: bool) -> str:
    return _env().get_template("segpolicy.nft.j2").render(router=router, chains=chains, has_internet=has_internet)


def topology(site: Site, plan: Plan, ifaces: dict[str, list[Interface]]) -> dict:
    """Containerlab topology. Paths are relative to the output directory."""
    nodes: dict[str, dict] = {}
    for r in (*site.routers, site.isp_name):
        binds = [
            f"{r}/daemons:/etc/frr/daemons",
            f"{r}/frr.conf:/etc/frr/frr.conf",
            f"{r}/vtysh.conf:/etc/frr/vtysh.conf",
        ]
        node: dict = {"kind": "linux", "image": FRR_IMAGE, "binds": binds}
        if r in site.routers:
            binds.append(f"{r}/segpolicy.nft:/etc/nftables/segpolicy.nft")
        nodes[r] = node

    listen_ports = sorted({p for rule in site.rules for p in rule.ports} | {8080})
    for seg in plan.segments:
        name = host_name(seg.name)
        listeners = " & ".join(
            f"socat TCP-LISTEN:{p},fork,reuseaddr SYSTEM:true" for p in listen_ports
        )
        nodes[name] = {
            "kind": "linux",
            "image": HOST_IMAGE,
            "exec": [
                f"ip addr add {seg.first_host}/{seg.network.prefixlen} dev eth1",
                f"ip route replace default via {seg.gateway}",
                f"sh -c '({listeners}) > /dev/null 2>&1 &'",
            ],
        }

    links = []
    seen: set[tuple[str, str]] = set()
    for device, items in ifaces.items():
        for i in items:
            peer_iface = next(p for p in ifaces[i.peer] if p.peer == device and p.network == i.network)
            key = tuple(sorted([f"{device}:{i.name}", f"{i.peer}:{peer_iface.name}"]))
            if key in seen:
                continue
            seen.add(key)  # type: ignore[arg-type]
            links.append({"endpoints": list(key)})
    return {"name": "netops", "topology": {"nodes": nodes, "links": links}}


def build(site: Site, out: Path) -> dict[str, str]:
    """Write every generated file under `out`. Returns {relative path: content}."""
    plan = allocate(site)
    ifaces = assign(site, plan)
    chains = compile_policy(site, plan, ifaces)
    files: dict[str, str] = {}
    for r in site.routers:
        files[f"{r}/frr.conf"] = router_config(site, plan, ifaces, r)
        files[f"{r}/daemons"] = DAEMONS
        files[f"{r}/vtysh.conf"] = VTYSH
        files[f"{r}/segpolicy.nft"] = firewall_config(r, chains[r], r == site.edge_router)
    files[f"{site.isp_name}/frr.conf"] = isp_config(site, plan, ifaces)
    files[f"{site.isp_name}/daemons"] = DAEMONS
    files[f"{site.isp_name}/vtysh.conf"] = VTYSH
    files["netops.clab.yml"] = yaml.safe_dump(topology(site, plan, ifaces), sort_keys=False)
    for rel, content in files.items():
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        # newline="\n": the configs are read inside Linux containers.
        path.write_text(content, encoding="utf-8", newline="\n")
    return files

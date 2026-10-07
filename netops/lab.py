"""Verify the deployed Containerlab network on real packets.

Run after `containerlab deploy -t out/netops.clab.yml` (CI does both):

    python -m netops lab

1. Load each router's firewall rules (nftables).
2. Wait for routing to converge: every OSPF adjacency Full, the eBGP session
   Established.
3. Open every test flow for real (TCP connects, pings) and compare the result
   with the policy. A flow that should be blocked but connects is a failure, and
   so is one that should connect but is blocked.
4. Failover drill: cut the core1-edge link, time how long the office loses the
   internet, check traffic now goes through core2, then restore the link.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from .interfaces import Interface, assign, host_name
from .ipam import allocate
from .model import Site
from .policy import INTERNET, Flow, flows_to_check, intended

LAB = "netops"


def node(name: str) -> str:
    return f"clab-{LAB}-{name}"


def sh(name: str, command: str, timeout: float = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", node(name), "sh", "-c", command],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def vtysh_json(router: str, command: str) -> dict:
    out = sh(router, f'vtysh -c "{command} json"').stdout
    try:
        return json.loads(out or "{}")
    except json.JSONDecodeError:
        return {}


# ---------------------------------------------------------------------------
# Setup and convergence.


def load_firewalls(site: Site) -> None:
    for r in site.routers:
        res = sh(r, "apk add --no-cache nftables > /dev/null && nft -f /etc/nftables/segpolicy.nft", timeout=120)
        if res.returncode != 0:
            raise SystemExit(f"{r}: loading nftables failed:\n{res.stderr}")
    print(f"firewall loaded on {', '.join(site.routers)}")


def full_neighbors(router: str) -> int:
    data = vtysh_json(router, "show ip ospf neighbor")
    count = 0
    for entries in data.get("neighbors", {}).values():
        for e in entries:
            state = str(e.get("state") or e.get("nbrState") or "")
            if state.startswith("Full"):
                count += 1
    return count


def bgp_established(router: str) -> bool:
    peers = vtysh_json(router, "show bgp summary").get("ipv4Unicast", {}).get("peers", {})
    return bool(peers) and all(p.get("state") == "Established" for p in peers.values())


def wait_converged(site: Site, timeout_s: float = 120) -> float:
    degree = {r: sum(r in link for link in site.links) for r in site.routers}
    start = time.monotonic()
    while time.monotonic() - start < timeout_s:
        ospf_ok = all(full_neighbors(r) == degree[r] for r in site.routers)
        if ospf_ok and bgp_established(site.edge_router):
            return time.monotonic() - start
        time.sleep(2)
    detail = {r: f"{full_neighbors(r)}/{degree[r]} OSPF Full" for r in site.routers}
    raise SystemExit(f"routing did not converge in {timeout_s:.0f}s: {detail}, BGP up: {bgp_established(site.edge_router)}")


# ---------------------------------------------------------------------------
# Reachability.


@dataclass
class Result:
    flow: Flow
    want: bool
    got: bool | None  # None: not testable in the lab (no listener on the internet side)

    @property
    def ok(self) -> bool:
        return self.got is None or self.got == self.want


def try_flow(site: Site, flow: Flow, addresses: dict[str, str]) -> bool | None:
    internet_ip = str(site.internet.network_address)
    if flow.src == INTERNET:
        if flow.proto != "icmp":
            return None
        cmd = f"ping -c 2 -W 1 -I {internet_ip} {addresses[flow.dst]}"
        return sh(site.isp_name, cmd).returncode == 0
    src = host_name(flow.src)
    if flow.dst == INTERNET:
        if flow.proto != "icmp":
            return None
        return sh(src, f"ping -c 2 -W 1 {internet_ip}").returncode == 0
    dst_ip = addresses[flow.dst]
    if flow.proto == "icmp":
        return sh(src, f"ping -c 2 -W 1 {dst_ip}").returncode == 0
    return sh(src, f"nc -z -w 2 {dst_ip} {flow.port}").returncode == 0


def reachability(site: Site) -> list[Result]:
    plan = allocate(site)
    addresses = {s.name: str(s.first_host) for s in plan.segments}
    flows = flows_to_check(site)
    with ThreadPoolExecutor(max_workers=12) as pool:
        got = list(pool.map(lambda f: try_flow(site, f, addresses), flows))
    return [Result(f, intended(site, f), g) for f, g in zip(flows, got)]


# ---------------------------------------------------------------------------
# Failover drill.


def iface_toward(ifaces: dict[str, list[Interface]], device: str, peer: str) -> Interface:
    return next(i for i in ifaces[device] if i.peer == peer and i.kind == "p2p")


def failover_drill(site: Site) -> dict:
    """Cut core1-edge and time the office's internet outage."""
    plan = allocate(site)
    ifaces = assign(site, plan)
    office_router = plan.segment("office").router
    cut = iface_toward(ifaces, office_router, site.edge_router)
    target = str(site.internet.network_address)
    office = host_name("office")

    before = sh(office, f"traceroute -n -w 1 -q 1 -m 6 {target}").stdout
    sh(office_router, f"ip link set {cut.name} down")
    start = time.monotonic()
    outage = None
    while time.monotonic() - start < 60:
        if sh(office, f"ping -c 1 -W 1 {target}").returncode == 0:
            outage = time.monotonic() - start
            break
    after = sh(office, f"traceroute -n -w 1 -q 1 -m 6 {target}").stdout
    sh(office_router, f"ip link set {cut.name} up")
    wait_converged(site)
    other_core = next(r for r in site.routers if r not in (office_router, site.edge_router))
    via = str(plan.loopbacks[other_core])
    p2p_other = {str(i.address) for i in ifaces[other_core]}
    return {
        "cut": f"{office_router} {cut.name} (to {site.edge_router})",
        "outage_s": outage,
        "rerouted_via_other_core": any(ip in after for ip in p2p_other | {via}),
        "path_before": before.strip(),
        "path_after": after.strip(),
    }


# ---------------------------------------------------------------------------


def report(results: list[Result], converged_s: float, drill: dict) -> str:
    tested = [r for r in results if r.got is not None]
    bad = [r for r in tested if not r.ok]
    lines = [
        "## Lab verification",
        "",
        f"- Routing converged in **{converged_s:.1f} s** (all OSPF adjacencies Full, eBGP Established).",
        f"- Flows tested on real packets: **{len(tested)}**; matching the policy: **{len(tested) - len(bad)}**.",
        f"- Failover drill: cut {drill['cut']}. Office lost the internet for "
        + (f"**{drill['outage_s']:.1f} s**" if drill["outage_s"] is not None else "**over 60 s (FAILED)**")
        + f", rerouted through the other core: **{drill['rerouted_via_other_core']}**. The link was then restored.",
        "",
        "| From | To | Proto | Port | Policy | Lab | |",
        "|---|---|---|---:|---|---|---|",
    ]
    for r in tested:
        mark = "ok" if r.ok else "**MISMATCH**"
        lines.append(
            f"| {r.flow.src} | {r.flow.dst} | {r.flow.proto} | {r.flow.port or ''} | "
            f"{'allow' if r.want else 'deny'} | {'open' if r.got else 'blocked'} | {mark} |"
        )
    lines += ["", "Path before the cut:", "```", drill["path_before"], "```", "Path after:", "```", drill["path_after"], "```"]
    return "\n".join(lines) + "\n"


def drop_management_default(site: Site) -> None:
    """Remove the default route Docker gives every container on its management port.

    Each container has eth0 on Containerlab's management network, with a kernel
    default route through it. A kernel route has administrative distance 0, so it
    beats the OSPF default (110) that the edge originates, and the cores would send
    internet-bound traffic out the management port instead of to the edge. Real
    networks avoid this with a separate management VRF; the lab simply removes it,
    after the package install that still needs it.
    """
    for r in site.routers:
        sh(r, "ip route del default dev eth0 2> /dev/null || true")
    print(f"management default route removed on {', '.join(site.routers)}")


def run(site: Site) -> int:
    for r in site.routers:
        sh(r, "sysctl -w net.ipv4.ip_forward=1 > /dev/null")
    load_firewalls(site)
    drop_management_default(site)
    converged = wait_converged(site)
    print(f"converged in {converged:.1f}s")
    results = reachability(site)
    drill = failover_drill(site)
    text = report(results, converged, drill)
    print(text)
    Path("lab-report.md").write_text(text, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(text)
    failed = [r for r in results if not r.ok]
    drill_ok = drill["outage_s"] is not None and drill["rerouted_via_other_core"]
    if failed or not drill_ok:
        print(f"FAILED: {len(failed)} flow mismatches, drill ok: {drill_ok}", file=sys.stderr)
        return 1
    return 0

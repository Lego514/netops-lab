# NetOps Lab

A small factory network, defined in one YAML file and built, checked and tested by code.

The site has an office, servers, a production (OT) network for fab equipment, and a
management network, behind one edge router that peers with an ISP over BGP. Production
equipment must never reach the internet, and the office may only see a read-only dashboard
on the production side. Those rules live in [`inventory/site.yaml`](inventory/site.yaml),
next to the segments and links. Everything else is generated:

```
inventory/site.yaml  ──►  IP plan (subnets, gateways, /31 links, loopbacks)
                     ──►  FRRouting configs: OSPF inside, eBGP to the ISP   out/<router>/frr.conf
                     ──►  nftables segmentation rules per router            out/<router>/segpolicy.nft
                     ──►  Containerlab topology                             out/netops.clab.yml
                     ──►  IP plan and policy matrix                         docs/ip-plan.md
```

Two more tools sit next to it: `netops check`, which proves the compiled firewall matches
the policy before anything is deployed, and `netops probe`, which measures a real network
layer by layer and says which layer is at fault.

## Topology

```
                     ISP (AS 65000, "internet" 198.51.100.1)
                      │  eBGP
                    edge (AS 65020)
                   ╱      ╲          OSPF area 0 on every link;
              core1 ─────── core2    the triangle survives any one cut
             ╱     ╲       ╱     ╲
        office  servers  fab_ot   mgmt
        VLAN 10 VLAN 30  VLAN 20  VLAN 99
```

The full plan, with every address and the policy matrix, is in [`docs/ip-plan.md`](docs/ip-plan.md).

## Commands

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m netops build     # generate out/ and docs/ from the inventory
python -m netops check     # compiled firewall vs policy, on every pair of segments
python -m netops probe     # measure this machine's network (add --watch 60 to repeat)
pytest                     # unit tests
python -m netops lab       # after `containerlab deploy` (Linux + Docker): verify on real packets
```

## How each part works

**IP address management** ([`netops/ipam.py`](netops/ipam.py)). Each segment gets the smallest
subnet that fits its hosts plus a gateway, network and broadcast address. Largest segments are
placed first so every block stays aligned. Router links get /31s (RFC 3021: two addresses, no
waste), routers get /32 loopbacks as OSPF and BGP router IDs. The same inventory always yields
the same plan, so re-running the build is idempotent and a diff of `out/` shows exactly what a
change to the YAML does.

**Routing** ([`netops/templates/frr.conf.j2`](netops/templates/frr.conf.j2)). OSPF area 0 on every
router link, point-to-point (no DR election on a /31). Segment interfaces are advertised but
passive, so no OSPF hellos leak to hosts. The edge router originates a default route into OSPF and
announces the site's /16 to the ISP over eBGP; a blackhole route for the /16 is what lets BGP announce
the summary while the more specific OSPF routes carry the traffic.

**Segmentation** ([`netops/policy.py`](netops/policy.py)). Each segment is guarded on its own gateway,
on traffic leaving the router toward it: allowed sources and ports are accepted, everything else is
dropped. Internet egress is guarded on the edge. The firewall is stateful, so return traffic of an
allowed connection always passes.

**Checking the firewall before deploying it.** `intended()` answers "is this flow allowed?" straight
from the YAML. `simulate()` answers the same question by walking the compiled rules first-match-wins,
the way nftables does. `netops check` runs both on every pair of segments and the internet, on every
port the policy mentions plus one it doesn't, and fails on any disagreement. A test reorders one rule
to prove the check catches it.

**Verifying the real network** ([`netops/lab.py`](netops/lab.py), CI job `lab`). GitHub Actions deploys
the topology with Containerlab (FRRouting routers, one Linux host per segment), loads the firewalls,
and waits until every OSPF adjacency is Full and the BGP session Established. Then it opens every test
flow for real (TCP connects with `nc`, pings) and compares each result with the policy, and runs a
failover drill: it cuts the core1–edge link, times how long the office loses the internet, checks that
traffic now flows through core2, and restores the link.

**Probing a real network** ([`netops/probe.py`](netops/probe.py)). Checks bottom-up: the default
gateway, public IPs, DNS, then TCP to real services, with loss, average, p95 and jitter for each. The
verdict is the lowest layer that is down or degraded, because a dead ISP also breaks DNS and every
website, and those aren't the cause. Results go into SQLite; an alert fires only when the verdict
changes, so a two-hour outage is one alert, not hundreds.

## What this is not

It runs FRRouting and nftables on Linux, not Cisco IOS, Fortinet or Palo Alto. The protocols
(OSPF, BGP) and the ideas (source of truth, generated configs, segmentation, pre-deployment checks)
carry over; the vendor syntax does not. VLAN IDs are part of the plan and the docs, but the lab wires
each segment to its own router interface instead of trunking 802.1Q tags.

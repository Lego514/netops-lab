from pathlib import Path

import pytest
import yaml

from netops.interfaces import assign
from netops.ipam import allocate
from netops.model import load, parse
from netops.policy import INTERNET, Flow, compile_policy, intended, simulate, flows_to_check
from netops.render import build, nft_rule

INVENTORY = Path(__file__).resolve().parent.parent / "inventory" / "site.yaml"


@pytest.fixture
def site():
    return load(INVENTORY)


def compiled(site):
    plan = allocate(site)
    return plan, compile_policy(site, plan, assign(site, plan))


# --- policy -------------------------------------------------------------------


@pytest.mark.parametrize(
    "flow, allowed",
    [
        (Flow("office", "servers", "tcp", 443), True),
        (Flow("office", "servers", "tcp", 5432), False),
        (Flow("office", "fab_ot", "tcp", 443), True),
        (Flow("office", "fab_ot", "tcp", 22), False),
        (Flow("fab_ot", "servers", "tcp", 5432), True),
        (Flow("fab_ot", "office", "tcp", 443), False),
        (Flow("servers", "office", "icmp"), False),
        (Flow("mgmt", "fab_ot", "tcp", 22), True),
        (Flow("office", "mgmt", "tcp", 22), False),
        (Flow("office", INTERNET, "tcp", 443), True),
        (Flow("fab_ot", INTERNET, "tcp", 443), False),
        (Flow(INTERNET, "servers", "tcp", 443), False),
    ],
)
def test_intent(site, flow, allowed):
    assert intended(site, flow) is allowed


def test_compiled_firewall_matches_the_policy_on_every_flow(site):
    plan, chains = compiled(site)
    flows = flows_to_check(site)
    assert len(flows) > 50
    mismatches = [f for f in flows if intended(site, f) != simulate(site, plan, chains, f)]
    assert mismatches == []


def test_the_simulator_catches_a_misordered_rule(site):
    """Prove the check above can fail: put the drop first and it must disagree."""
    plan, chains = compiled(site)
    chain = next(c for c in chains["core1"] if c.name == "to_servers")
    broken = chain.__class__(chain.name, chain.oif, (chain.rules[-1], *chain.rules[:-1]))
    chains["core1"] = [broken if c is chain else c for c in chains["core1"]]
    assert simulate(site, plan, chains, Flow("office", "servers", "tcp", 443)) is False
    assert intended(site, Flow("office", "servers", "tcp", 443)) is True


def test_every_chain_ends_in_drop(site):
    _, chains = compiled(site)
    for router_chains in chains.values():
        for c in router_chains:
            assert c.rules[-1].action == "drop" and c.rules[-1].saddr is None


# --- rendering ------------------------------------------------------------------


def test_nft_rule_text(site):
    plan, chains = compiled(site)
    rules = {r.comment: nft_rule(r) for c in chains["core1"] for r in c.rules}
    assert rules["office -> servers"] == (
        'ip saddr 10.20.0.0/25 tcp dport { 22, 443 } counter accept comment "office -> servers"'
    )
    assert rules["mgmt -> any"].startswith("ip saddr 10.20.0.224/28 counter accept")


def test_build_writes_consistent_configs(site, tmp_path):
    files = build(site, tmp_path)
    plan = allocate(site)

    edge = files["edge/frr.conf"]
    assert "router bgp 65020" in edge and "neighbor 203.0.113.0 remote-as 65000" in edge
    assert "network 10.20.0.0/16" in edge and "default-information originate always" in edge

    core1 = files["core1/frr.conf"]
    assert "router bgp" not in core1
    # Every OSPF network on core1 is one of its own subnets, and segments are passive.
    office = plan.segment("office")
    assert f"network {office.network} area 0" in core1
    assert "passive-interface eth3" in core1

    isp = files["isp/frr.conf"]
    assert "ip address 198.51.100.1/32" in isp and "network 198.51.100.1/32" in isp

    assert "fab_ot may not reach the internet" in files["edge/segpolicy.nft"]
    assert (tmp_path / "netops.clab.yml").exists()


def test_topology_wires_every_interface_exactly_once(site, tmp_path):
    files = build(site, tmp_path)
    topo = yaml.safe_load(files["netops.clab.yml"])
    endpoints = [e for link in topo["topology"]["links"] for e in link["endpoints"]]
    assert len(endpoints) == len(set(endpoints))
    ifaces = assign(site, allocate(site))
    assert len(endpoints) == sum(len(v) for v in ifaces.values())


def test_build_is_idempotent(site, tmp_path):
    assert build(site, tmp_path / "a") == build(site, tmp_path / "b")


def test_a_new_segment_flows_through_everything(site, tmp_path):
    """Add a segment in YAML only: subnet, gateway, OSPF, firewall and docs follow."""
    raw = yaml.safe_load(INVENTORY.read_text(encoding="utf-8"))
    raw["segments"].append({"name": "guest", "vlan": 40, "hosts": 25, "router": "core2"})
    raw["policy"]["internet"].append("guest")
    s = parse(raw)
    files = build(s, tmp_path)
    guest = allocate(s).segment("guest")
    assert f"network {guest.network} area 0" in files["core2/frr.conf"]
    assert "chain to_guest" in files["core2/segpolicy.nft"]
    assert intended(s, Flow("guest", "office", "tcp", 443)) is False

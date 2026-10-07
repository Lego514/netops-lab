import copy
import ipaddress
from pathlib import Path

import pytest
import yaml

from netops.interfaces import assign
from netops.ipam import allocate, prefix_for
from netops.model import InventoryError, load, parse

INVENTORY = Path(__file__).resolve().parent.parent / "inventory" / "site.yaml"


@pytest.fixture
def raw() -> dict:
    with open(INVENTORY, encoding="utf-8") as f:
        return yaml.safe_load(f)


@pytest.fixture
def site():
    return load(INVENTORY)


# --- validation -------------------------------------------------------------


def broken(raw: dict, mutate) -> dict:
    data = copy.deepcopy(raw)
    mutate(data)
    return data


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda d: d["segments"].append({**d["segments"][0]}), "names must be unique"),
        (lambda d: d["segments"][1].update(vlan=10), "VLAN IDs must be unique"),
        (lambda d: d["segments"][0].update(vlan=5000), "outside 1-4094"),
        (lambda d: d["segments"][0].update(router="core9"), "unknown router"),
        (lambda d: d["links"].append(["edge", "edge"]), "two different known routers"),
        (lambda d: d["links"].append(["core1", "edge"]), "duplicate link"),
        (lambda d: d["policy"]["allow"].append({"from": "ofice", "to": "servers"}), "unknown segment 'ofice'"),
        (lambda d: d["policy"]["allow"].append({"from": "office", "to": "mgmt", "proto": "any", "ports": [22]}),
         "cannot list ports"),
        (lambda d: d["policy"]["internet"].append("lab"), "unknown segment 'lab'"),
        (lambda d: d["site"].update(p2p="10.99.0.0/24"), "inside site.supernet"),
        (lambda d: d.pop("routers"), "missing key"),
    ],
)
def test_rejects_bad_inventory(raw, mutate, message):
    with pytest.raises(InventoryError, match=message):
        parse(broken(raw, mutate))


# --- IPAM ---------------------------------------------------------------------


@pytest.mark.parametrize("hosts, prefix", [(1, 30), (13, 28), (14, 27), (29, 27), (60, 26), (61, 26), (62, 25), (120, 25)])
def test_prefix_leaves_room_for_gateway_network_and_broadcast(hosts, prefix):
    assert prefix_for(hosts) == prefix
    assert 2 ** (32 - prefix) - 3 >= hosts


def test_every_segment_fits_and_nothing_overlaps(site):
    plan = allocate(site)
    nets = [s.network for s in plan.segments] + [site.loopbacks, site.p2p]
    for i, a in enumerate(nets):
        for b in nets[i + 1 :]:
            assert not a.overlaps(b), f"{a} overlaps {b}"
    for s in plan.segments:
        assert s.network.subnet_of(site.supernet)
        assert s.usable - 1 >= s.hosts  # one usable address is the gateway
        assert s.gateway == s.network.network_address + 1


def test_allocation_is_deterministic(site):
    assert allocate(site) == allocate(site)


def test_links_are_31s_from_the_p2p_pool(site):
    plan = allocate(site)
    for link in plan.links:
        assert link.network.prefixlen == 31 and link.network.subnet_of(site.p2p)
        assert {link.a_ip, link.b_ip} == set(link.network)


def test_runs_out_of_room_with_a_clear_error(raw):
    data = broken(raw, lambda d: d["segments"].append({"name": "huge", "vlan": 50, "hosts": 70000, "router": "core1"}))
    with pytest.raises(InventoryError, match="no room for segment huge"):
        allocate(parse(data))


# --- interfaces ----------------------------------------------------------------


def test_both_ends_of_every_link_agree(site):
    ifaces = assign(site, allocate(site))
    for device, items in ifaces.items():
        names = [i.name for i in items]
        assert names == [f"eth{n}" for n in range(1, len(items) + 1)], device
        for i in items:
            peers = [p for p in ifaces[i.peer] if p.peer == device and p.network == i.network]
            assert len(peers) == 1
            assert peers[0].address != i.address
            assert ipaddress.ip_interface(f"{i.address}/{i.network.prefixlen}").network == i.network

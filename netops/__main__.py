"""Command line.

    python -m netops build    generate configs, topology and docs from the inventory
    python -m netops check    prove the compiled firewall matches the policy
    python -m netops probe    measure this machine's network, layer by layer
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .docs import ip_plan, policy_matrix
from .interfaces import assign
from .ipam import allocate
from .model import InventoryError, load
from .policy import compile_policy, intended, simulate, flows_to_check
from .render import build

ROOT = Path(__file__).resolve().parent.parent


def cmd_build(args: argparse.Namespace) -> int:
    site = load(args.inventory)
    files = build(site, Path(args.out))
    plan = allocate(site)
    docs = Path(args.docs)
    docs.mkdir(parents=True, exist_ok=True)
    (docs / "ip-plan.md").write_text(
        ip_plan(site, plan, assign(site, plan)) + "\n" + policy_matrix(site), encoding="utf-8", newline="\n"
    )
    print(f"wrote {len(files)} files to {args.out}/ and docs/ip-plan.md")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    site = load(args.inventory)
    plan = allocate(site)
    chains = compile_policy(site, plan, assign(site, plan))
    flows = flows_to_check(site)
    bad = [f for f in flows if intended(site, f) != simulate(site, plan, chains, f)]
    for f in bad:
        want = "allow" if intended(site, f) else "deny"
        print(f"MISMATCH {f.src} -> {f.dst} {f.proto} {f.port or ''}: policy says {want}")
    print(f"checked {len(flows)} flows: {len(flows) - len(bad)} match the policy, {len(bad)} do not")
    return 1 if bad else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netops")
    parser.add_argument("--inventory", default=str(ROOT / "inventory" / "site.yaml"))
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="generate configs, topology and docs")
    b.add_argument("--out", default=str(ROOT / "out"))
    b.add_argument("--docs", default=str(ROOT / "docs"))
    b.set_defaults(fn=cmd_build)
    c = sub.add_parser("check", help="verify the compiled firewall against the policy")
    c.set_defaults(fn=cmd_check)
    p = sub.add_parser("probe", help="measure this machine's network, layer by layer")
    p.add_argument("--count", type=int, default=10, help="probes per target")
    p.add_argument("--db", default=str(ROOT / "probe.sqlite"))
    p.add_argument("--watch", type=int, default=0, help="repeat every N seconds")
    p.set_defaults(fn=None)
    sub.add_parser("lab", help="verify the deployed Containerlab network (needs Docker)")
    args = parser.parse_args(argv)
    try:
        if args.cmd == "lab":
            from .lab import run

            return run(load(args.inventory))
        if args.cmd == "probe":
            from .probe import run_cli

            return run_cli(args)
        return args.fn(args)
    except InventoryError as e:
        print(f"inventory error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

"""Contain the stack's containers: no route from them to private networks or this host.

Rootless Podman keeps every bridge-networked container in one shared network namespace
(`podman unshare --rootless-netns`), owned by the stack user and separate from the host's.
Container traffic to the outside is *forwarded* through it, so an nftables `forward` hook
there filters exactly the stack's containers: no sudo, and nothing else of the user's is
affected (host processes, and containers on other networks, never enter that namespace).

`matrix-netns` holds the namespace open and `matrix-egress` loads these rules before any
other container starts, so there is no unfiltered window and a failure stops the stack.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import subprocess
import sys



BLOCKED_V4 = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
]
BLOCKED_V6 = ["::1/128", "::ffff:0:0/96", "fc00::/7", "fe80::/10", "ff00::/8"]
TABLE = "matrix_egress"


def host_addresses() -> list[str]:
    """Every address this host owns. A container reaching one of them reaches the host's services."""
    out = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True, check=True).stdout
    addrs = {
        a["local"]
        for iface in json.loads(out)
        for a in iface.get("addr_info", [])
        if not ipaddress.ip_address(a["local"]).is_link_local
    }
    return sorted(addrs)


def ruleset(host_addrs: list[str]) -> str:
    v4 = [a for a in host_addrs if ":" not in a]
    v6 = [a for a in host_addrs if ":" in a]
    own = []
    if v4:
        own.append(f"ip daddr {{ {', '.join(v4)} }} counter reject with icmpx type admin-prohibited")
    if v6:
        own.append(f"ip6 daddr {{ {', '.join(v6)} }} counter reject with icmpx type admin-prohibited")
    own_rules = "\n\t\t".join(own)
    return f"""\
table inet {TABLE}
delete table inet {TABLE}

table inet {TABLE} {{
	chain forward {{
		type filter hook forward priority -10; policy accept;

		# replies to connections that were opened towards the container (published ports)
		ct state established,related accept

		# this host's own addresses, so a container can't reach host services via its public IP
		{own_rules}

		# LAN, loopback, link-local (cloud metadata), CGNAT, multicast, ULA
		ip daddr {{ {', '.join(BLOCKED_V4)} }} counter reject with icmpx type admin-prohibited
		ip6 daddr {{ {', '.join(BLOCKED_V6)} }} counter reject with icmpx type admin-prohibited
	}}
}}
"""


def in_netns(*cmd: str, input: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["podman", "unshare", "--rootless-netns", *cmd], input=input, capture_output=True, text=True
    )


def current_ruleset() -> str:
    return ruleset(host_addresses())


def apply() -> None:
    """Load the rules in the rootless netns. Raises if the netns isn't the container one."""
    # With no containers running, `--rootless-netns` silently runs in the HOST namespace.
    # netavark's table only exists in the real one; refuse to proceed otherwise.
    if "inet netavark" not in in_netns("nft", "list", "tables").stdout:
        raise RuntimeError("rootless container network namespace not found; is matrix-netns running?")
    proc = in_netns("nft", "-f", "/dev/stdin", input=current_ruleset())
    if proc.returncode != 0:
        raise RuntimeError(f"loading egress rules failed: {proc.stderr.strip()}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--apply", action="store_true", help="load the rules")
    g.add_argument("--print", action="store_true", help="print the ruleset for this host")
    g.add_argument("--counters", action="store_true", help="show what has been blocked so far")
    args = p.parse_args(argv)

    if args.print:
        sys.stdout.write(current_ruleset())
    elif args.counters:
        sys.stdout.write(in_netns("nft", "list", "chain", "inet", TABLE, "forward").stdout)
    else:
        try:
            apply()
        except RuntimeError as e:
            print(e, file=sys.stderr)
            return 1
        print("egress filter loaded")
    return 0


if __name__ == "__main__":
    sys.exit(main())

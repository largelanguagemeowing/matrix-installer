"""Keep LiveKit's advertised media addresses in step with this host's public IPs.

LiveKit can't discover them itself (STUN fails while the media port is published), so they are
rendered into livekit.yaml. When the host's address changes, re-render and restart LiveKit.
Runs from the 5-minute refresh timer; a failed lookup changes nothing.
"""

from __future__ import annotations

import dataclasses
import subprocess
import sys

from .checks import public_ipv4, public_ipv6
from .config import Paths, Stack
from .render import render_all


def sync(paths: Paths, ip4: str | None, ip6: str | None) -> bool:
    """Apply detected addresses; True if the stack config changed. None (lookup failed) keeps the old value."""
    stack = Stack.load(paths)
    new = dataclasses.replace(stack, public_ipv4=ip4 or stack.public_ipv4, public_ipv6=ip6 or stack.public_ipv6)
    if new == stack:
        return False
    new.save(paths)
    render_all(new, paths)
    return True


def main() -> int:
    paths = Paths()
    if sync(paths, public_ipv4(), public_ipv6()):
        print("public address changed; restarting LiveKit")
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "--user", "try-restart", "matrix-livekit.service"], check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

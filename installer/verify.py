"""`just check`: probe the running deployment from the outside."""

from __future__ import annotations

import argparse
import sys
import time

from .checks import Check, has_failures, verify_deployment
from .config import Paths, Stack


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--wait", type=int, default=0, metavar="SECONDS",
                   help="retry until everything passes (certificates take a moment to issue)")
    args = p.parse_args(argv)

    s = Stack.load(Paths())
    deadline = time.monotonic() + args.wait
    while True:
        results: list[Check] = verify_deployment(s.server_name, s.matrix_host, s.chat_host, s.rtc_host)
        if not has_failures(results) or time.monotonic() >= deadline:
            break
        time.sleep(10)
    print(*results, sep="\n")
    return 1 if has_failures(results) else 0


if __name__ == "__main__":
    sys.exit(main())

"""Tiny read-only queries for the Justfile, so service lists live in one place (services.py)."""

from __future__ import annotations

import sys

from . import services

QUERIES = {
    "services": services.SERVICES,
    "journal-args": [a for c in services.SERVICES for a in (f"CONTAINER_NAME={c}", "+")][:-1],
    "units": services.BACKGROUND_UNITS,
}


def main(argv: list[str]) -> int:
    print(" ".join(QUERIES[argv[0]]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

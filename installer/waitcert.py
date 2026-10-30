"""ExecStartPre helper: block until Caddy has issued the certificate LiveKit's TURN/TLS needs."""

from __future__ import annotations

import sys
import time
from pathlib import Path

CA_DIR = "acme-v02.api.letsencrypt.org-directory"  # pinned via acme_ca in the Caddyfile


def cert_dir(caddy_data: Path, host: str) -> Path:
    return caddy_data / "caddy" / "certificates" / CA_DIR / host


def main(argv: list[str]) -> int:
    caddy_data, host = Path(argv[0]), argv[1]
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        d = cert_dir(caddy_data, host)
        if all((d / f"{host}.{ext}").is_file() and (d / f"{host}.{ext}").stat().st_size for ext in ("crt", "key")):
            return 0
        time.sleep(3)
    print(f"no certificate for {host} in {caddy_data}; is DNS pointing here and port 80/443 open?", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

"""Render templates/ into the Quadlet, config and systemd directories."""

from __future__ import annotations

import json
from pathlib import Path
from string import Template

from .config import Paths, Stack

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"
REPO_DIR = TEMPLATES.parent

# Single source of truth for every image in the stack (also used by the scanner).
# The Postgres image is derived from Stack.postgres_major (a major upgrade needs a dump/restore).
IMAGES = {
    "synapse_image": "ghcr.io/element-hq/synapse:latest",
    "caddy_image": "docker.io/library/caddy:2-alpine",
    "livekit_image": "docker.io/livekit/livekit-server:latest",
    "jwt_image": "ghcr.io/element-hq/lk-jwt-service:latest",
    "pinniped_image": "ghcr.io/largelanguagemeowing/pinniped:latest",  # linux/amd64 only
    "trivy_image": "ghcr.io/aquasecurity/trivy:latest",
}


# Synapse listens only on this address of the `matrix` network, so the JWT service (which shares
# a network with it for the application-service proxy) cannot reach its port, and nobody on the
# host can either: that port accepts X-Forwarded-For from whoever connects, so only Caddy may.
MATRIX_SUBNET = "10.89.201.0/24"
MATRIX_GATEWAY = "10.89.201.1"
SYNAPSE_IP = "10.89.201.10"


def livekit_ip_config(stack: Stack) -> str:
    """One address per family, as `v4,v6`. STUN discovery can't be used: it fails while the media port is published."""
    ips = [ip for ip in (stack.public_ipv4, stack.public_ipv6) if ip]
    if not ips:
        return "use_external_ip: true"
    # Quoted: an IPv6 address can end in "::", which YAML would read as a mapping key.
    return "use_external_ip: false\n  node_ip: " + json.dumps(",".join(ips))


def postgres_image(major: int) -> str:
    return f"docker.io/library/postgres:{major}-alpine"


def postgres_data_mount(major: int) -> str:
    """Postgres 18+ images keep a versioned directory under /var/lib/postgresql and refuse a mount on .../data."""
    return "/var/lib/postgresql" if major >= 18 else "/var/lib/postgresql/data"


def client_wellknown(stack: Stack) -> dict:
    return {
        "m.homeserver": {"base_url": f"https://{stack.matrix_host}"},
        "org.matrix.msc4143.rtc_foci": [
            {
                "type": "livekit",
                "livekit_service_url": f"https://{stack.matrix_host}/livekit/jwt",
            }
        ],
    }


def server_wellknown(stack: Stack) -> dict:
    return {"m.server": f"{stack.matrix_host}:443"}


def _wellknown_handlers(stack: Stack) -> str:
    def handler(name: str, body: dict) -> str:
        return (
            f"\thandle /.well-known/matrix/{name} {{\n"
            "\t\theader Access-Control-Allow-Origin *\n"
            "\t\theader Content-Type application/json\n"
            f"\t\trespond `{json.dumps(body)}` 200\n"
            "\t}"
        )

    return "\n".join(
        [handler("client", client_wellknown(stack)), handler("server", server_wellknown(stack))]
    )


def _apex_block(stack: Stack) -> str:
    if not stack.serve_apex_wellknown:
        return ""
    return (
        f"{stack.server_name} {{\n\timport listen\n{_wellknown_handlers(stack)}\n"
        "\thandle {\n\t\trespond 404\n\t}\n}\n"
    )


def template_values(stack: Stack, paths: Paths) -> dict[str, str]:
    return {
        **IMAGES,
        "postgres_image": postgres_image(stack.postgres_major),
        "postgres_data_mount": postgres_data_mount(stack.postgres_major),
        **{k: str(v) for k, v in vars(stack.secrets).items()},
        "server_name": stack.server_name,
        "matrix_host": stack.matrix_host,
        "chat_host": stack.chat_host,
        "rtc_host": stack.rtc_host,
        "acme_email": stack.acme_email,
        "conf_dir": str(paths.conf_dir),
        "caddy_data_dir": str(paths.caddy_data_dir),
        "rtc_ip_config": livekit_ip_config(stack),
        "matrix_subnet": MATRIX_SUBNET,
        "matrix_gateway": MATRIX_GATEWAY,
        "synapse_ip": SYNAPSE_IP,
        "repo_dir": str(REPO_DIR),
        "jwt_aliases": ",".join(f"alias={h}" for h in stack.hosts if h != stack.chat_host),
        "wellknown": _wellknown_handlers(stack),
        "apex_block": _apex_block(stack),
    }


def _destination(src: Path, paths: Paths) -> Path:
    kind = src.relative_to(TEMPLATES).parts[0]
    root = {"quadlet": paths.quadlet_dir, "conf": paths.conf_dir, "systemd": paths.systemd_dir}[kind]
    return root / src.name


def render_all(stack: Stack, paths: Paths) -> list[Path]:
    """Write every template; unresolved ${vars} raise KeyError rather than ship broken config."""
    values = template_values(stack, paths)
    paths.caddy_data_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for src in sorted(p for p in TEMPLATES.rglob("*") if p.is_file()):
        dest = _destination(src, paths)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(Template(src.read_text()).substitute(values))
        dest.chmod(0o600 if dest.suffix == ".env" else 0o644)
        written.append(dest)
    paths.conf_dir.chmod(0o700)  # secrets live in here; keep other local users out
    return written

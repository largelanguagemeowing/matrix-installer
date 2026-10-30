"""Preflight and post-deploy checks. Each returns a Check; nothing here raises on a failed probe."""

from __future__ import annotations

import errno
import json
import platform
import re
import socket
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Status(Enum):
    OK = "ok"
    WARN = "warn"
    FAIL = "FAIL"


@dataclass(frozen=True)
class Check:
    name: str
    status: Status
    detail: str = ""

    def __str__(self) -> str:
        return f"[{self.status.value:>4}] {self.name}" + (f": {self.detail}" if self.detail else "")


def has_failures(checks: list[Check]) -> bool:
    return any(c.status is Status.FAIL for c in checks)


def http_get(url: str, timeout: float = 10) -> tuple[int, str]:
    """(status, body); status 0 on connection/TLS failure with the reason as the body."""
    req = urllib.request.Request(url, headers={"User-Agent": "matrix-installer"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return 0, str(e)


# ---- preflight (before anything is running) --------------------------------------------


def _public_ip(url: str) -> str | None:
    status, body = http_get(url, timeout=5)
    return body.strip() if status == 200 else None


def public_ipv4() -> str | None:
    return _public_ip("https://api.ipify.org")


def public_ipv6() -> str | None:
    """None when this host has no working IPv6 route to the internet."""
    return _public_ip("https://api6.ipify.org")


def check_dns(host: str, ip4: str | None, ip6: str | None) -> Check:
    """A must point here. AAAA, if present, must point here too: a stale AAAA silently breaks
    ACME and federation for every IPv6-capable peer, so it is a failure, not a warning."""
    name = f"DNS {host}"
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return Check(name, Status.FAIL, "does not resolve; create an A (and optionally AAAA) record")
    v4 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
    v6 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
    if ip4 is not None and ip4 not in v4:
        return Check(name, Status.FAIL, f"A record is {v4 or 'missing'}, this host's public IPv4 is {ip4}")
    if v6 and ip6 is None:
        return Check(name, Status.FAIL, f"AAAA {v6} exists but this host has no public IPv6; remove it or fix IPv6")
    if v6 and ip6 not in v6:
        return Check(name, Status.FAIL, f"AAAA is {v6}, this host's public IPv6 is {ip6}")
    if ip4 is None:
        return Check(name, Status.WARN, f"resolves to {', '.join(v4 + v6)}; could not learn this host's public IPv4")
    if ip6 is not None and not v6:
        return Check(name, Status.OK, f"{ip4} (IPv4 only; add AAAA {ip6} for IPv6 clients)")
    return Check(name, Status.OK, ", ".join([ip4] + ([ip6] if v6 else [])))


def check_port_free(port: int, proto: str = "tcp") -> Check:
    name = f"port {port}/{proto} free"
    kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    for family, addr in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
        try:
            with socket.socket(family, kind) as s:
                if family == socket.AF_INET6:
                    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                s.bind((addr, port))
        except PermissionError:
            return Check(name, Status.OK, "needs the unprivileged-port sysctl (checked separately)")
        except OSError as e:
            if family == socket.AF_INET6 and e.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
                continue  # no IPv6 on this host
            return Check(name, Status.WARN, f"in use on {addr} (expected if the stack is already running)")
    return Check(name, Status.OK)


def check_unprivileged_ports(sysctl: Path = Path("/proc/sys/net/ipv4/ip_unprivileged_port_start")) -> Check:
    name = "user systemd can bind 80/443"
    try:
        start = int(sysctl.read_text())
    except (OSError, ValueError):
        return Check(name, Status.WARN, "could not read net.ipv4.ip_unprivileged_port_start")
    if start <= 80:
        return Check(name, Status.OK)
    return Check(
        name,
        Status.FAIL,
        f"ip_unprivileged_port_start={start}; run: "
        "echo 'net.ipv4.ip_unprivileged_port_start=80' | sudo tee /etc/sysctl.d/99-unpriv-ports.conf "
        "&& sudo sysctl --system",
    )


def check_podman() -> Check:
    name = "podman >= 5.2 (Quadlet network aliases, healthy notify)"
    try:
        out = subprocess.run(["podman", "--version"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return Check(name, Status.FAIL, "podman not found")
    m = re.search(r"(\d+)\.(\d+)", out)
    if not m or (int(m[1]), int(m[2])) < (5, 2):
        return Check(name, Status.FAIL, out.strip())
    return Check(name, Status.OK, out.strip())


def check_architecture() -> Check:
    name = "x86_64 (Pinniped image is amd64 only)"
    machine = platform.machine()
    return Check(name, Status.OK if machine == "x86_64" else Status.FAIL, machine)


def check_journal(persistent_dir: Path = Path("/var/log/journal")) -> Check:
    """Container logs go to the journal, whose rotation (size and age caps) is journald's.
    Without a persistent journal they vanish on reboot, exactly when you need them."""
    name = "logs persist across reboots (journald)"
    if persistent_dir.is_dir():
        return Check(name, Status.OK, "rotation: journald SystemMaxUse (default 10% of the disk, max 4G)")
    return Check(name, Status.WARN, "journal is volatile; run: sudo mkdir -p /var/log/journal && sudo systemctl restart systemd-journald")


def check_linger(user: str) -> Check:
    name = "user lingering (services survive logout/reboot)"
    out = subprocess.run(
        ["loginctl", "show-user", user, "--property=Linger", "--value"], capture_output=True, text=True
    ).stdout.strip()
    if out == "yes":
        return Check(name, Status.OK)
    return Check(name, Status.WARN, f"run: loginctl enable-linger {user}  (`just up` does this for you)")


def check_wellknown_server(server_name: str, matrix_host: str) -> Check:
    """Is server_name already delegating to matrix_host? Only meaningful for a separate apex."""
    name = f"https://{server_name}/.well-known/matrix/server"
    status, body = http_get(f"https://{server_name}/.well-known/matrix/server", timeout=8)
    if status != 200:
        return Check(name, Status.WARN, "not served yet; either let Caddy serve it, or host the JSON yourself")
    try:
        target = json.loads(body).get("m.server")
    except json.JSONDecodeError:
        return Check(name, Status.FAIL, "not valid JSON")
    if target != f"{matrix_host}:443":
        return Check(name, Status.FAIL, f'points at {target!r}, expected "{matrix_host}:443"')
    return Check(name, Status.OK)


# ---- post-deploy (`just check`) ----------------------------------------------------------


def _expect(name: str, url: str, want: int = 200, contains: str = "") -> Check:
    status, body = http_get(url)
    if status != want:
        return Check(name, Status.FAIL, f"{url} -> {status or body}")
    if contains and contains not in body:
        return Check(name, Status.FAIL, f"{url} missing {contains!r}")
    return Check(name, Status.OK)


def verify_deployment(server_name: str, matrix_host: str, chat_host: str, rtc_host: str) -> list[Check]:
    checks = [
        _expect("client API", f"https://{matrix_host}/_matrix/client/versions", contains="versions"),
        _expect("client well-known + MatrixRTC focus", f"https://{matrix_host}/.well-known/matrix/client", contains="rtc_foci"),
        check_wellknown_server(server_name, matrix_host),
        _expect("lk-jwt-service health", f"https://{matrix_host}/livekit/jwt/healthz"),
        _expect("LiveKit signalling", f"https://{rtc_host}/"),
        _expect("Pinniped", f"https://{chat_host}/"),
        # the admin API must NOT be reachable from the internet
        _expect("admin API not exposed", f"https://{matrix_host}/_synapse/admin/v1/server_version", want=404),
    ]
    for host, port in ((rtc_host, 7881), (rtc_host, 5349), (matrix_host, 443)):
        checks += reachable_per_family(host, port)
    checks.append(federation_tester(server_name))
    return checks


def reachable_per_family(host: str, port: int) -> list[Check]:
    """Connect over every address family the name resolves to; a dead AAAA must not hide behind a live A."""
    checks = []
    for family, label in ((socket.AF_INET, "IPv4"), (socket.AF_INET6, "IPv6")):
        name = f"{host}:{port} reachable over {label}"
        try:
            addrs = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
        except socket.gaierror:
            if family == socket.AF_INET:
                checks.append(Check(name, Status.FAIL, "no A record"))
            continue  # no AAAA is fine
        try:
            socket.create_connection(addrs[0][4][:2], timeout=5).close()
            checks.append(Check(name, Status.OK))
        except OSError as e:
            checks.append(Check(name, Status.FAIL, f"{e}; check firewall / port forwarding for {label}"))
    return checks


def federation_tester(server_name: str) -> Check:
    name = "federation (federationtester.matrix.org)"
    status, body = http_get(f"https://federationtester.matrix.org/api/report?server_name={server_name}", timeout=30)
    if status != 200:
        return Check(name, Status.WARN, f"tester unavailable ({status or body})")
    ok = json.loads(body).get("FederationOK")
    return Check(name, Status.OK if ok else Status.FAIL, "" if ok else "tester reports federation is broken")

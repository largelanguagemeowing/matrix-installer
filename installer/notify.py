"""Scan running images with Trivy, check for pending image updates, DM the admin on Matrix.

Runs from matrix-scan.timer. Only messages when the set of problems changes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from .services import CONTAINERS
from .config import BOT_USER, Paths, Stack
from .render import IMAGES

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1}
MAX_LISTED = 15


@dataclass(frozen=True)
class Finding:
    image: str
    cve: str
    package: str
    installed: str
    fixed: str
    severity: str


# ---- pure parsing / formatting (unit tested) -------------------------------------------


def parse_trivy(image: str, report: dict) -> list[Finding]:
    return [
        Finding(
            image=image,
            cve=v["VulnerabilityID"],
            package=v["PkgName"],
            installed=v.get("InstalledVersion", "?"),
            fixed=v["FixedVersion"],
            severity=v["Severity"],
        )
        for result in report.get("Results") or []
        for v in result.get("Vulnerabilities") or []
        if v.get("FixedVersion") and v["Severity"] in SEVERITY_ORDER
    ]


def parse_pending(auto_update_output: str) -> list[str]:
    """`podman auto-update --dry-run --format '{{.Unit}}\\t{{.Image}}\\t{{.Updated}}'` -> pending images."""
    pending = []
    for line in auto_update_output.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[2].strip() == "pending":
            pending.append(parts[1].strip())
    return pending


def fingerprint(findings: list[Finding], pending: list[str]) -> str:
    items = sorted({f"{f.image}|{f.cve}" for f in findings} | {f"pending|{i}" for i in pending})
    return hashlib.sha256("\n".join(items).encode()).hexdigest() if items else ""


def format_report(findings: list[Finding], pending: list[str]) -> str:
    lines = ["⚠️ Your Matrix stack needs an update. Run `just update` on the server.", ""]
    if pending:
        lines.append("Newer images available:")
        lines += [f"  • {image}" for image in pending]
        lines.append("")
    if findings:
        ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.image, f.cve))
        lines.append(f"{len(findings)} fixable HIGH/CRITICAL vulnerabilities:")
        for f in ordered[:MAX_LISTED]:
            lines.append(f"  • {f.severity} {f.cve} in {f.image}: {f.package} {f.installed} → {f.fixed}")
        if len(ordered) > MAX_LISTED:
            lines.append(f"  … and {len(ordered) - MAX_LISTED} more (`just scan --print`)")
    return "\n".join(lines).rstrip()


def plan_message(findings: list[Finding], pending: list[str], last_fingerprint: str | None) -> str | None:
    """The DM to send, or None when nothing changed since the last one (None = always send)."""
    current = fingerprint(findings, pending)
    if current == last_fingerprint:
        return None
    if not current:
        return "✅ Stack is up to date: no pending updates, no fixable HIGH/CRITICAL vulnerabilities."
    return format_report(findings, pending)


# ---- health (pure parts unit tested) --------------------------------------------------

BACKUP_MAX_AGE = 36 * 3600


def parse_inspect(name: str, line: str) -> str | None:
    """`podman inspect -f '{{.State.Status}}|{{.State.Health.Status}}'` -> a problem description, or None."""
    state, _, health = line.strip().partition("|")
    if state != "running":
        return f"{name} is {state or 'missing'}"
    if health == "unhealthy":
        return f"{name} is unhealthy"
    return None


def backup_problem(newest: float | None, now: float) -> str | None:
    if newest is None:
        return "no backup exists yet"
    if now - newest > BACKUP_MAX_AGE:
        return f"last verified backup is {int((now - newest) / 3600)}h old"
    return None


def format_health(problems: list[str]) -> str:
    if not problems:
        return "🟢 Stack recovered: all services healthy and backups fresh."
    return "🔴 Stack problems:\n" + "\n".join(f"  • {p}" for p in problems)


def health_problems(stack: Stack, paths: Paths) -> list[str]:
    problems = []
    for name in CONTAINERS:
        out = subprocess.run(
            ["podman", "inspect", "-f", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}", name],
            capture_output=True, text=True,
        )
        if problem := parse_inspect(name, out.stdout if out.returncode == 0 else "|"):
            problems.append(problem)
    failed = subprocess.run(
        ["systemctl", "--user", "list-units", "--state=failed", "--no-legend", "--plain", "matrix-*"],
        capture_output=True, text=True,
    ).stdout.split("\n")
    problems += [f"systemd unit failed: {line.split()[0]}" for line in failed if line.strip()]
    backups = [p.stat().st_mtime for p in paths.backup_dir.glob("*/MANIFEST.json")] if paths.backup_dir.exists() else []
    if problem := backup_problem(max(backups, default=None), time.time()):
        problems.append(problem)
    return problems


def run_health(stack: Stack, paths: Paths, print_only: bool) -> int:
    problems = health_problems(stack, paths)
    if print_only:
        print(format_health(problems) if problems else "healthy")
        return 0
    state = paths.state_dir / "health_fingerprint"
    last = state.read_text().strip() if state.exists() else ""
    current = hashlib.sha256("\n".join(sorted(problems)).encode()).hexdigest() if problems else ""
    if current == last:
        return 0
    try:
        send_dm(stack, paths, format_health(problems))
    except (urllib.error.URLError, OSError) as e:
        # Synapse itself is down so the DM can't go out; leave state alone and retry next tick.
        print(f"could not deliver alert ({e}); problems: {problems}", file=sys.stderr)
        return 1
    state.write_text(current)
    return 0


# ---- scanning ---------------------------------------------------------------------------


def running_images() -> list[str]:
    out = subprocess.run(
        ["podman", "ps", "--filter", "name=^matrix-", "--format", "{{.Image}}"],
        capture_output=True, text=True, check=True,
    ).stdout
    return sorted(set(out.split()))


def scan_image(image: str) -> list[Finding]:
    with tempfile.TemporaryDirectory() as tmp:
        tar = Path(tmp) / "image.tar"
        saved = subprocess.run(["podman", "save", "-o", str(tar), image], capture_output=True, text=True)
        if saved.returncode != 0:
            raise RuntimeError(f"podman save failed on {image}: {saved.stderr.strip()}")
        proc = subprocess.run(
            [
                "podman", "run", "--rm", "--network", "matrix",  # inside the egress filter
                "-v", "matrix-trivy-cache:/root/.cache",
                "-v", f"{tar}:/image.tar:ro,Z",
                IMAGES["trivy_image"],
                "image", "--input", "/image.tar", "--scanners", "vuln",
                "--severity", "HIGH,CRITICAL", "--ignore-unfixed", "--quiet", "--format", "json",
            ],
            capture_output=True, text=True,
        )
    if proc.returncode != 0:
        raise RuntimeError(f"trivy failed on {image}: {proc.stderr.strip()}")
    return parse_trivy(image, json.loads(proc.stdout))


def pending_updates() -> list[str]:
    proc = subprocess.run(
        ["podman", "auto-update", "--dry-run", "--format", "{{.Unit}}\t{{.Image}}\t{{.Updated}}"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"podman auto-update --dry-run failed: {proc.stderr.strip()}")
    return parse_pending(proc.stdout)


# ---- Matrix bot -------------------------------------------------------------------------


class MatrixBot:
    def __init__(self, base_url: str, user: str, password: str) -> None:
        self.base = base_url.rstrip("/")
        self.user, self.password = user, password
        self.token = ""

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        req = urllib.request.Request(
            f"{self.base}/_matrix/client/v3{path}",
            method=method,
            data=json.dumps(body if body is not None else {}).encode(),
            headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {self.token}"} if self.token else {})},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())

    def __enter__(self) -> MatrixBot:
        self.token = self._call("POST", "/login", {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": self.user},
            "password": self.password,
        })["access_token"]
        return self

    def __exit__(self, *exc: object) -> None:
        self._call("POST", "/logout")  # don't accumulate a device per timer run

    def create_dm(self, invitee: str) -> str:
        return self._call("POST", "/createRoom", {
            "is_direct": True,
            "invite": [invitee],
            "preset": "trusted_private_chat",
            "name": "Stack updates",
        })["room_id"]

    def send(self, room_id: str, text: str) -> None:
        self._call("PUT", f"/rooms/{quote(room_id)}/send/m.room.message/{uuid.uuid4().hex}",
                   {"msgtype": "m.text", "body": text})


def send_dm(stack: Stack, paths: Paths, text: str) -> None:
    room_file = paths.state_dir / "dm_room"
    # via Caddy: Synapse has no host-side port, and this is the path real clients use
    with MatrixBot(f"https://{stack.matrix_host}", BOT_USER, stack.secrets.bot_password) as bot:
        room = room_file.read_text().strip() if room_file.exists() else ""
        if room:
            try:
                bot.send(room, text)
                return
            except urllib.error.HTTPError:
                pass  # the bot lost access to the room; start a fresh DM
        room = bot.create_dm(stack.admin_mxid)
        room_file.write_text(room)
        bot.send(room, text)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--print", action="store_true", help="print the report instead of sending it")
    p.add_argument("--force", action="store_true", help="send even if nothing changed since the last DM")
    p.add_argument("--health", action="store_true", help="check services and backups instead of scanning images")
    args = p.parse_args(argv)

    paths = Paths()
    stack = Stack.load(paths)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    if args.health:
        return run_health(stack, paths, args.print)

    # An incomplete scan must never look like a clean one: on any failure send nothing, keep the
    # last fingerprint and exit non-zero so the unit shows failed and systemd retries it.
    findings: list[Finding] = []
    failures: list[str] = []
    for image in running_images():
        try:
            findings += scan_image(image)
        except RuntimeError as e:
            failures.append(str(e))
    try:
        pending = pending_updates()
    except RuntimeError as e:
        pending = []
        failures.append(str(e))
    if failures:
        print("scan incomplete, not reporting:\n" + "\n".join(failures), file=sys.stderr)
        return 1

    if args.print:
        print(format_report(findings, pending) if findings or pending else "No fixable HIGH/CRITICAL issues, no pending updates.")
        return 0

    state = paths.state_dir / "last_fingerprint"
    last = state.read_text().strip() if state.exists() else ""
    text = plan_message(findings, pending, None if args.force else last)
    if text is None:
        return 0
    send_dm(stack, paths, text)
    state.write_text(fingerprint(findings, pending))
    return 0


if __name__ == "__main__":
    sys.exit(main())

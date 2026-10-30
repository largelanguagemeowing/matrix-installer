"""Create accounts through Synapse's shared-secret registration (public registration stays off)."""

from __future__ import annotations

import argparse
import getpass
import os
import subprocess
import sys
import time

from .config import BOT_USER, Paths, Stack
from .render import SYNAPSE_IP


def wait_for_synapse(timeout: float = 300) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        health = subprocess.run(
            ["podman", "inspect", "-f", "{{.State.Health.Status}}", "matrix-synapse"], capture_output=True, text=True
        ).stdout.strip()
        if health == "healthy":
            return
        time.sleep(3)
    sys.exit("Synapse did not become healthy; see `just logs synapse`")


def register(username: str, password: str, admin: bool) -> bool:
    """True if created, False if the user already existed."""
    proc = subprocess.run(
        [
            "podman", "exec", "-i", "matrix-synapse", "register_new_matrix_user",
            "-c", "/config/homeserver.yaml", "-u", username,
            "--password-file", "/dev/stdin", "-a" if admin else "--no-admin",
            f"http://{SYNAPSE_IP}:8008",
        ],
        input=password, text=True, capture_output=True,
    )
    if proc.returncode == 0:
        return True
    if "User ID already taken" in proc.stdout + proc.stderr:
        return False
    sys.exit(f"registering {username} failed:\n{proc.stdout}{proc.stderr}")


MIN_PASSWORD = 12


def read_password_file(path: str) -> str:
    """First line of `path` ("-" for stdin), for scripted installs. Keeps the password out of argv and the env."""
    try:
        text = sys.stdin.read() if path == "-" else open(path).read()
    except OSError as e:
        sys.exit(f"cannot read password file {path}: {e.strerror}")
    pw = text.splitlines()[0] if text else ""
    if len(pw) < MIN_PASSWORD:
        sys.exit(f"password in {path} must be at least {MIN_PASSWORD} characters")
    return pw


def prompt_password(user: str) -> str:
    while True:
        pw = getpass.getpass(f"Password for {user}: ")
        if len(pw) >= MIN_PASSWORD and pw == getpass.getpass("Repeat: "):
            return pw
        print("Passwords must match and be at least 12 characters.")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--user", help="create this extra (non-admin) user instead of the first admin + bot")
    p.add_argument("--password-file", metavar="PATH",
                   help='read the password from the first line of PATH ("-" = stdin) instead of prompting; '
                        "for the admin it defaults to $ADMIN_PASSWORD_FILE")
    args = p.parse_args(argv)
    path = args.password_file or (None if args.user else os.environ.get("ADMIN_PASSWORD_FILE"))
    password = (lambda user: read_password_file(path)) if path else prompt_password

    stack = Stack.load(Paths())
    wait_for_synapse()

    if args.user:
        created = register(args.user, password(args.user), admin=False)
        print(f"{'Created' if created else 'Already exists:'} @{args.user}:{stack.server_name}")
        return 0

    created = register(stack.admin_user, password(stack.admin_user), admin=True)
    print(f"{'Created' if created else 'Already exists:'} admin {stack.admin_mxid}")
    created = register(BOT_USER, stack.secrets.bot_password, admin=False)
    print(f"{'Created' if created else 'Already exists:'} notifier bot {stack.bot_mxid}")
    print(f"\nLog in at https://{stack.chat_host} as {stack.admin_mxid}")
    print("Run `just scan` to get the first vulnerability report as a DM.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

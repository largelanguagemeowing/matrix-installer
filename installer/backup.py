"""Backup, verified restore and Postgres major upgrade.

A backup is a directory holding a `pg_dump -Fc` of Synapse's database, an export of the Synapse
data volume (signing key + media), the stack config (which holds every secret) and a manifest
with checksums and row counts. `verify` proves a backup is restorable by loading it into a
throwaway Postgres and comparing counts; it is what the daily timer runs after each backup.

Backups contain secrets and your server's signing key: encrypt them before they leave this host.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .services import EDGE
from .config import Paths, Stack
from .render import postgres_image, render_all

PG = "matrix-postgres"
SYNAPSE_VOLUME = "matrix-synapse-data"
PG_VOLUME = "matrix-postgres-data"
COUNTED_TABLES = ("users", "events", "rooms")
KEEP_DEFAULT = 7


class BackupError(RuntimeError):
    pass


def run(*cmd: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if check and proc.returncode != 0:
        raise BackupError(f"{' '.join(cmd[:4])}… failed: {proc.stderr.strip()}")
    return proc


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def row_counts(container: str) -> dict[str, int]:
    counts = {}
    for table in COUNTED_TABLES:
        out = run("podman", "exec", container, "psql", "-U", "synapse", "-d", "synapse", "-tAc",
                  f"select count(*) from {table}").stdout.strip()
        counts[table] = int(out)
    return counts


# ---- backup -----------------------------------------------------------------------------


def backup(paths: Paths) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = paths.backup_dir / stamp
    dest.mkdir(parents=True)
    paths.backup_dir.chmod(0o700)
    dest.chmod(0o700)
    try:
        _write_backup(paths, dest, stamp)
    except BaseException:
        shutil.rmtree(dest)  # a half-written backup must never look like a backup
        raise
    return dest


def _write_backup(paths: Paths, dest: Path, stamp: str) -> None:
    counts = row_counts(PG)
    with (dest / "db.dump").open("wb") as f:
        proc = subprocess.run(["podman", "exec", PG, "pg_dump", "-U", "synapse", "-Fc", "synapse"],
                              stdout=f, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise BackupError(f"pg_dump failed: {proc.stderr.decode().strip()}")
    run("podman", "volume", "export", SYNAPSE_VOLUME, "--output", str(dest / "synapse-data.tar"))
    shutil.copy2(paths.stack_file, dest / "stack.json")

    manifest = {
        "created": stamp,
        "postgres_major": Stack.load(paths).postgres_major,
        "counts": counts,
        "files": {p.name: sha256(p) for p in sorted(dest.iterdir())},
    }
    (dest / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for p in dest.iterdir():
        p.chmod(0o600)


def prune(paths: Paths, keep: int) -> list[Path]:
    old = sorted(p for p in paths.backup_dir.iterdir() if p.is_dir())[:-keep]
    for p in old:
        shutil.rmtree(p)
    return old


def latest(paths: Paths) -> Path:
    dirs = sorted(p for p in paths.backup_dir.glob("*") if (p / "MANIFEST.json").exists())
    if not dirs:
        raise BackupError(f"no backups in {paths.backup_dir}")
    return dirs[-1]


# ---- verify -----------------------------------------------------------------------------


def check_files(backup_dir: Path) -> dict:
    manifest = json.loads((backup_dir / "MANIFEST.json").read_text())
    for name, digest in manifest["files"].items():
        if sha256(backup_dir / name) != digest:
            raise BackupError(f"{name} does not match its checksum; the backup is corrupt")
    # the signing key is what makes this server *this* server: a backup without it isn't restorable
    listing = run("tar", "-tf", str(backup_dir / "synapse-data.tar")).stdout
    if not any(line.rstrip().endswith("signing.key") for line in listing.splitlines()):
        raise BackupError("synapse-data.tar has no signing.key")
    return manifest


def verify(paths: Paths, backup_dir: Path) -> None:
    """Restore the dump into a throwaway Postgres and compare row counts with the manifest."""
    manifest = check_files(backup_dir)
    name = "matrix-verify-pg"
    run("podman", "rm", "-f", name, check=False)
    run("podman", "run", "-d", "--rm", "--name", name, "--network", "none", "--tmpfs", "/var/lib/postgresql/data",
        "-e", "POSTGRES_USER=synapse", "-e", "POSTGRES_PASSWORD=verify", "-e", "POSTGRES_DB=synapse",
        "-e", "POSTGRES_INITDB_ARGS=--encoding=UTF-8 --lc-collate=C --lc-ctype=C",
        postgres_image(manifest["postgres_major"]))
    try:
        for _ in range(60):
            # the image's init phase restarts the server once, so require two consecutive successes
            if all(run("podman", "exec", name, "pg_isready", "-U", "synapse", "-d", "synapse", check=False).returncode == 0
                   for _ in range(2)):
                break
            time.sleep(1)
        else:
            raise BackupError("throwaway Postgres never became ready")
        with (backup_dir / "db.dump").open("rb") as f:
            proc = subprocess.run(["podman", "exec", "-i", name, "pg_restore", "-U", "synapse", "-d", "synapse",
                                   "--no-owner", "--exit-on-error"], stdin=f, capture_output=True)
        if proc.returncode != 0:
            raise BackupError(f"pg_restore failed: {proc.stderr.decode().strip()}")
        restored = row_counts(name)
        if restored != manifest["counts"]:
            raise BackupError(f"row counts differ: backup said {manifest['counts']}, restore has {restored}")
    finally:
        run("podman", "rm", "-f", name, check=False)


# ---- restore ----------------------------------------------------------------------------


def systemctl(*args: str, check: bool = True) -> None:
    run("systemctl", "--user", *args, check=check)


def restore(paths: Paths, backup_dir: Path, restore_config: bool) -> None:
    verify(paths, backup_dir)  # never wipe a live database for a backup we haven't proven loads
    if restore_config:
        paths.config_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup_dir / "stack.json", paths.stack_file)
        paths.stack_file.chmod(0o600)
        render_all(Stack.load(paths), paths)
        systemctl("daemon-reload")
    systemctl("stop", "matrix-synapse", *EDGE, check=False)
    systemctl("start", PG)
    with (backup_dir / "db.dump").open("rb") as f:
        proc = subprocess.run(["podman", "exec", "-i", PG, "pg_restore", "-U", "synapse", "-d", "synapse",
                               "--clean", "--if-exists", "--no-owner"], stdin=f, capture_output=True)
    if proc.returncode != 0:
        raise BackupError(f"pg_restore failed: {proc.stderr.decode().strip()}")
    run("podman", "volume", "rm", "-f", SYNAPSE_VOLUME, check=False)
    run("podman", "volume", "create", SYNAPSE_VOLUME)
    run("podman", "volume", "import", SYNAPSE_VOLUME, str(backup_dir / "synapse-data.tar"))
    systemctl("start", "matrix-synapse", *EDGE)


# ---- postgres major upgrade --------------------------------------------------------------


def upgrade_postgres(paths: Paths, new_major: int) -> None:
    stack = Stack.load(paths)
    if new_major <= stack.postgres_major:
        raise BackupError(f"already on {stack.postgres_major}; Postgres cannot be downgraded")
    systemctl("stop", *EDGE, check=False)  # nothing may write while we dump
    dest = backup(paths)
    verify(paths, dest)
    counts = json.loads((dest / "MANIFEST.json").read_text())["counts"]

    systemctl("stop", "matrix-synapse", PG)
    old = dest / "postgres-data-pre-upgrade.tar"  # the way back
    run("podman", "volume", "export", PG_VOLUME, "--output", str(old))
    run("podman", "volume", "rm", PG_VOLUME)

    new = dataclasses.replace(stack, postgres_major=new_major)
    new.save(paths)
    render_all(new, paths)
    systemctl("daemon-reload")
    systemctl("start", PG)  # fresh volume: initdb with the new major
    for _ in range(60):
        if run("podman", "exec", PG, "pg_isready", "-U", "synapse", check=False).returncode == 0:
            break
        time.sleep(1)
    with (dest / "db.dump").open("rb") as f:
        proc = subprocess.run(["podman", "exec", "-i", PG, "pg_restore", "-U", "synapse", "-d", "synapse",
                               "--no-owner", "--exit-on-error"], stdin=f, capture_output=True)
    if proc.returncode != 0 or row_counts(PG) != counts:
        raise BackupError(
            f"upgrade to {new_major} failed ({proc.stderr.decode().strip() or 'row counts differ'}).\n"
            f"Roll back: set postgres_major back to {stack.postgres_major} in {paths.stack_file}, run `just render`, "
            f"`podman volume rm -f {PG_VOLUME} && podman volume create {PG_VOLUME} && "
            f"podman volume import {PG_VOLUME} {old}`, then `just up`."
        )
    systemctl("start", "matrix-synapse", *EDGE)


# ---- cli ---------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("backup", help="take a backup, verify it, prune old ones")
    b.add_argument("--keep", type=int, default=KEEP_DEFAULT)
    v = sub.add_parser("verify", help="prove a backup restores (default: the latest)")
    v.add_argument("path", nargs="?", type=Path)
    r = sub.add_parser("restore", help="replace the live database and Synapse data with a backup")
    r.add_argument("path", nargs="?", type=Path)
    r.add_argument("--config", action="store_true", help="also restore stack.json (new machine)")
    r.add_argument("--yes", action="store_true")
    u = sub.add_parser("upgrade-postgres", help="dump, recreate on a newer major, reload, verify")
    u.add_argument("major", type=int)
    args = p.parse_args(argv)

    paths = Paths()
    try:
        if args.cmd == "backup":
            dest = backup(paths)
            verify(paths, dest)
            gone = prune(paths, args.keep)
            print(f"backup {dest} verified; pruned {len(gone)} old")
        elif args.cmd == "verify":
            target = args.path or latest(paths)
            verify(paths, target)
            print(f"{target} restores cleanly")
        elif args.cmd == "restore":
            target = args.path or latest(paths)
            if not args.yes and input(f"Replace the live data with {target}? [y/N] ").lower() != "y":
                return 1
            restore(paths, target, args.config)
            print("restored")
        else:
            upgrade_postgres(paths, args.major)
            print(f"postgres now on {args.major}")
    except BackupError as e:
        print(e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

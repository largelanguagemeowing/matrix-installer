"""Stack configuration: the one authoritative description of an install."""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path

BOT_USER = "notifier"


@dataclass(frozen=True)
class Paths:
    # MATRIX_STACK_HOME relocates only our files (tests); $HOME also moves Podman's own storage.
    home: Path = field(default_factory=lambda: Path(os.environ.get("MATRIX_STACK_HOME") or Path.home()))

    @property
    def config_dir(self) -> Path:
        return self.home / ".config" / "matrix-stack"

    @property
    def conf_dir(self) -> Path:
        """Rendered config files mounted into containers."""
        return self.config_dir / "conf"

    @property
    def stack_file(self) -> Path:
        return self.config_dir / "stack.json"

    @property
    def quadlet_dir(self) -> Path:
        return self.home / ".config" / "containers" / "systemd" / "matrix-stack"

    @property
    def systemd_dir(self) -> Path:
        return self.home / ".config" / "systemd" / "user"

    @property
    def caddy_data_dir(self) -> Path:
        """Bind-mounted (not a named volume) so LiveKit can read Caddy's certificates and a path unit can watch them."""
        return self.home / ".local" / "share" / "matrix-stack" / "caddy-data"

    @property
    def backup_dir(self) -> Path:
        return self.home / ".local" / "share" / "matrix-stack" / "backups"

    @property
    def state_dir(self) -> Path:
        return self.home / ".local" / "state" / "matrix-stack"


@dataclass(frozen=True)
class Secrets:
    postgres_password: str
    registration_secret: str
    macaroon_secret: str
    form_secret: str
    livekit_key: str
    livekit_secret: str
    bot_password: str
    as_token: str  # lk-jwt-service application service
    hs_token: str

    @classmethod
    def generate(cls) -> Secrets:
        token = lambda: secrets.token_urlsafe(32)  # noqa: E731
        return cls(
            postgres_password=token(),
            registration_secret=token(),
            macaroon_secret=token(),
            form_secret=token(),
            livekit_key="API" + secrets.token_hex(6),
            livekit_secret=token(),
            bot_password=token(),
            as_token=token(),
            hs_token=token(),
        )


@dataclass(frozen=True)
class Stack:
    server_name: str  # the domain in user IDs: @alice:server_name
    matrix_host: str  # where Synapse (and the JWT service) is served
    chat_host: str  # where Pinniped is served
    rtc_host: str  # where LiveKit signalling is served
    acme_email: str
    admin_user: str
    serve_apex_wellknown: bool  # Caddy answers /.well-known on server_name itself
    secrets: Secrets
    postgres_major: int = 17  # bump only through `just postgres-upgrade`
    public_ipv4: str = ""  # advertised to call clients as LiveKit's media addresses
    public_ipv6: str = ""

    @property
    def bot_mxid(self) -> str:
        return f"@{BOT_USER}:{self.server_name}"

    @property
    def admin_mxid(self) -> str:
        return f"@{self.admin_user}:{self.server_name}"

    @property
    def hosts(self) -> tuple[str, ...]:
        """Every public DNS name the stack needs."""
        names = [self.matrix_host, self.chat_host, self.rtc_host]
        if self.serve_apex_wellknown:
            names.append(self.server_name)
        return tuple(dict.fromkeys(names))

    def save(self, paths: Paths) -> None:
        paths.config_dir.mkdir(parents=True, exist_ok=True)
        paths.config_dir.chmod(0o700)
        paths.stack_file.write_text(json.dumps(asdict(self), indent=2) + "\n")
        paths.stack_file.chmod(0o600)

    @classmethod
    def load(cls, paths: Paths) -> Stack:
        data = json.loads(paths.stack_file.read_text())
        data["secrets"] = Secrets(**data["secrets"])
        if data.pop("proxy", "bundled") != "bundled":
            raise ValueError("stack.json uses the removed external-Caddy mode; rerun `just setup`")
        for gone in ("upstream_bind", "turn_cert", "turn_key"):  # external-mode settings
            data.pop(gone, None)
        return cls(**data)

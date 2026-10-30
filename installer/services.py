"""The stack's units, in one place for the Justfile (via info.py), backups and the scanner."""

from __future__ import annotations

CORE = ["matrix-postgres", "matrix-synapse"]
EDGE = ["matrix-jwt", "matrix-livekit", "matrix-pinniped", "matrix-caddy"]
SERVICES = CORE + EDGE
CONTAINERS = SERVICES + ["matrix-netns"]
# Sockets, timers and the certificate watcher, enabled after the services start.
BACKGROUND_UNITS = ["matrix-caddy.socket", "matrix-scan.timer", "matrix-health.timer", "matrix-backup.timer",
                    "matrix-egress-refresh.timer", "matrix-livekit-cert.path"]

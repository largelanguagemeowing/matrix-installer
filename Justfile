# Matrix stack: Synapse + MatrixRTC (LiveKit) + Pinniped, as rootless Podman Quadlets.
set shell := ["bash", "-euo", "pipefail", "-c"]

# Keep in sync with installer/services.py (CORE, EDGE).
core := "matrix-postgres matrix-synapse"
edge := "matrix-jwt matrix-livekit matrix-pinniped matrix-caddy"
services := core + " " + edge

default:
    @just --list

# One command: wizard (all questions up front) -> start -> create your account -> verify -> first scan.
install: setup _prepare _start-core provision _start-rest
    just backup
    just check --wait 180 || echo 'Some checks failed (see above). Fix DNS/firewall, then rerun: just check'
    just scan --force

# Ask about your domain, check DNS/ports, write config. Flags pass through (see --help).
setup *args:
    python3 -m installer.wizard {{args}}

# Re-render Quadlets/config from the saved answers (after editing templates).
render:
    python3 -m installer.wizard --render-only

# Validate the generated Quadlet units with podman's own generator.
lint:
    /usr/lib/systemd/system-generators/podman-system-generator --user --dryrun >/dev/null

# Start the stack, or restart it to pick up re-rendered config (`just render && just up`).
up: _prepare _start-core _start-rest

_prepare: lint
    loginctl enable-linger "$USER"
    systemctl --user daemon-reload

# Database + homeserver first, so `provision` can run before the slow Pinniped build.
_start-core:
    systemctl --user restart {{core}}

_start-rest:
    systemctl --user restart {{edge}}
    systemctl --user enable --now $(python3 -m installer.info units)

down:
    systemctl --user stop {{services}}

status:
    systemctl --user --no-pager status {{services}} matrix-scan.timer | grep -E '^(●|○|×)|Active:'

# Follow application logs: `just logs` (all) or `just logs synapse`. (Container output is in the
# journal under CONTAINER_NAME; `journalctl -u` would only show Podman's lifecycle events.)
logs name="":
    journalctl --user -f $( [ -z "{{name}}" ] && python3 -m installer.info journal-args || echo "CONTAINER_NAME=matrix-{{name}}" )

# Create the admin account and the notifier bot.
provision:
    python3 -m installer.provision

# Add another (non-admin) user.
user name:
    python3 -m installer.provision --user {{name}}

# Probe the running stack from outside: TLS, well-known, calls, federation, admin API closed.
check *args:
    python3 -m installer.verify {{args}}

# Scan now; DMs you if something changed. `just scan --print` only prints.
scan *args:
    python3 -m installer.notify {{args}}

# Take a backup and prove it restores (also runs daily). Copy backups off this machine, encrypted.
backup:
    python3 -m installer.backup backup

# Re-prove that the newest (or a given) backup restores into a throwaway database.
backup-verify *path:
    python3 -m installer.backup verify {{path}}

# Replace the live data with a backup (newest by default). Add --config on a brand-new machine.
restore *args:
    python3 -m installer.backup restore {{args}}

# Dump, recreate on a newer Postgres major, reload, verify counts: `just postgres-upgrade 18`.
postgres-upgrade major:
    python3 -m installer.backup upgrade-postgres {{major}}

# Print current problems (what the 5-minute health timer would DM you).
health:
    python3 -m installer.notify --health --print

# Pull new images and restart the services whose image changed.
update:
    podman auto-update

# Prove containment: a stack container must be refused the LAN, the host and the metadata address.
egress-test:
    podman run --rm --network matrix docker.io/library/alpine:3 sh -c \
        'for t in 169.254.169.254:80 host.containers.internal:22 192.168.0.1:53; do \
           nc -w3 -z ${t%:*} ${t#*:} && echo "FAIL reachable: $t" || echo "ok blocked: $t"; done; \
         nc -w5 -z 1.1.1.1 443 && echo "ok internet reachable" || echo "FAIL internet unreachable"'
    python3 -m installer.egress --counters | grep counter

test:
    python3 -m unittest discover -s tests -v

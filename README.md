# matrix-installer

Rootless-Podman Quadlets for Synapse, MatrixRTC (LiveKit with TURN, lk-jwt-service as an application
service), the Pinniped web client and Caddy (automatic TLS), plus daily Trivy scans, verified backups
and health alerts that DM you on Matrix.

    just install     # wizard -> start -> create your account -> first verified backup -> checks

Scripted (no prompts): put the admin password on the first line of a file, then

    ADMIN_PASSWORD_FILE=pw.txt just install --yes --server-name example.org --email you@example.org --admin alice

Hostnames default to `matrix.`, `chat.` and `rtc.` under the server name; `just setup --help` lists every flag.
`just user bob --password-file bob.txt` adds a user the same way.

Day to day: `just check` · `just health` · `just backup` · `just restore` · `just update` · `just postgres-upgrade 18`

Requires podman >= 5.2, just, python3 >= 3.11 (stdlib only), x86_64, and DNS records for the matrix/chat/rtc hosts.
Published ports: 80/tcp, 443/tcp, 7881/tcp, 7882/udp, 3478/udp, 5349/tcp; Synapse publishes nothing.
Keep this checkout in place: the timers run `installer.*` from here.

- Config and secrets: `~/.config/matrix-stack/` (0700). Backups: `~/.local/share/matrix-stack/backups/` (contain secrets and the
  signing key: copy them off this machine encrypted).
- Containers cannot reach your LAN, loopback or this host (nftables in Podman's rootless netns; see `installer/egress.py`).
- IPv6: containers get NAT66 egress (federation with v6-only servers) and published ports accept v6. LiveKit advertises your
  public IPv4 and IPv6 as media addresses (`node_ip: v4,v6`); a 5-minute timer re-renders and restarts it if either changes.
- Client IPs: Caddy is socket-activated (`matrix-caddy.socket` opens 80/443 and 443/udp on the host), so it
  sees real client addresses; Podman's rootless port forwarder, which would replace them with the bridge gateway, is not
  used. Caddy discards client-supplied `X-Forwarded-For` and Synapse listens only for Caddy, so Synapse's per-IP limits work.
- Known limits: `:latest` image tags are not digest-pinned; an off-host backup copy is up to you.

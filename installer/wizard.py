"""Config wizard: ask about the domain, check DNS/ports, write config, render Quadlets."""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from . import checks
from .checks import Check, Status
from .config import Paths, Secrets, Stack
from .render import render_all, server_wellknown


TCP_PORTS = [80, 443, 7881, 5349]


def public_ports() -> str:
    lines = ["Ports to open in your firewall / router (nothing else is published):",
             "  80/tcp    HTTP (ACME challenges, redirect to HTTPS)",
             "  443/tcp   HTTPS: Pinniped, client API, federation, LiveKit signalling",
             "  7881/tcp  LiveKit media over TCP (fallback for UDP-hostile networks)",
             "  7882/udp  LiveKit media over UDP",
             "  3478/udp  TURN (calls from networks that block direct media)",
             "  5349/tcp  TURN over TLS"]
    lines += ["(IPv6: allow the same ports for IPv6 too; firewalld's default zone covers both families.)",
              "firewalld example:",
              f"  sudo firewall-cmd --permanent --add-port={{{','.join(map(str, TCP_PORTS))}}}/tcp --add-port={{7882,3478}}/udp && sudo firewall-cmd --reload"]
    return "\n".join(lines) + "\n"


def ask(prompt: str, default: str | None, assume_yes: bool) -> str:
    if assume_yes:
        if default is None:
            sys.exit(f"--yes: no default for {prompt!r}; pass it as a flag (see --help)")
        return default
    suffix = f" [{default}]" if default else ""
    while True:
        answer = input(f"{prompt}{suffix}: ").strip() or (default or "")
        if answer:
            return answer


def ask_bool(prompt: str, default: bool, assume_yes: bool) -> bool:
    if assume_yes:
        return default
    answer = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return default if not answer else answer.startswith("y")


def gather(args: argparse.Namespace, previous: Stack | None, ip4: str | None, ip6: str | None) -> Stack:
    yes = args.yes
    prev = previous

    def pick(flag: str | None, prompt: str, default: str | None) -> str:
        return flag or ask(prompt, default, yes)

    server_name = pick(args.server_name, "Matrix domain (the part after the colon in @you:domain)",
                       prev.server_name if prev else None).lower()
    matrix_host = pick(args.matrix_host, "Hostname for the homeserver", prev.matrix_host if prev else f"matrix.{server_name}")
    chat_host = pick(args.chat_host, "Hostname for the Pinniped web client", prev.chat_host if prev else f"chat.{server_name}")
    rtc_host = pick(args.rtc_host, "Hostname for LiveKit (calls)", prev.rtc_host if prev else f"rtc.{server_name}")
    email = pick(args.email, "Email for Let's Encrypt expiry notices", prev.acme_email if prev else None)
    admin = pick(args.admin, "Username for your first (admin) account", prev.admin_user if prev else None)

    serve_apex = False
    if server_name != matrix_host:
        if args.serve_apex is not None:
            serve_apex = args.serve_apex
        else:
            serve_apex = ask_bool(
                f"Does {server_name} point at this machine and should Caddy answer its /.well-known? "
                "(say no if the apex hosts a website elsewhere)",
                prev.serve_apex_wellknown if prev else False,
                yes,
            )
    return Stack(
        server_name=server_name,
        matrix_host=matrix_host,
        chat_host=chat_host,
        rtc_host=rtc_host,
        acme_email=email,
        admin_user=admin,
        serve_apex_wellknown=serve_apex,
        secrets=prev.secrets if prev else Secrets.generate(),  # reruns must keep existing secrets
        public_ipv4=args.public_ipv4 or ip4 or (prev.public_ipv4 if prev else ""),
        public_ipv6=args.public_ipv6 or ip6 or (prev.public_ipv6 if prev else ""),
    )


def preflight(stack: Stack, ip4: str | None, ip6: str | None) -> list[Check]:
    results = [checks.check_podman(), checks.check_architecture(), checks.check_unprivileged_ports()]
    results += [checks.check_dns(h, ip4, ip6) for h in stack.hosts]
    results += [checks.check_port_free(p) for p in TCP_PORTS] + [checks.check_port_free(p, "udp") for p in (7882, 3478)]
    results.append(checks.check_linger(getpass.getuser()))
    results.append(checks.check_journal())
    if stack.server_name != stack.matrix_host and not stack.serve_apex_wellknown:
        results.append(checks.check_wellknown_server(stack.server_name, stack.matrix_host))
    return results


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--server-name")
    p.add_argument("--matrix-host")
    p.add_argument("--chat-host")
    p.add_argument("--rtc-host")
    p.add_argument("--email")
    p.add_argument("--admin")
    p.add_argument("--serve-apex", action=argparse.BooleanOptionalAction, default=None)
    p.add_argument("--public-ipv4", help="media address to advertise (default: detected)")
    p.add_argument("--public-ipv6")
    p.add_argument("--yes", action="store_true", help="accept defaults instead of prompting")
    p.add_argument("--skip-checks", action="store_true")
    p.add_argument("--render-only", action="store_true", help="re-render from the saved stack.json")
    args = p.parse_args(argv)

    paths = Paths()
    previous = Stack.load(paths) if paths.stack_file.exists() else None
    if args.render_only:
        if previous is None:
            sys.exit("no saved config; run `just setup` first")
        stack = previous
    else:
        ip4, ip6 = checks.public_ipv4(), checks.public_ipv6()
        stack = gather(args, previous, args.public_ipv4 or ip4, args.public_ipv6 or ip6)
        if not args.skip_checks:
            results = preflight(stack, stack.public_ipv4 or None, stack.public_ipv6 or None)
            print(*results, sep="\n")
            if checks.has_failures(results) and not ask_bool("Checks failed. Continue anyway?", False, args.yes):
                return 1
        stack.save(paths)

    written = render_all(stack, paths)
    print(f"\nRendered {len(written)} files under {paths.config_dir} and {paths.quadlet_dir}")
    if stack.server_name != stack.matrix_host and not stack.serve_apex_wellknown:
        print(f"\nHost this at https://{stack.server_name}/.well-known/matrix/server:\n{json.dumps(server_wellknown(stack))}")
    print("\n" + public_ports())
    print("Next: `just install` (or `just up` + `just provision`).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

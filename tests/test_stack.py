import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from installer.checks import Status, check_dns, check_journal, reachable_per_family, check_unprivileged_ports
from installer.config import Paths, Secrets, Stack
from installer.backup import prune
from installer.notify import backup_problem, parse_inspect, format_health
from installer.publicip import sync
from installer.render import livekit_ip_config, postgres_data_mount
from installer.waitcert import cert_dir
from installer.notify import Finding, fingerprint, format_report, parse_pending, parse_trivy, plan_message
from installer import services
from installer.provision import read_password_file
from installer.wizard import ask
from installer.egress import ruleset
from installer.render import render_all

GENERATOR = Path("/usr/lib/systemd/system-generators/podman-system-generator")


def make_stack(**over) -> Stack:
    base = dict(
        server_name="example.com", matrix_host="matrix.example.com", chat_host="chat.example.com",
        rtc_host="rtc.example.com", acme_email="a@example.com", admin_user="alice",
        serve_apex_wellknown=True, secrets=Secrets.generate(),
    )
    return Stack(**{**base, **over})


class RenderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.paths = Paths(home=Path(self.tmp.name))

    def test_renders_everything_without_leftover_placeholders(self):
        files = render_all(make_stack(), self.paths)
        self.assertGreaterEqual(len(files), 28)
        for f in files:
            self.assertNotIn("${", f.read_text(), f.name)

    def test_secret_files_are_private(self):
        render_all(make_stack(), self.paths)
        self.assertEqual((self.paths.conf_dir / "postgres.env").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.paths.conf_dir.stat().st_mode & 0o777, 0o700)

    def test_apex_block_only_when_requested(self):
        render_all(make_stack(serve_apex_wellknown=False), self.paths)
        caddy = (self.paths.conf_dir / "Caddyfile").read_text()
        self.assertNotIn("example.com {", caddy.replace("matrix.example.com {", "").replace("chat.example.com {", "").replace("rtc.example.com {", ""))

    def test_admin_api_not_proxied_and_wellknown_advertises_livekit(self):
        render_all(make_stack(), self.paths)
        caddy = (self.paths.conf_dir / "Caddyfile").read_text()
        self.assertIn("@synapse path /_matrix/* /_synapse/client/*", caddy)
        self.assertNotIn("/_synapse/*", caddy)
        self.assertIn("https://matrix.example.com/livekit/jwt", caddy)
        self.assertIn('"m.server": "matrix.example.com:443"', caddy)

    def test_ssrf_containment(self):
        render_all(make_stack(), self.paths)
        q = self.paths.quadlet_dir
        net = lambda name: [l for l in (q / name).read_text().splitlines() if l.startswith("Network=")]
        self.assertEqual(net("matrix-postgres.container"), ["Network=matrix-db.network"])
        self.assertIn("Internal=true", (q / "matrix-db.network").read_text())
        self.assertEqual(net("matrix-jwt.container"), ["Network=matrix-jwt.network"])
        self.assertIn("alias=matrix.example.com,alias=rtc.example.com", " ".join(net("matrix-caddy.container")))
        hs = (self.paths.conf_dir / "homeserver.yaml").read_text()
        self.assertIn("url_preview_enabled: false", hs)
        for cidr in ("10.0.0.0/8", "169.254.0.0/16", "fc00::/7", "127.0.0.0/8"):
            self.assertIn(f"- {cidr}", hs)

    def test_jwt_can_resolve_every_name_it_validates_tokens_against(self):
        for apex in (True, False):
            with tempfile.TemporaryDirectory() as d:
                paths = Paths(home=Path(d))
                render_all(make_stack(serve_apex_wellknown=apex), paths)
                caddy = (paths.quadlet_dir / "matrix-caddy.container").read_text()
                jwt_net = [l for l in caddy.splitlines() if l.startswith("Network=matrix-jwt.network")][0]
                self.assertIn("alias=matrix.example.com", jwt_net)
                self.assertIn("alias=rtc.example.com", jwt_net)
                self.assertEqual("alias=example.com" in jwt_net, apex)
                # LiveKit's webhook URL must resolve on the network LiveKit is on
                self.assertIn("Network=matrix.network:alias=matrix.example.com", caddy)
                lk = (paths.conf_dir / "livekit.yaml").read_text()
                self.assertIn("https://matrix.example.com/livekit/jwt/sfu_webhook", lk)

    def test_pinniped_config_is_valid_json(self):
        render_all(make_stack(), self.paths)
        cfg = json.loads((self.paths.conf_dir / "pinniped-config.json").read_text())
        self.assertEqual(cfg["homeserverList"], ["example.com"])

    def test_stack_roundtrip_keeps_secrets(self):
        stack = make_stack()
        stack.save(self.paths)
        self.assertEqual(Stack.load(self.paths), stack)

    @unittest.skipUnless(GENERATOR.exists(), "podman quadlet generator not installed")
    def test_quadlets_pass_podman_generator(self):
        render_all(make_stack(), self.paths)
        env = {**os.environ, "HOME": self.tmp.name, "XDG_CONFIG_HOME": f"{self.tmp.name}/.config"}
        proc = subprocess.run([str(GENERATOR), "--user", "--dryrun"], env=env, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("error", proc.stderr.lower())
        for unit in ("matrix-synapse", "matrix-pinniped", "matrix-caddy"):
            self.assertIn(f"{unit}.service", proc.stdout)


class OperationsTest(unittest.TestCase):
    def test_container_health_parsing(self):
        self.assertIsNone(parse_inspect("c", "running|healthy"))
        self.assertIsNone(parse_inspect("c", "running|"))  # no health check defined
        self.assertEqual(parse_inspect("c", "running|unhealthy"), "c is unhealthy")
        self.assertEqual(parse_inspect("c", "exited|"), "c is exited")
        self.assertEqual(parse_inspect("c", "|"), "c is missing")

    def test_backup_freshness(self):
        self.assertIn("no backup", backup_problem(None, 1000))
        self.assertIsNone(backup_problem(1000, 1000 + 35 * 3600))
        self.assertIn("37h old", backup_problem(1000, 1000 + 37 * 3600))

    def test_recovery_message_when_no_problems(self):
        self.assertIn("recovered", format_health([]))
        self.assertIn("• x", format_health(["x"]))

    def test_postgres_18_needs_the_parent_mount(self):
        self.assertEqual(postgres_data_mount(17), "/var/lib/postgresql/data")
        self.assertEqual(postgres_data_mount(18), "/var/lib/postgresql")

    def test_prune_keeps_the_newest(self):
        with tempfile.TemporaryDirectory() as d:
            paths = Paths(home=Path(d))
            for name in ("20260101T000000Z", "20260102T000000Z", "20260103T000000Z"):
                (paths.backup_dir / name).mkdir(parents=True)
            self.assertEqual([p.name for p in prune(paths, 2)], ["20260101T000000Z"])
            self.assertEqual(sorted(p.name for p in paths.backup_dir.iterdir()), ["20260102T000000Z", "20260103T000000Z"])

    def test_livekit_reads_the_certificate_caddy_writes(self):
        with tempfile.TemporaryDirectory() as d:
            paths = Paths(home=Path(d))
            render_all(make_stack(), paths)
            lk = (paths.quadlet_dir / "matrix-livekit.container").read_text()
            host_dir = cert_dir(paths.caddy_data_dir, "rtc.example.com")
            self.assertIn(f"Volume={host_dir}:/certs:ro", lk)  # same path waitcert and the mount agree on
            self.assertIn("PathChanged=" + str(host_dir / "rtc.example.com.crt"),
                          (paths.systemd_dir / "matrix-livekit-cert.path").read_text())
            self.assertIn("acme_ca https://acme-v02.api.letsencrypt.org/directory", (paths.conf_dir / "Caddyfile").read_text())
            for port in ("3478:3478/udp", "5349:5349/tcp"):
                self.assertIn(port, lk)

    def test_jwt_homeserver_override_is_a_full_url(self):
        # found on a real host: a bare hostname here makes every membership check fail, so calls never start
        with tempfile.TemporaryDirectory() as d:
            paths = Paths(home=Path(d)); render_all(make_stack(), paths)
            env = (paths.conf_dir / "jwt.env").read_text()
            self.assertIn("LIVEKIT_CS_API_URL_OVERRIDES=example.com=https://matrix.example.com\n", env)

    def test_jwt_runs_as_application_service(self):
        with tempfile.TemporaryDirectory() as d:
            paths = Paths(home=Path(d))
            render_all(make_stack(), paths)
            env = (paths.conf_dir / "jwt.env").read_text()
            self.assertIn("LIVEKIT_AS_REGISTRATION_FILE=", env)
            reg = (paths.conf_dir / "lk-jwt-registration.yaml").read_text()
            self.assertIn("proxy_url: \"http://matrix-jwt:8080\"", reg)
            hs = (paths.conf_dir / "homeserver.yaml").read_text()
            self.assertIn("msc4512_enabled: true", hs)
            self.assertIn("/config/lk-jwt-registration.yaml", hs)


class UnitListTest(unittest.TestCase):
    def test_only_existing_units_are_enabled(self):
        with tempfile.TemporaryDirectory() as d:
            paths = Paths(home=Path(d)); render_all(make_stack(), paths)
            for unit in services.BACKGROUND_UNITS:
                self.assertTrue((paths.systemd_dir / unit).exists(), f"{unit} would be enabled but was not rendered")
            for name in services.SERVICES:
                self.assertTrue((paths.quadlet_dir / f"{name}.container").exists(), name)

    def test_old_bundled_config_still_loads(self):
        with tempfile.TemporaryDirectory() as d:
            paths = Paths(home=Path(d)); make_stack().save(paths)
            data = json.loads(paths.stack_file.read_text())
            paths.stack_file.write_text(json.dumps({**data, "proxy": "bundled", "upstream_bind": "127.0.0.1",
                                                    "turn_cert": "", "turn_key": ""}))
            self.assertEqual(Stack.load(paths).server_name, "example.com")

    def test_old_external_config_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            paths = Paths(home=Path(d)); make_stack().save(paths)
            data = json.loads(paths.stack_file.read_text())
            paths.stack_file.write_text(json.dumps({**data, "proxy": "external"}))
            with self.assertRaises(ValueError):
                Stack.load(paths)


class IntegrationRegressionTest(unittest.TestCase):
    """Bugs only a real run of the generated containers revealed."""

    def test_jwt_health_check_uses_exec_form_because_the_image_has_no_shell(self):
        with tempfile.TemporaryDirectory() as d:
            paths = Paths(home=Path(d)); render_all(make_stack(), paths)
            self.assertIn("HealthCmd=CMD /lk-jwt-service-healthcheck", (paths.quadlet_dir / "matrix-jwt.container").read_text())

    def test_synapse_can_write_its_signing_key_on_a_fresh_rootless_volume(self):
        with tempfile.TemporaryDirectory() as d:
            paths = Paths(home=Path(d)); render_all(make_stack(), paths)
            unit = (paths.quadlet_dir / "matrix-synapse.container").read_text()
            self.assertIn("Environment=UID=0", unit)
            self.assertIn("Environment=GID=0", unit)


class ClientIpTest(unittest.TestCase):
    def render(self, d):
        paths = Paths(home=Path(d))
        render_all(make_stack(), paths)
        return paths

    def test_synapse_is_only_reachable_by_caddy(self):
        with tempfile.TemporaryDirectory() as d:
            paths = self.render(d)
            unit = (paths.quadlet_dir / "matrix-synapse.container").read_text()
            self.assertNotIn("PublishPort", unit)  # nothing on the host can spoof X-Forwarded-For
            self.assertIn("Network=matrix.network:ip=10.89.201.10", unit)
            self.assertIn("http://10.89.201.10:8008/health", unit)
            hs = (paths.conf_dir / "homeserver.yaml").read_text()
            self.assertIn('bind_addresses: ["10.89.201.10"]', hs)
            self.assertIn("x_forwarded: true", hs)
            self.assertIn("reverse_proxy 10.89.201.10:8008", (paths.conf_dir / "Caddyfile").read_text())
            self.assertIn("Subnet=10.89.201.0/24", (paths.quadlet_dir / "matrix.network").read_text())

    def test_per_ip_login_limits_stay_default(self):
        with tempfile.TemporaryDirectory() as d:
            hs = (self.render(d).conf_dir / "homeserver.yaml").read_text()
            self.assertNotIn("rc_login:", hs)  # Caddy sees real addresses, so no shared-IP relaxation

    def test_bundled_caddy_is_socket_activated(self):
        with tempfile.TemporaryDirectory() as d:
            paths = Paths(home=Path(d)); render_all(make_stack(serve_apex_wellknown=True), paths)
            caddy = (paths.quadlet_dir / "matrix-caddy.container").read_text()
            self.assertNotIn("PublishPort=", caddy)  # the forwarder would hide client addresses
            self.assertIn("matrix-caddy.socket", caddy)
            sock = (paths.systemd_dir / "matrix-caddy.socket").read_text()
            self.assertEqual(["ListenStream=80", "ListenStream=443", "ListenDatagram=443"],
                             [l for l in sock.splitlines() if l.startswith("Listen")])  # fd/3, fd/4, fdgram/5
            self.assertEqual(4, (paths.conf_dir / "Caddyfile").read_text().count("\timport listen"))  # matrix, chat, rtc, apex
            self.assertIn("matrix-caddy.socket", services.BACKGROUND_UNITS)


class LoggingTest(unittest.TestCase):
    def test_every_container_logs_to_journald_explicitly(self):
        with tempfile.TemporaryDirectory() as d:
            paths = Paths(home=Path(d))
            render_all(make_stack(), paths)
            units = sorted(paths.quadlet_dir.glob("*.container"))
            self.assertEqual(len(units), 7)
            for unit in units:
                self.assertIn("LogDriver=journald", unit.read_text(), unit.name)

    def test_volatile_journal_is_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(check_journal(Path(d)).status, Status.OK)
            self.assertEqual(check_journal(Path(d) / "missing").status, Status.WARN)


class Ipv6Test(unittest.TestCase):
    def test_livekit_advertises_one_address_per_family(self):
        both = make_stack(public_ipv4="203.0.113.7", public_ipv6="2001:db8::7")
        self.assertEqual(livekit_ip_config(both), "use_external_ip: false\n  node_ip: \"203.0.113.7,2001:db8::7\"")
        self.assertIn("node_ip: \"203.0.113.7\"\n", livekit_ip_config(make_stack(public_ipv4="203.0.113.7")) + "\n")
        self.assertNotIn("2001", livekit_ip_config(make_stack(public_ipv4="203.0.113.7")))
        # found on a real host: an address ending in "::" unquoted is a YAML mapping key, and LiveKit won't start
        self.assertTrue(livekit_ip_config(make_stack(public_ipv6="2001:db8:2:3::")).endswith('node_ip: "2001:db8:2:3::"'))
        self.assertEqual(livekit_ip_config(make_stack()), "use_external_ip: true")  # nothing detected: fall back

    def test_rendered_livekit_config_carries_both_addresses(self):
        with tempfile.TemporaryDirectory() as d:
            paths = Paths(home=Path(d))
            render_all(make_stack(public_ipv4="203.0.113.7", public_ipv6="2001:db8::7"), paths)
            text = (paths.conf_dir / "livekit.yaml").read_text()
            self.assertIn("  use_external_ip: false\n  node_ip: \"203.0.113.7,2001:db8::7\"\n", text)

    def test_container_networks_are_ipv6_enabled(self):
        with tempfile.TemporaryDirectory() as d:
            paths = Paths(home=Path(d))
            render_all(make_stack(), paths)
            for net in ("matrix.network", "matrix-jwt.network"):
                self.assertIn("IPv6=true", (paths.quadlet_dir / net).read_text(), net)
            # the DB network stays internal and v4-only: nothing there needs a route out
            self.assertNotIn("IPv6", (paths.quadlet_dir / "matrix-db.network").read_text())

    def test_sync_rewrites_and_reports_only_real_changes(self):
        with tempfile.TemporaryDirectory() as d:
            paths = Paths(home=Path(d))
            stack = make_stack(public_ipv4="203.0.113.7", public_ipv6="2001:db8::7")
            stack.save(paths)
            render_all(stack, paths)
            self.assertFalse(sync(paths, "203.0.113.7", "2001:db8::7"))
            self.assertFalse(sync(paths, None, None))  # failed lookups never wipe a known address
            self.assertEqual(Stack.load(paths).public_ipv6, "2001:db8::7")
            self.assertTrue(sync(paths, "198.51.100.9", None))
            self.assertIn("node_ip: \"198.51.100.9,2001:db8::7\"", (paths.conf_dir / "livekit.yaml").read_text())


class EgressTest(unittest.TestCase):
    HOST = ["192.168.1.5", "2001:db8::5"]

    def test_ruleset_blocks_private_space_and_the_host(self):
        text = ruleset(self.HOST)
        for needle in ("192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8", "fc00::/7",
                       "192.168.1.5", "2001:db8::5", "hook forward"):
            self.assertIn(needle, text)

    def test_established_replies_accepted_before_any_block(self):
        text = ruleset(self.HOST)
        self.assertLess(text.index("established,related"), text.index("admin-prohibited"))

    @unittest.skipUnless(shutil.which("nft") and shutil.which("unshare"), "nft/unshare missing")
    def test_ruleset_is_valid_nft_syntax(self):
        with tempfile.NamedTemporaryFile("w", suffix=".nft") as f:
            f.write(ruleset(self.HOST)); f.flush()
            proc = subprocess.run(["unshare", "-Urn", "nft", "-c", "-f", f.name], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_every_routable_container_waits_for_the_filter(self):
        with tempfile.TemporaryDirectory() as d:
            paths = Paths(home=Path(d))
            render_all(make_stack(), paths)
            for name in ("synapse", "jwt", "livekit", "pinniped", "caddy"):
                unit = (paths.quadlet_dir / f"matrix-{name}.container").read_text()
                self.assertIn("Requires=matrix-egress.service", unit, name)
                self.assertIn("After=matrix-egress.service", unit, name)
            # postgres sits on an Internal network and has no route out to filter
            self.assertIn("Internal=true", (paths.quadlet_dir / "matrix-db.network").read_text())


TRIVY = {"Results": [{"Vulnerabilities": [
    {"VulnerabilityID": "CVE-1", "PkgName": "openssl", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "CRITICAL"},
    {"VulnerabilityID": "CVE-2", "PkgName": "zlib", "InstalledVersion": "1", "Severity": "HIGH"},  # no fix
    {"VulnerabilityID": "CVE-3", "PkgName": "curl", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "LOW"},
]}]}


class NotifyTest(unittest.TestCase):
    def test_no_message_when_nothing_changed(self):
        f = parse_trivy("img", TRIVY)
        self.assertIsNone(plan_message(f, [], fingerprint(f, [])))
        self.assertIsNone(plan_message([], [], ""))

    def test_all_clear_only_after_previous_problems(self):
        f = parse_trivy("img", TRIVY)
        self.assertIn("up to date", plan_message([], [], fingerprint(f, [])))
        self.assertIn("just update", plan_message(f, [], ""))

    def test_failed_scans_are_never_reported_as_clean(self):
        import subprocess as sp
        from unittest import mock
        from installer import notify
        with mock.patch.object(notify.subprocess, "run", return_value=sp.CompletedProcess([], 1, "", "boom")):
            with self.assertRaises(RuntimeError):
                notify.pending_updates()
            with self.assertRaises(RuntimeError):
                notify.scan_image("img")

    def test_only_fixable_high_critical_are_kept(self):
        self.assertEqual([f.cve for f in parse_trivy("img", TRIVY)], ["CVE-1"])

    def test_clean_report_has_no_results_key(self):
        self.assertEqual(parse_trivy("img", {}), [])

    def test_pending_parsed_from_auto_update(self):
        out = "matrix-synapse.service\tghcr.io/x/synapse:latest\tpending\nmatrix-caddy.service\tcaddy\tfalse\n"
        self.assertEqual(parse_pending(out), ["ghcr.io/x/synapse:latest"])

    def test_fingerprint_stable_and_empty_when_clean(self):
        f = parse_trivy("img", TRIVY)
        self.assertEqual(fingerprint(f, []), fingerprint(list(reversed(f)), []))
        self.assertEqual(fingerprint([], []), "")
        self.assertNotEqual(fingerprint(f, []), fingerprint(f, ["new"]))

    def test_report_mentions_update_command_and_truncates(self):
        many = [Finding("img", f"CVE-{i}", "p", "1", "2", "HIGH") for i in range(40)]
        text = format_report(many, ["img"])
        self.assertIn("just update", text)
        self.assertIn("and 25 more", text)


class ScriptedInstallTest(unittest.TestCase):
    def test_password_file_takes_the_first_line_only(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt") as f:
            f.write("correct horse battery\nignored\n"); f.flush()
            self.assertEqual(read_password_file(f.name), "correct horse battery")

    def test_short_or_missing_password_file_is_refused(self):
        with tempfile.NamedTemporaryFile("w") as f:
            f.write("short\n"); f.flush()
            with self.assertRaises(SystemExit):
                read_password_file(f.name)
        with self.assertRaises(SystemExit):
            read_password_file("/nonexistent/pw.txt")

    def test_yes_without_a_required_value_exits_instead_of_prompting(self):
        with self.assertRaises(SystemExit) as cm:
            ask("Email for Let's Encrypt expiry notices", None, assume_yes=True)
        self.assertIn("pass it as a flag", str(cm.exception))
        self.assertEqual(ask("Hostname", "matrix.example.com", assume_yes=True), "matrix.example.com")


class ChecksTest(unittest.TestCase):
    def _dns(self, records, ip4, ip6):
        import socket
        orig = socket.getaddrinfo
        socket.getaddrinfo = lambda *a, **k: [
            (socket.AF_INET6 if ":" in r else socket.AF_INET, 0, 0, "", (r, 0)) for r in records
        ]
        try:
            return check_dns("h", ip4, ip6)
        finally:
            socket.getaddrinfo = orig

    def test_dns_a_record_must_match(self):
        self.assertEqual(self._dns(["203.0.113.9"], "198.51.100.1", None).status, Status.FAIL)
        self.assertEqual(self._dns(["203.0.113.9"], "203.0.113.9", None).status, Status.OK)

    def test_dns_aaaa_must_match_or_be_absent(self):
        both = ["203.0.113.9", "2001:db8::1"]
        self.assertEqual(self._dns(both, "203.0.113.9", "2001:db8::1").status, Status.OK)
        self.assertEqual(self._dns(both, "203.0.113.9", "2001:db8::2").status, Status.FAIL)  # stale AAAA
        self.assertEqual(self._dns(both, "203.0.113.9", None).status, Status.FAIL)  # AAAA but no IPv6 here

    def test_dns_suggests_aaaa_when_host_has_ipv6(self):
        check = self._dns(["203.0.113.9"], "203.0.113.9", "2001:db8::1")
        self.assertEqual(check.status, Status.OK)
        self.assertIn("add AAAA", check.detail)

    def test_reachable_per_family_handles_ipv6_sockaddr(self):
        import socket
        with socket.socket() as srv:
            srv.bind(("127.0.0.1", 0)); srv.listen()
            results = reachable_per_family("localhost", srv.getsockname()[1])
        by_name = {c.name.rsplit(" ", 1)[1]: c for c in results}
        self.assertEqual(by_name["IPv4"].status, Status.OK)
        if "IPv6" in by_name:  # localhost also resolves to ::1, where nothing listens
            self.assertEqual(by_name["IPv6"].status, Status.FAIL)

    def test_unprivileged_port_sysctl(self):
        with tempfile.NamedTemporaryFile("w") as f:
            f.write("1024\n"); f.flush()
            self.assertEqual(check_unprivileged_ports(Path(f.name)).status, Status.FAIL)
            Path(f.name).write_text("80\n")
            self.assertEqual(check_unprivileged_ports(Path(f.name)).status, Status.OK)


if __name__ == "__main__":
    unittest.main()

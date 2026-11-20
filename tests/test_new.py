"""Behavior added in the standalone package: kickout, TLS pinning, cert, config, CLI contract."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from helpers import (
    ALEX,
    API_KEY,
    DEN_IP,
    NOW,
    OFFICE_IP,
    PATIO_IP,
    SAM,
    SHOP_IP,
    FakeController,
    FakeSSH,
    make_env,
    run,
    unquote_toon,
)
from unifi_axi import _version, api, cli, config
from unifi_axi.commands import cert

ROOT = Path(__file__).parents[1]


def kick_output(dmesg: list[str], log: list[str], uptime: str = "87771.20") -> str:
    head = [f"EPOCH {NOW}", "DATE 2026-11-19 19:02:51", f"UPTIME {uptime}",
            "FIRST Wed Nov 18 17:20:01 2026 user.notice syslog: start",
            f"DMESG_COUNT {len(dmesg)}", f"LOG_COUNT {len(log)}"]
    return "\n".join(head + ["---DMESG", *dmesg, "---LOG", *log]) + "\n"


def kick_line(mac: str, ts: str = "Thu Nov 19 09:30:00 2026") -> str:
    return (f"{ts} kern.warn kernel: wlan: [0:W:ANY] ol_peer_sta_kickout_event_handler: Station {mac} "
            "kicked out reason: Excessive Retries (1), associd 3")


def dmesg_line(mac: str) -> str:
    return (f"[ 8123.456] wlan: [0:W:ANY] ol_peer_sta_kickout_event_handler: Station {mac} kicked out "
            "reason: Excessive Retries (1), associd 3")


class KickoutTests(unittest.TestCase):
    def test_counts_per_ap_top_macs_with_names_and_uptime(self):
        outputs = {OFFICE_IP: kick_output([dmesg_line(ALEX)] * 2, [kick_line(ALEX)] * 3 + [kick_line(SAM)]),
                   DEN_IP: kick_output([], [kick_line(ALEX)]),
                   PATIO_IP: kick_output([], []), SHOP_IP: kick_output([], [])}
        code, out = run(["kickout"], ssh_fake=FakeSSH(outputs))
        self.assertEqual(code, 0, out)
        self.assertIn("kickout: 2 dmesg kicks, 5 'Excessive Retries' log lines on 4/4 APs read", out)
        self.assertIn("aps[4]{ap,dmesg_kicks,log_retries,log_from,uptime}:", out)
        self.assertIn("AP Office,2,4,11/18 17:20,1d0h", out)
        self.assertIn(f"Alex iPhone,{ALEX},4,AP Den/AP Office", out)
        self.assertIn(f"Sam iPhone,{SAM},1,AP Office", out)
        self.assertIn("help: unifi-axi client <mac> --since 24h", out)

    def test_unreachable_ap_is_partial_exit_1_and_empty_is_definitive(self):
        outputs = {ip: kick_output([], []) for ip in (OFFICE_IP, DEN_IP, SHOP_IP)}
        code, out = run(["kickout"], ssh_fake=FakeSSH(outputs, timeouts={PATIO_IP}))
        self.assertEqual(code, 1, out)
        self.assertIn("unreachable[1]{ap,reason}:", out)
        self.assertIn("AP Patio,ssh timeout 10s", out)
        self.assertIn("top_clients: 0 kicked stations in the lines read", out)

    def test_command_is_read_only_and_never_runs_iwpriv(self):
        from unifi_axi import ssh
        self.assertNotIn("iwpriv", ssh.KICKOUT_COMMAND)
        self.assertTrue(ssh.KICKOUT_COMMAND.rstrip().endswith(f"echo {ssh.END_MARKER}"))
        fake = FakeSSH({ip: kick_output([], []) for ip in (OFFICE_IP, DEN_IP, PATIO_IP, SHOP_IP)})
        controller = FakeController()
        run(["kickout", "office"], ssh_fake=fake, controller=controller)
        self.assertEqual(len(fake.calls), 1)
        self.assertTrue(all(m == "GET" for m, _, _ in controller.calls))


# --------------------------------------------------------------------------
# TLS pinning. FakeConn replaces http.client.HTTPSConnection inside api.

LEAF = b"synthetic-leaf-certificate-der"


class FakeConn:
    instances: list = []

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.context = host, port, context
        self.requests: list = []
        self.sock = None
        FakeConn.instances.append(self)

    def connect(self):
        if self.context.verify_mode == ssl.CERT_REQUIRED:
            raise ssl.SSLCertVerificationError("self-signed certificate")
        self.sock = mock.Mock()
        self.sock.getpeercert.return_value = FakeConn.der

    def request(self, method, path, body=None, headers=None):
        self.requests.append((method, path, headers))

    def getresponse(self):
        resp = mock.Mock(status=200)
        resp.read.return_value = json.dumps({"data": [], "meta": {"rc": "ok"}}).encode()
        return resp

    def close(self):
        pass


class PinTests(unittest.TestCase):
    def setUp(self):
        FakeConn.instances = []
        FakeConn.der = LEAF
        patcher = mock.patch("http.client.HTTPSConnection", FakeConn)
        patcher.start()
        self.addCleanup(patcher.stop)

    def request(self, pin: str | None):
        config.set_active(config.Config(url="https://192.0.2.1", api_key=API_KEY, cert_sha256=pin))
        return api.http_request("GET", "/proxy/network/api/s/default/stat/device")

    def test_pin_match_sends_the_request_with_the_key(self):
        payload, err = self.request(hashlib.sha256(LEAF).hexdigest())
        self.assertIsNone(err)
        conn = FakeConn.instances[0]
        self.assertEqual(conn.context.verify_mode, ssl.CERT_NONE)
        self.assertEqual(len(conn.requests), 1)
        self.assertEqual(conn.requests[0][2]["X-API-KEY"], API_KEY)

    def test_pin_mismatch_refuses_before_any_request_carries_the_key(self):
        payload, err = self.request("ab" * 32)
        self.assertIsNone(payload)
        self.assertEqual(err.kind, "pin")
        self.assertIn("certificate pin mismatch", err)
        self.assertIn("nothing sent", err)
        self.assertEqual([c.requests for c in FakeConn.instances], [[]])

    def test_no_pin_and_no_insecure_verifies_the_chain(self):
        payload, err = self.request(None)
        self.assertEqual(err.kind, "tls")
        self.assertIn("UNIFI_CERT_SHA256", err)
        self.assertEqual(FakeConn.instances[0].requests, [])

    def test_mismatch_through_the_cli_is_a_structured_error_exit_1_and_no_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = make_env(tmp, UNIFI_CERT_SHA256="AB:" * 31 + "AB")
            with mock.patch.dict(os.environ, env, clear=True):
                import contextlib
                import io
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = cli.main(["aps"])
        self.assertEqual(code, 1, out.getvalue())
        self.assertIn("error: stat/device failed: certificate pin mismatch", unquote_toon(out.getvalue()))
        self.assertEqual(len(FakeConn.instances), 1)  # a pin failure is not retried
        self.assertEqual(FakeConn.instances[0].requests, [])


def der(tag: int, body: bytes) -> bytes:
    n = len(body)
    length = bytes([n]) if n < 128 else bytes([0x81, n]) if n < 256 else bytes([0x82, n >> 8, n & 0xFF])
    return bytes([tag]) + length + body


def synthetic_cert() -> bytes:
    def name(cn: str) -> bytes:
        return der(0x30, der(0x31, der(0x30, der(0x06, b"\x55\x04\x03") + der(0x0C, cn.encode()))))
    validity = der(0x30, der(0x17, b"250101000000Z") + der(0x17, b"350101000000Z"))
    tbs = der(0x30, der(0xA0, der(0x02, b"\x02")) + der(0x02, b"\x01") + der(0x30, der(0x06, b"\x2a\x86\x48"))
              + name("Example CA") + validity + name("unifi.example") + der(0x30, b""))
    return der(0x30, tbs + der(0x30, der(0x06, b"\x2a")) + der(0x03, b"\x00\x01"))


class CertCommandTests(unittest.TestCase):
    def setUp(self):
        FakeConn.instances = []
        FakeConn.der = synthetic_cert()
        patcher = mock.patch("http.client.HTTPSConnection", FakeConn)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_cert(self, **env_extra):
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as tmp:
            env = make_env(tmp, **env_extra)
            env.pop("UNIFI_API_KEY")  # cert needs no key and sends none
            out = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(out), \
                    mock.patch("unifi_axi.clock.now_ts", lambda: NOW):
                code = cli.main(["cert"])
        return code, unquote_toon(out.getvalue())

    def test_prints_subject_issuer_expiry_fingerprint_and_pin_line_without_a_request(self):
        code, out = self.run_cert()
        self.assertEqual(code, 0, out)
        digest = api.colon_hex(hashlib.sha256(FakeConn.der).hexdigest())
        self.assertIn("cert: https://192.0.2.1  chain_verified=no (self-signed or unknown CA)", out)
        self.assertIn("subject: CN=unifi.example", out)
        self.assertIn("issuer: CN=Example CA", out)
        self.assertIn("valid: 2025-01-01..2035-01-01 UTC (expires in", out)
        self.assertIn(f"sha256: {digest}", out)
        self.assertIn(f"  export UNIFI_CERT_SHA256={digest}", out)
        self.assertIn("openssl s_client -connect 192.0.2.1:443", out)
        self.assertTrue(all(c.requests == [] for c in FakeConn.instances))

    def test_reports_a_configured_pin_mismatch_with_exit_1(self):
        code, out = self.run_cert(UNIFI_CERT_SHA256="ab" * 32)
        self.assertEqual(code, 1, out)
        self.assertIn("pin: MISMATCH", out)
        code, out = self.run_cert(UNIFI_CERT_SHA256=hashlib.sha256(FakeConn.der).hexdigest().upper())
        self.assertEqual(code, 0, out)
        self.assertIn("pin: UNIFI_CERT_SHA256 matches this certificate", out)

    def test_der_reader_parses_the_synthetic_certificate(self):
        info = cert.parse_certificate(synthetic_cert())
        self.assertEqual((info["subject"], info["issuer"]), ("CN=unifi.example", "CN=Example CA"))


class ConfigTests(unittest.TestCase):
    def test_fingerprint_accepts_colon_or_plain_hex_in_any_case(self):
        plain = "0123456789abcdef" * 4
        colon = ":".join(plain[i:i + 2] for i in range(0, 64, 2)).upper()
        for text in (plain, plain.upper(), colon, f"sha256 Fingerprint={colon}"):
            self.assertEqual(config.normalize_fingerprint(text.replace("sha256 F", "sha256F")), plain, text)
        with self.assertRaises(config.ConfigError):
            config.normalize_fingerprint("ab:cd")

    def test_precedence_flag_over_env_over_file_and_flat_parser(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text('url = "https://198.51.100.7"\nsite = "lab"\nroaming_ssids = ["A", "B"]\n'
                            "drop_baseline_per_day = 12\ninsecure = true\n")
            env = {"UNIFI_AXI_CONFIG": str(path), "UNIFI_API_KEY": API_KEY}
            cfg = config.load(env=env)
            self.assertEqual((cfg.url, cfg.site, cfg.roaming_ssids, cfg.drop_baseline_per_day, cfg.insecure),
                             ("https://198.51.100.7", "lab", ("A", "B"), 12.0, True))
            self.assertEqual(cfg.legacy_api, "/proxy/network/api/s/lab")
            self.assertTrue(cfg.warnings)
            cfg = config.load(env={**env, "UNIFI_URL": "https://192.0.2.9"}, cert_sha256="cd" * 32)
            self.assertEqual((cfg.url, cfg.cert_sha256, cfg.insecure), ("https://192.0.2.9", "cd" * 32, False))
            self.assertEqual(config.parse_flat_toml(path.read_text())["roaming_ssids"], ["A", "B"])

    def test_bad_config_is_refused_with_help(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            for text, needle in (('api_key = "x"\n', "api_key"), ('colour = "red"\n', "unknown keys")):
                path.write_text(text)
                with self.assertRaises(config.ConfigError) as ctx:
                    config.load(env={"UNIFI_AXI_CONFIG": str(path)})
                self.assertIn(needle, str(ctx.exception))
            for env, needle in (({"UNIFI_URL": "http://192.0.2.1"}, "https"), ({"UNIFI_SITE": "a/b"}, "UNIFI_SITE")):
                with self.assertRaises(config.ConfigError) as ctx:
                    config.load(env={"UNIFI_AXI_CONFIG": str(path) + ".none", **env})
                self.assertIn(needle, str(ctx.exception))
            keyfile = Path(tmp) / "key"
            keyfile.write_text(API_KEY + "\n")
            cfg = config.load(api_key_file=str(keyfile), env={"UNIFI_AXI_CONFIG": str(path) + ".none"})
            self.assertEqual(cfg.api_key, API_KEY)

    def test_missing_key_home_view_still_identifies_the_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = make_env(tmp)
            env.pop("UNIFI_API_KEY")
            code, out = run([], env=env)
        self.assertEqual(code, 2, out)
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("bin: "))
        self.assertTrue(lines[1].startswith("description: "))
        self.assertIn("error: no API key", out)
        self.assertIn("help: ", out)

    def test_insecure_prints_a_warn_line_on_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = run(["aps"], env=make_env(tmp, UNIFI_INSECURE="1"))
        self.assertEqual(code, 0, out)
        self.assertTrue(out.startswith("warn: TLS verification is off"), out)


class CliContractTests(unittest.TestCase):
    def test_unknown_flag_exits_2_and_lists_the_commands_flags(self):
        controller = FakeController()
        code, out = run(["aps", "--bogus"], controller=controller)
        self.assertEqual(code, 2)
        self.assertEqual(out.splitlines()[0], "error: unknown flag --bogus for `aps`")
        self.assertTrue(out.splitlines()[1].startswith("help: valid flags for `aps`: --json, --fields"), out)
        self.assertIn("(--help always allowed)", out)
        self.assertEqual(controller.calls, [])

    def test_flag_of_another_command_and_abbreviations_are_rejected(self):
        for argv in (["aps", "--confirm"], ["drops", "--sinc", "2h"], ["clients", "--no-ssh"]):
            with self.subTest(argv=argv):
                code, out = run(argv)
                self.assertEqual(code, 2, out)
                self.assertIn("error: unknown flag", out)

    def test_extra_positional_and_unknown_command_exit_2(self):
        code, out = run(["aps", "office", "extra"])
        self.assertEqual(code, 2, out)
        self.assertIn("error: unexpected argument 'extra' for `aps`", out)
        code, out = run(["bogus"])
        self.assertEqual(code, 2, out)
        self.assertIn("error: unknown command 'bogus'", out)

    def test_every_command_has_help_with_examples_and_exit_0(self):
        for cmd in cli.COMMANDS:
            with self.subTest(cmd=cmd):
                code, out = run([cmd, "--help"])
                self.assertEqual(code, 0, out)
                self.assertIn("Example", out)
        for cmd in ("client", "drops"):
            code, out = run([cmd, "--help"])
            self.assertIn("HH:MM", out, cmd)
        code, out = run(["verify", "--help"])
        self.assertIn("3 MISMATCH", out)

    def test_home_view_is_live_content_with_two_help_lines(self):
        code, out = run([], controller=FakeController(pages=[[]]))
        self.assertEqual(code, 0, out)
        self.assertIn("controller: https://192.0.2.1  site=default  tls=verified", out)
        self.assertIn("aps: 4 of 4 online  fw=8.8.14.20179 (all)", out)
        self.assertIn("drops: 0 in 24h (all wireless clients", out)
        self.assertIn("help[2]:", out)

    def test_json_errors_are_json(self):
        code, out = run(["aps", "--bogus", "--json"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["error"], "unknown flag --bogus for `aps`")

    def test_bare_version_fast_path_skips_the_cli_graph(self):
        script = ("import sys; sys.argv=['unifi-axi', '--version']; from unifi_axi import entry; rc = entry.main(); "
                  "print('cli' in sys.modules or 'unifi_axi.cli' in sys.modules); sys.exit(rc)")
        for flag in ("-v", "-V", "--version"):
            res = subprocess.run([sys.executable, "-c", script.replace("--version", flag)], capture_output=True,
                                 text=True, check=False)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.splitlines(), [_version.VERSION, "False"], flag)

    def test_version_matches_pyproject(self):
        text = (ROOT / "pyproject.toml").read_text()
        self.assertIn(f'version = "{_version.VERSION}"', text)
        self.assertIn(f"## {_version.VERSION}", (ROOT / "CHANGELOG.md").read_text())


if __name__ == "__main__":
    unittest.main()


class ReviewFixTests(unittest.TestCase):
    """Fixes from the catalog source review of d482f83."""

    def test_strings_with_colons_or_number_shapes_are_quoted(self):
        from unifi_axi.toon import toon_scalar
        self.assertEqual(toon_scalar("09:51:44"), '"09:51:44"')
        self.assertEqual(toon_scalar("5"), '"5"')
        self.assertEqual(toon_scalar("-70 dBm"), '"-70 dBm"')
        self.assertEqual(toon_scalar(-70), "-70")
        self.assertEqual(toon_scalar("AP Office"), "AP Office")

    def test_lists_use_dash_items_and_repeated_groups_are_one_list(self):
        from unifi_axi.toon import Doc
        doc = Doc()
        doc.items("help", ["unifi-axi aps"])
        for name in ("AP Den", "AP Office"):
            sub = Doc()
            sub.kv("verify", name)
            doc.group("aps", sub)
        self.assertEqual(doc.toon(), "help[1]:\n  - unifi-axi aps\naps[2]:\n  - verify: AP Den\n  - verify: AP Office\n")

    def test_unknown_fields_name_is_reported(self):
        code, out = run(["aps", "--fields", "nosuch"])
        self.assertEqual(code, 0, out)
        self.assertIn("warn: --fields nosuch matched no column; available:", out)

    def test_unknown_flag_before_the_command_is_named(self):
        code, out = run(["--sin", "1h", "drops"])
        self.assertEqual(code, 2, out)
        self.assertIn("error: unknown flag --sin (before the command)", out)

    @unittest.skipUnless(shutil.which("npx") and os.environ.get("UNIFI_AXI_TOON_STRICT"),
                         "set UNIFI_AXI_TOON_STRICT=1 with npx on PATH to run the official decoder")
    def test_every_command_output_decodes_with_the_official_toon_cli(self):
        cases = [[], ["aps"], ["clients"], ["drops", "--since", "24h"], ["kickout"], ["verify", "--all"],
                 ["client", "Alex iPhone", "--since", "2026-11-19 09:50", "--until", "2026-11-19 10:12"],
                 ["set-power", "AP Office", "5", "19"], ["aps", "--bogus"]]
        for argv in cases:
            with self.subTest(argv=argv):
                _, out = run(argv, raw_output=True)
                res = subprocess.run(["npx", "-y", "-q", "@toon-format/cli@4.4.0", "--decode"], input=out,
                                     capture_output=True, text=True, timeout=120)
                self.assertEqual(res.returncode, 0, res.stderr + out)

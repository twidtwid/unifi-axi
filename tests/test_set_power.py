"""set-power: the one write. The write function is always a fake, and run()
also blocks the real HTTP layer, so no test can send a request anywhere."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import shlex
import stat
import tempfile
import unittest
from unittest import mock

from helpers import OFFICE_ID, OFFICE_IP, FakeController, FakeSSH, fixture_json, fixture_text, run
from unifi_axi import api, aplog, clock
from unifi_axi.commands import setpower


def office(device: dict) -> dict:
    return next(ap for ap in device["data"] if ap.get("name") == "AP Office")


def verify_text(na: int | None = 20, ng: int | None = None, six: int | None = None, serve6: bool = False) -> str:
    """AP Office iwconfig/hostapd fixture with the device Tx-Power per band rewritten."""
    text = fixture_text("verify-office.txt")
    if na is not None:
        text = text.replace("Tx-Power=20 dBm", f"Tx-Power={na} dBm")  # only 5 GHz ifaces read 20
    lines, block = [], None
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s+IEEE", line)
        if m:
            block = m.group(1)
        elif line and not line.startswith(" "):
            block = None
        if serve6 and block == "wifi2ap5" and "ESSID:" in line:
            line = line.replace('ESSID:"element-example"', 'ESSID:"ExampleLAN"')
        if block and block.startswith("wifi0") and ng is not None:
            line = re.sub(r"Tx-Power=\d+ dBm", f"Tx-Power={ng} dBm", line)
        if block == "wifi2ap5" and six is not None:
            line = re.sub(r"Tx-Power=\d+ dBm", f"Tx-Power={six} dBm", line)
        lines.append(line)
    text = "\n".join(lines) + "\n"
    if serve6:
        text = text.replace("---HOSTAPD wifi2ap5\nbssid=02:00:00:00:00:12\nssid=element-example",
                            "---HOSTAPD wifi2ap5\nbssid=02:00:00:00:00:12\nssid=ExampleLAN")
    return text


def serve_6ghz(device: dict) -> dict:
    office(device)["vap_table"].append({"radio": "6e", "essid": "ExampleLAN", "name": "wifi2ap5", "num_sta": 0})
    return device


class FakeWriter:
    """Stands in for api.api_write_device. Applies the body to the fake controller
    the way the controller would (new cfgversion, state), records every call.
    delay_reads: the first N stat/device reads after the PUT still return the
    old record in state 1 (the controller has not provisioned yet)."""

    def __init__(self, controller: FakeController, state_after: int = 1, delay_reads: int = 0,
                 drift=None, result=None, raises: Exception | None = None):
        self.controller = controller
        self.state_after = state_after
        self.delay_reads = delay_reads
        self.drift = drift
        self.result = result
        self.raises = raises
        self.calls: list[tuple[str, list]] = []

    def __call__(self, device_id, radio_table):
        self.calls.append((device_id, copy.deepcopy(radio_table)))
        if self.raises:
            raise self.raises
        pending = copy.deepcopy(radio_table)

        def apply():
            for ap in self.controller.device["data"]:
                if ap.get("_id") == device_id:
                    ap["radio_table"] = copy.deepcopy(pending)
                    ap["state"] = self.state_after
                    ap["cfgversion"] = "after-put"
                    if self.drift:
                        self.drift(ap)

        if self.delay_reads:
            first = self.controller.device_reads

            def hook(n):
                if n - first == self.delay_reads + 1:
                    apply()
            self.controller.read_hook = hook
        else:
            apply()
        return self.result or ({"meta": {"rc": "ok"}, "data": []}, None)


class FakeClock:
    def __init__(self):
        self.t = 1000.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.t += seconds


class SeqSSH(FakeSSH):
    """AP Office answers each verify read with the next text; the last one repeats."""

    def __init__(self, texts: list[str]):
        super().__init__({})
        self.texts = list(texts)

    def __call__(self, argv, **kwargs):
        self.outputs[OFFICE_IP] = self.texts.pop(0) if len(self.texts) > 1 else self.texts[0]
        return super().__call__(argv, **kwargs)


class SetPowerBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name)
        self.evidence = self.state / "evidence"

    def set_power(self, argv, controller=None, ssh_fake=None, writer=None, extra=None, **writer_kw):
        controller = controller or FakeController()
        writer = writer or FakeWriter(controller, **writer_kw)
        self.clock = FakeClock()
        controller.clock = self.clock
        patches = [mock.patch.object(api, "api_write_device", writer),
                   mock.patch.object(clock, "sleep", self.clock.sleep),
                   mock.patch.object(clock, "monotonic", self.clock.monotonic)]
        self.ssh = ssh_fake or FakeSSH({OFFICE_IP: verify_text()})
        code, out = run(["set-power", *argv], controller=controller, ssh_fake=self.ssh, state_dir=self.state,
                        extra=patches + (extra or []))
        self.assertTrue(all(m == "GET" for m, _, _ in controller.calls), controller.calls)
        self.controller = controller
        return code, out, writer

    def bundles(self) -> list[Path]:
        return list(self.evidence.iterdir()) if self.evidence.exists() else []

    def bundle(self) -> Path:
        dirs = self.bundles()
        self.assertEqual(len(dirs), 1, dirs)
        return dirs[0]


class SetPowerTests(SetPowerBase):
    def test_preview_sends_nothing_and_prints_diff_warning_and_help(self):
        code, out, writer = self.set_power(["office", "5", "18"])
        self.assertEqual(code, 0, out)
        self.assertEqual(writer.calls, [])
        self.assertIn("set-power: AP Office 5 GHz  20 -> 18 dBm  PREVIEW (nothing sent)", out)
        self.assertIn("radio: mode=custom ch=149 width=40 sta=7  "
                      "body: only na tx_power_mode/tx_power change; other radios and fields sent as read", out)
        self.assertIn("warn: do not apply during a live call", out)
        self.assertIn("clients: 7 on AP Office 5 GHz now", out)
        self.assertEqual([line for line in out.splitlines() if line.startswith("help:")],
                         ["help: unifi-axi set-power 'AP Office' 5 18 --confirm"])
        self.assertEqual(self.bundles(), [])
        self.assertEqual(self.ssh.calls, [])

    def test_put_body_is_fetched_radio_table_with_one_radios_two_fields_changed(self):
        device = fixture_json("stat-device.json")
        na = next(r for r in office(device)["radio_table"] if r["radio"] == "na")
        na.update(tx_power_mode="auto", tx_power=6)
        expected = copy.deepcopy(office(device)["radio_table"])
        next(r for r in expected if r["radio"] == "na").update(tx_power_mode="custom", tx_power=18)
        code, out, writer = self.set_power(["AP Office", "na", "18", "--confirm"],
                                           controller=FakeController(device=device), ssh_fake=FakeSSH({OFFICE_IP: verify_text(18)}))
        self.assertEqual(code, 0, out)
        self.assertEqual(len(writer.calls), 1)
        device_id, body = writer.calls[0]
        self.assertEqual(device_id, OFFICE_ID)
        self.assertEqual(body, expected)
        bundle = self.bundle()
        self.assertRegex(bundle.name, r"^unifi-change-\d{8}-\d{4}-ap-office-power$")
        self.assertEqual(json.loads((bundle / "put.json").read_text()), {"radio_table": expected})
        before = json.loads((bundle / "before.json").read_text())
        self.assertEqual(before["_id"], OFFICE_ID)
        self.assertEqual(before["radio_table"][1]["tx_power_mode"], "auto")
        self.assertIn("check: PASS", out)
        self.assertIn("undo: unifi-axi set-power 'AP Office' 5 auto --tx-power 6 --confirm", out)

    def test_same_value_is_noop_without_a_request(self):
        code, out, writer = self.set_power(["AP Office", "5", "20", "--confirm"])
        self.assertEqual(code, 0, out)
        self.assertEqual(writer.calls, [])
        self.assertIn("no-op", out)
        self.assertEqual(self.bundles(), [])

    def test_device_power_never_matches_is_exit_3_after_rereads_with_undo(self):
        code, out, writer = self.set_power(["AP Office", "5", "18", "--confirm"])  # device keeps 20
        self.assertEqual(code, 3, out)
        self.assertEqual(len(writer.calls), 1)
        self.assertIn("check: MISMATCH", out)
        self.assertIn("undo: unifi-axi set-power 'AP Office' 5 20 --confirm", out)
        self.assertGreater(len(self.ssh.calls), 1)
        self.assertLessEqual(self.clock.t - 1000.0, setpower.POLL_LIMIT_S)

    def test_stale_state_1_then_config_then_device_match_is_exit_0(self):
        ssh_fake = SeqSSH([verify_text(20), verify_text(18)])
        code, out, writer = self.set_power(["AP Office", "5", "18", "--confirm"], ssh_fake=ssh_fake, delay_reads=2)
        self.assertEqual(code, 0, out)
        self.assertIn("check: PASS  device Tx-Power 18 dBm", out)
        self.assertEqual(len(ssh_fake.calls), 2)  # SSH did not start until the config was provisioned
        self.assertIn("marker=cfgversion", out)
        polls = [kw for path, kw in self.controller.read_kwargs if path.endswith("/stat/device")]
        self.assertGreaterEqual(len(polls), 3)
        self.assertTrue(all(kw.get("retry") is False and kw["timeout"] <= 20 for kw in polls), polls)

    def test_poll_timeout_says_write_sent_and_verify_did_not_run(self):
        controller = FakeController()
        controller.slow = True  # every read takes its whole timeout
        code, out, writer = self.set_power(["AP Office", "5", "18", "--confirm"], controller=controller, state_after=5)
        self.assertEqual(code, 1, out)
        self.assertEqual(len(writer.calls), 1)
        self.assertIn("write sent", out)
        self.assertIn("verify did not run", out)
        self.assertIn("undo: unifi-axi set-power 'AP Office' 5 20 --confirm", out)
        self.assertEqual(self.ssh.calls, [])
        self.assertLessEqual(self.clock.t - 1000.0, setpower.POLL_LIMIT_S + 1)

    def test_unparsed_device_tx_power_is_unverified_exit_1(self):
        text = verify_text().replace("Tx-Power=20 dBm", "Tx-Power:off")
        code, out, writer = self.set_power(["AP Office", "5", "18", "--confirm"], ssh_fake=FakeSSH({OFFICE_IP: text}))
        self.assertEqual(code, 1, out)
        self.assertEqual(len(writer.calls), 1)
        self.assertIn("check: UNVERIFIED  device Tx-Power not read", out)

    def test_ssh_creds_or_wlanconf_failure_or_unserved_radio_refuses_before_put(self):
        for fail, needle in (({"get/setting/mgmt"}, "no SSH credentials"), ({"rest/wlanconf"}, "rest/wlanconf")):
            with self.subTest(fail=fail):
                code, out, writer = self.set_power(["AP Office", "5", "18", "--confirm"],
                                                   controller=FakeController(fail_paths=fail))
                self.assertEqual(code, 1, out)
                self.assertIn(needle, out)
                self.assertIn("nothing sent", out)
                self.assertEqual(writer.calls, [])
                self.assertEqual(self.bundles(), [])
        code, out, writer = self.set_power(["AP Office", "6", "20", "--confirm"])
        self.assertEqual(code, 1, out)
        self.assertIn("no served SSID on AP Office 6 GHz", out)
        self.assertEqual(writer.calls, [])

    def test_radio_table_changed_before_put_refuses(self):
        controller = FakeController()

        def hook(n):
            if n == 2:
                office(controller.device)["radio_table"][0]["min_rssi"] = -70
        controller.read_hook = hook
        code, out, writer = self.set_power(["AP Office", "5", "18", "--confirm"], controller=controller)
        self.assertEqual(code, 1, out)
        self.assertIn("radio_table changed since it was read", out)
        self.assertIn("nothing sent", out)
        self.assertEqual(writer.calls, [])

    def test_derived_field_refresh_before_put_does_not_refuse(self):
        controller = FakeController()

        def hook(n):
            if n == 2:
                office(controller.device)["radio_table"][1].update(current_antenna_gain=4, max_txpower=25, has_dfs=False)
        controller.read_hook = hook
        code, out, writer = self.set_power(["AP Office", "5", "18", "--confirm"], controller=controller,
                                           ssh_fake=FakeSSH({OFFICE_IP: verify_text(18)}))
        self.assertEqual(code, 0, out)
        self.assertEqual(len(writer.calls), 1)
        body = writer.calls[0][1]
        self.assertEqual((body[1]["current_antenna_gain"], body[1]["max_txpower"]), (4, 25))  # sent as re-read
        self.assertEqual((body[1]["tx_power_mode"], body[1]["tx_power"]), ("custom", 18))

    def test_other_field_drift_after_write_is_exit_3_and_derived_fields_ignored(self):
        def drift(ap):
            ap["radio_table"][0]["min_rssi"] = -70
            ap["radio_table"][1]["current_antenna_gain"] = 3
        code, out, writer = self.set_power(["AP Office", "5", "18", "--confirm"],
                                           ssh_fake=FakeSSH({OFFICE_IP: verify_text(18)}), drift=drift)
        self.assertEqual(code, 3, out)
        self.assertIn("drift: [(0, 'min_rssi')]", out)
        self.assertNotIn("current_antenna_gain')", out)

        def derived(ap):
            ap["radio_table"][1]["current_antenna_gain"] = 3
        code, out, writer = self.set_power(["AP Office", "5", "18", "--confirm"],
                                           ssh_fake=FakeSSH({OFFICE_IP: verify_text(18)}), drift=derived)
        self.assertEqual(code, 0, out)
        self.assertNotIn("drift:", out)

    def test_confirm_needs_exact_name_or_mac(self):
        code, out, writer = self.set_power(["offi", "5", "19", "--confirm"])
        self.assertEqual(code, 1, out)
        self.assertIn("PREVIEW (nothing sent)", out)
        self.assertIn("error: exact AP name required for --confirm", out)
        self.assertEqual(writer.calls, [])
        mac = office(fixture_json("stat-device.json"))["mac"]
        for who in ("AP OFFICE", mac.upper(), mac.replace(":", "")):
            with self.subTest(who=who):
                code, out, writer = self.set_power([who, "5", "18", "--confirm"], ssh_fake=FakeSSH({OFFICE_IP: verify_text(18)}))
                self.assertEqual(code, 0, out)
                self.assertEqual(len(writer.calls), 1)

    def test_ambiguous_help_keeps_band_and_dbm(self):
        code, out, writer = self.set_power(["ap", "5", "19"])
        self.assertEqual(code, 1, out)
        self.assertIn("help: unifi-axi set-power <exact AP name> 5 19", out)

    def test_auto_sets_mode_keeps_power_and_verifies_mode_only(self):
        code, out, writer = self.set_power(["office", "5", "auto"])
        self.assertEqual(code, 0, out)
        self.assertIn("set-power: AP Office 5 GHz  20 -> auto  PREVIEW (nothing sent)", out)
        self.assertIn("help: unifi-axi set-power 'AP Office' 5 auto --confirm", out)
        code, out, writer = self.set_power(["AP Office", "5", "auto", "--confirm"], ssh_fake=FakeSSH({OFFICE_IP: verify_text(23)}))
        self.assertEqual(code, 0, out)
        body = writer.calls[0][1]
        self.assertEqual((body[1]["tx_power_mode"], body[1]["tx_power"]), ("auto", 20))
        self.assertIn("check: PASS  controller tx_power_mode=auto; device Tx-Power 23 dBm on wifi1ap2 (reported, "
                      "not compared)", out)
        self.assertIn("undo: unifi-axi set-power 'AP Office' 5 20 --confirm", out)
        code, out, writer = self.set_power(["AP Office", "6", "auto", "--confirm"])  # 6 GHz is already auto
        self.assertEqual(code, 0, out)
        self.assertIn("no-op", out)
        code, out, writer = self.set_power(["office", "5", "loud"])
        self.assertEqual(code, 2, out)

    def test_exception_after_put_prints_sent_time_stub_and_undo(self):
        boom = mock.patch.object(aplog, "parse_verify", mock.Mock(side_effect=RuntimeError("boom")))
        code, out, writer = self.set_power(["AP Office", "5", "18", "--confirm"], extra=[boom])
        self.assertEqual(code, 1, out)
        self.assertEqual(len(writer.calls), 1)
        self.assertIn("NOT VERIFIED: internal error after write", out)
        self.assertRegex(out, r"write sent at \d\d:\d\d:\d\d")
        self.assertIn("changelog[", out)
        self.assertIn("undo: unifi-axi set-power 'AP Office' 5 20 --confirm", out)

    def test_evidence_has_before_put_after_without_secrets_and_stub_has_undo(self):
        device = fixture_json("stat-device.json")
        office(device).update(syslog_key="PLACEHOLDER-SYSLOG-KEY", x_authkey="placeholder", x_vwirekey="placeholder")
        code, out, writer = self.set_power(["AP Office", "5", "18", "--confirm"], controller=FakeController(device=device),
                                           ssh_fake=FakeSSH({OFFICE_IP: verify_text(18)}))
        self.assertEqual(code, 0, out)
        bundle = self.bundle()
        for path in (bundle, self.evidence, self.state):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700, path)
        self.assertEqual(sorted(p.name for p in bundle.iterdir()), ["after.json", "before.json", "put.json"])
        for name in ("before.json", "after.json"):
            text = (bundle / name).read_text()
            self.assertNotIn("PLACEHOLDER-SYSLOG-KEY", text)
            data = json.loads(text)
            self.assertFalse([k for k in data if k.startswith("x_") or re.search(r"(^|_)key$", k, re.I)], name)
        after = json.loads((bundle / "after.json").read_text())
        self.assertEqual(after["radio_table"][1]["tx_power"], 18)
        stub = out.split("changelog[", 1)[1]
        self.assertIn("AP Office 5 GHz power 20 -> 18 dBm", stub)
        self.assertIn("custom/20 -> custom/18", stub)
        self.assertIn("Rollback: unifi-axi set-power 'AP Office' 5 20 --confirm", stub)
        self.assertIn("clients: 7 on AP Office 5 GHz now", out)

    def test_band_tokens_pick_the_matching_radio_and_bad_token_is_exit_2(self):
        for token, band in (("2.4", "2.4"), ("ng", "2.4"), ("6", "6"), ("6e", "6")):
            with self.subTest(token=token):
                code, out, writer = self.set_power(["office", token, "17"])
                self.assertEqual(code, 0, out)
                self.assertIn(f"set-power: AP Office {band} GHz ", out)
        code, out, writer = self.set_power(["AP Office", "ng", "17", "--confirm"], ssh_fake=FakeSSH({OFFICE_IP: verify_text(ng=17)}))
        self.assertEqual(code, 0, out)
        self.assertEqual([i for i, r in enumerate(writer.calls[0][1]) if r["tx_power"] == 17], [0])
        code, out, writer = self.set_power(["office", "bogus", "17"])
        self.assertEqual(code, 2, out)
        self.assertIn("use 2.4, 5, 6 or ng, na, 6e", out)

    def test_6ghz_radio_on_three_radio_ap_and_two_radio_ap_refusal(self):
        code, out, writer = self.set_power(["AP Office", "6", "20", "--confirm"],
                                           controller=FakeController(device=serve_6ghz(fixture_json("stat-device.json"))),
                                           ssh_fake=FakeSSH({OFFICE_IP: verify_text(six=20, serve6=True)}))
        self.assertEqual(code, 0, out)
        body = writer.calls[0][1]
        self.assertEqual((body[2]["radio"], body[2]["tx_power_mode"], body[2]["tx_power"]), ("6e", "custom", 20))
        self.assertIn("check: PASS  device Tx-Power 20 dBm on wifi2ap5", out)
        code, out, writer = self.set_power(["AP Shop", "6", "18", "--confirm"])
        self.assertEqual(code, 1, out)
        self.assertIn("AP Shop has no 6 GHz radio", out)
        self.assertEqual(writer.calls, [])

    def test_put_error_rc_or_exception_is_exit_1_and_verify_not_run(self):
        cases = (dict(result=(None, "PUT failed: timed out")), dict(result=({"meta": {"rc": "error"}}, None)),
                 dict(raises=RuntimeError("socket blew up")))
        for kw in cases:
            with self.subTest(kw=kw):
                code, out, writer = self.set_power(["AP Office", "5", "18", "--confirm"], **kw)
                self.assertEqual(code, 1, out)
                self.assertEqual(len(writer.calls), 1)
                self.assertIn("PUT rest/device failed", out)
                self.assertIn("NOT VERIFIED: PUT failed, state unknown", out)
                self.assertIn("undo: unifi-axi set-power 'AP Office' 5 20 --confirm", out)
                self.assertEqual(self.ssh.calls, [])

    def test_out_of_range_unknown_bounds_and_offline_ap_are_refused(self):
        device = fixture_json("stat-device.json")
        del office(device)["radio_table"][1]["max_txpower"]
        offline = fixture_json("stat-device.json")
        office(offline)["state"] = 0
        for argv, controller, needle in ((["AP Office", "5", "99", "--confirm"], None, "6..26"),
                                         (["AP Office", "5", "18", "--confirm"], FakeController(device=device), "UNKNOWN"),
                                         (["AP Office", "5", "18", "--confirm"], FakeController(device=offline), "not online")):
            with self.subTest(needle=needle):
                code, out, writer = self.set_power(argv, controller=controller)
                self.assertEqual(code, 1, out)
                self.assertIn(needle, out)
                self.assertEqual(writer.calls, [])
        self.assertEqual(self.bundles(), [])

    def test_undo_from_auto_restores_mode_and_power(self):
        device = fixture_json("stat-device.json")
        next(r for r in office(device)["radio_table"] if r["radio"] == "na").update(tx_power_mode="auto", tx_power=20)
        controller = FakeController(device=device)
        code, out, writer = self.set_power(["AP Office", "5", "18", "--confirm"], controller=controller,
                                           ssh_fake=FakeSSH({OFFICE_IP: verify_text(18)}))
        self.assertEqual(code, 0, out)
        undo = next(line for line in out.splitlines() if line.startswith("undo: "))[len("undo: "):]
        self.assertEqual(undo, "unifi-axi set-power 'AP Office' 5 auto --tx-power 20 --confirm")
        na = next(r for r in office(controller.device)["radio_table"] if r["radio"] == "na")
        self.assertEqual((na["tx_power_mode"], na["tx_power"]), ("custom", 18))
        argv = shlex.split(undo)[2:]  # drop "unifi-axi set-power"
        office(controller.device)["cfgversion"] = "between-writes"  # FakeWriter sets the same marker each PUT
        code, out, writer = self.set_power(argv, controller=controller, ssh_fake=FakeSSH({OFFICE_IP: verify_text(18)}))
        self.assertEqual(code, 0, out)
        body = writer.calls[0][1]
        self.assertEqual((body[1]["tx_power_mode"], body[1]["tx_power"]), ("auto", 20))
        code, out, writer = self.set_power(argv, controller=controller)  # now at auto/20: no-op
        self.assertIn("no-op", out)
        self.assertEqual(writer.calls, [])
        code, out, writer = self.set_power(["office", "5", "18", "--tx-power", "20"])
        self.assertEqual(code, 2, out)  # --tx-power only with auto


if __name__ == "__main__":
    unittest.main()

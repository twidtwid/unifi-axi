"""Read-path behavior: name resolution, client timeline, aps, drops, verify, paging, safety."""

from __future__ import annotations

import ast
import calendar
import json
from pathlib import Path
import re
import tempfile
import time
import unittest
from unittest import mock

from helpers import (
    ALEX,
    KERN,
    NOW,
    OFFICE_IP,
    PASSWORD,
    PATIO_IP,
    SAM,
    T10,
    WATCH,
    WINDOW,
    FakeController,
    FakeSSH,
    alex_event,
    ap_output,
    event,
    fixture_json,
    fixture_text,
    local,
    run,
    stamp,
)
from unifi_axi import api, aplog, cli, config, site, ssh, timeline, toon
from unifi_axi.commands import verify

SRC = Path(__file__).parents[1] / "src" / "unifi_axi"


class ResolveTests(unittest.TestCase):
    def test_possessive_name_and_bare_mac_resolve(self):
        sta = fixture_json("stat-sta.json")["data"]
        users = fixture_json("rest-user.json")["data"]
        match = site.resolve_client("Alex's iPhone", sta, users, [])
        self.assertEqual(match.macs, [ALEX])
        self.assertEqual(match.name, "Alex iPhone")
        self.assertIn("tokens", match.how)
        self.assertEqual(site.resolve_client("02000000A001", sta, users, []).macs, [ALEX])

    def test_ambiguous_name_lists_candidates_and_exits_1(self):
        code, out = run(["client", "iphone", "--no-ssh"])
        self.assertEqual(code, 1)
        self.assertIn('error: 3 clients match "iphone"', out)
        self.assertIn("candidates[3]{name,mac,ap,last_seen}:", out)
        self.assertIn(f"Sam iPhone,{SAM},AP Office", out)


class ClientTimelineTests(unittest.TestCase):
    def test_controller_roam_and_ap_ft_auth_merge_into_one_row(self):
        code, out = run(["client", "Alex iPhone", *WINDOW])
        self.assertEqual(code, 0, out)
        self.assertIn("09:53:39,ctl+ap,AP Office,5,roam ft,-47,from AP Den (-57)", out)
        self.assertEqual(out.count("09:53:39,"), 1)

    def test_sae_auth_is_full_join_and_controller_only_roam_is_unknown(self):
        code, out = run(["client", "Alex iPhone", *WINDOW])
        self.assertIn("09:52:03,ctl+ap,AP Den,2.4,join full_sae,-49", out)
        code, out = run(["client", "Alex iPhone", *WINDOW, "--no-ssh"])
        self.assertEqual(code, 0, out)
        self.assertIn("09:53:39,ctl,AP Office,5,roam,-47,from AP Den (-57); FT UNKNOWN", out)
        self.assertNotIn("roam ft", out)

    def test_btm_runs_collapse_with_range_and_reject_count(self):
        t = "Thu Nov 19 10:03:{:02d} 2026 kern.info kernel: wlan: [0:I:ANY] [UNSPECIFIED] vap-0(wifi1ap2):BTM: "
        lines = []
        for i, rssi in enumerate([-85, -80, -76, -78]):
            lines.append(t.format(10 * i) + f"STA {ALEX} RSSI: {rssi}, candidates: 5, error: 0, flags: ALLOW (0x1)")
            lines.append(t.format(10 * i + 1) + f"Received response from [{ALEX}](len = 5): dialog_token 1, status 1, delay 0, bssid n/a, cancel 0")
        code, out = run(["client", ALEX, "--since", "2026-11-19 10:00", "--until", "2026-11-19 10:05"],
                        ssh_fake=FakeSSH({OFFICE_IP: ap_output(lines)}), controller=FakeController(pages=[[]]))
        self.assertEqual(code, 0, out)
        self.assertIn("10:03:00,ap,AP Office,5,btm_req x4,-76..-85,until 10:03:30", out)
        self.assertIn("10:03:01,ap,AP Office,5,btm_resp x4,UNKNOWN,status 1 x4 (reject)", out)
        self.assertIn("btm_req=4 accepted=0 rejected=4", out)
        self.assertIn("timeline[2]", out)

    def test_stale_stat_sta_against_newer_ap_join_is_conflict(self):
        sta = fixture_json("stat-sta.json")
        for s in sta["data"]:
            if s["mac"] == ALEX:
                s["latest_assoc_time"] = 1795110000  # 09:40, before the 10:05:28 AP Den join
        code, out = run(["client", "Alex iPhone", "--since", "2026-11-19 10:00", "--until", "2026-11-19 10:12"],
                        controller=FakeController(sta=sta))
        self.assertIn("conflict: stat/sta says AP Office (last_seen 60s); AP log shows roam ft to AP Den at 10:05:28", out)

    def test_one_ap_timeout_is_partial_not_failure(self):
        code, out = run(["client", "Alex iPhone", *WINDOW], ssh_fake=FakeSSH.fixtures(timeouts={PATIO_IP}))
        self.assertEqual(code, 0, out)
        self.assertIn("ap_logs=3/4", out)
        self.assertIn("unreachable[1]{ap,reason}:", out)
        self.assertIn("AP Patio,ssh timeout 10s", out)
        self.assertIn("09:53:56,ctl,AP Patio,5,roam,", out)

    def test_empty_window_states_coverage(self):
        code, out = run(["client", "Alex iPhone", "--since", "2026-11-19 12:00", "--until", "2026-11-19 12:10"],
                        controller=FakeController(pages=[[]]))
        self.assertEqual(code, 0, out)
        self.assertIn("timeline: 0 events for Alex iPhone in 12:00-12:10. controller=ok ap_logs=1/1 (oldest line 10/30 00:00).", out)

    def test_more_than_40_rows_hides_btm_first_and_full_shows_all(self):
        lines = []
        for i in range(45):
            lines.append(f"{stamp(T10 + 100 * i)} {KERN}vap-0(wifi1ap2):BTM: STA {ALEX} RSSI: -80, candidates: 5, error: 0, flags: ALLOW (0x1)")
        for i in range(5):
            ts = stamp(T10 + 100 * i + 50)
            lines.append(f"{ts} {KERN}vap-0(wifi1ap2): [{ALEX}]recv auth frame with algorithm 2 seq 1 rssi:40 minrssi:0")
            lines.append(f"{ts} user.notice hostapd[1]: wifi1ap2: AP-STA-CONNECTED {ALEX}")
        lines.sort(key=lambda s: time.mktime(time.strptime(s[:24], "%a %b %d %H:%M:%S %Y")))
        ssh_fake = FakeSSH({OFFICE_IP: ap_output(lines)})
        argv = ["client", ALEX, "--since", "2026-11-19 09:59", "--until", "2026-11-19 11:30"]
        code, out = run(argv, ssh_fake=ssh_fake, controller=FakeController(pages=[[]]))
        self.assertEqual(code, 0, out)
        self.assertEqual(out.count(",roam ft,"), 5)
        self.assertIn("more: 10 rows hidden (10 btm). Add --full.", out)
        self.assertIn("timeline[40]", out)
        code, out = run(argv + ["--full"], ssh_fake=ssh_fake, controller=FakeController(pages=[[]]))
        self.assertIn("timeline[50]", out)
        self.assertNotIn("more:", out)


class ApsTests(unittest.TestCase):
    def test_auto_power_mismatch_and_unknown(self):
        device = fixture_json("stat-device.json")
        for ap in device["data"]:
            if ap["name"] == "AP Office":
                for r in ap["radio_table_stats"]:
                    if r["radio"] == "na":
                        r["tx_power"] = 26
            if ap["name"] == "AP Shop":
                for r in ap["radio_table_stats"]:
                    if r["radio"] == "ng":
                        del r["cu_total"]
        code, out = run(["aps"], controller=FakeController(device=device))
        self.assertEqual(code, 0, out)
        self.assertIn("AP Patio,5,157,157,40,auto,25,", out)
        self.assertIn("AP Office,5,149,149,40,20,26,", out)
        self.assertIn("mismatch[1]{ap,band,field,cfg,live}:", out)
        self.assertIn("AP Office,5,pwr,20,26", out)
        self.assertIn("AP Shop,2.4,1,1,20,18,18,UNKNOWN,11", out)

    def test_one_ap_detail_names_model_and_uptime(self):
        code, out = run(["aps", "office"])
        self.assertEqual(code, 0, out)
        self.assertRegex(out, r"ap: AP Office  model=U7PRO  ip=192\.0\.2\.92  uplink=\S+.*uptime=1d0h")


def drop_pages(include_second_page_drop: bool = True) -> list[list[dict]]:
    base = 1795100000000
    office = {"name": "AP Office"}
    band = {"name": "na"}
    p1 = [
        # counts: 179 s gap
        event("CLIENT_DISCONNECTED_WIRELESS_2", base, ALEX, "Alex iPhone", DEVICE=office, RADIO_BAND=band),
        event("CLIENT_CONNECTED_WIRELESS_2", base + 179_000, ALEX, "Alex iPhone", DEVICE=office, RADIO_BAND=band),
        # does not count: 181 s gap
        event("CLIENT_DISCONNECTED_WIRELESS_2", base + 1_000_000, ALEX, "Alex iPhone", DEVICE=office, RADIO_BAND=band),
        event("CLIENT_CONNECTED_WIRELESS_2", base + 1_181_000, ALEX, "Alex iPhone", DEVICE=office, RADIO_BAND=band),
        # a roam is not a drop
        event("CLIENT_ROAMED_2", base + 2_000_000, ALEX, "Alex iPhone", DEVICE_FROM=office, DEVICE_TO={"name": "AP Shop"}),
        # not an iPhone: counted by default, excluded by --match iphone
        event("CLIENT_DISCONNECTED_WIRELESS_2", base + 3_000_000, WATCH, "Alex Watch", hostname="Watch", DEVICE=office, RADIO_BAND=band),
        event("CLIENT_CONNECTED_WIRELESS_2", base + 3_010_000, WATCH, "Alex Watch", hostname="Watch", DEVICE=office, RADIO_BAND=band),
    ]
    p2 = []
    if include_second_page_drop:
        p2 = [
            event("CLIENT_DISCONNECTED_WIRELESS_2", base + 4_000_000, SAM, "Sam iPhone", DEVICE={"name": "AP Patio"}, RADIO_BAND={"name": "ng"}),
            event("CLIENT_CONNECTED_WIRELESS_2", base + 4_009_000, SAM, "Sam iPhone", DEVICE={"name": "AP Patio"}, RADIO_BAND={"name": "ng"}),
        ]
    return [p1, p2]


class DropsTests(unittest.TestCase):
    def test_gap_limit_roam_match_filter_and_second_page(self):
        controller = FakeController(pages=drop_pages())
        code, out = run(["drops", "--since", "24h", "--match", "iphone"], controller=controller)
        self.assertEqual(code, 0, out)
        self.assertIn("drops: 2 in 24h (clients matching 'iphone'; reconnect within 180 s)\n", out)
        self.assertIn("events: 9 read; 2/2 pages; complete", out)
        self.assertIn("Alex iPhone,1,179,", out)
        self.assertIn("Sam iPhone,1,9,", out)
        self.assertNotIn("Alex Watch", out)
        pages = [c[2]["pageNumber"] for c in controller.calls if c[1].endswith("system-log/all")]
        self.assertEqual(pages, [0, 1])

    def test_default_scope_is_every_wireless_client_and_baseline_only_when_configured(self):
        code, out = run(["drops", "--since", "24h"], controller=FakeController(pages=drop_pages()))
        self.assertEqual(code, 0, out)
        self.assertIn("drops: 3 in 24h (all wireless clients; reconnect within 180 s)  per_day=3.0\n", out)
        self.assertIn("Alex Watch,1,10,", out)
        self.assertNotIn("baseline", out)
        with tempfile.TemporaryDirectory() as tmp:
            from helpers import make_env
            env = make_env(tmp, UNIFI_DROP_BASELINE_PER_DAY="41")
            code, out = run(["drops", "--since", "24h"], controller=FakeController(pages=drop_pages()), env=env)
        self.assertIn("per_day=3.0 baseline_per_day=41 (configured)", out)
        code, out = run(["drops", "--since", "24h", "--gap", "60"], controller=FakeController(pages=drop_pages()), env=env)
        self.assertNotIn("baseline", out)  # the baseline belongs to the default scope and gap only

    def test_failed_page_is_incomplete_exit_1(self):
        code, out = run(["drops", "--since", "24h"], controller=FakeController(pages=drop_pages(), fail_pages={1}))
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("drops: INCOMPLETE (1/2 pages)"), out)

    def test_by_hour_has_date_when_window_spans_two_dates(self):
        code, out = run(["drops", "--since", "24h"], controller=FakeController(pages=drop_pages()))
        self.assertIn("by_hour[", out)
        self.assertIn("  11-19 06,1", out)

    def test_full_lifts_by_client_cap(self):
        page = []
        for i in range(12):
            mac = f"02:00:00:00:c0:{i:02x}"
            page.append(event("CLIENT_DISCONNECTED_WIRELESS_2", 1795100000000 + i * 1000, mac, f"P{i} iPhone"))
            page.append(event("CLIENT_CONNECTED_WIRELESS_2", 1795100010000 + i * 1000, mac, f"P{i} iPhone"))
        code, out = run(["drops", "--since", "24h"], controller=FakeController(pages=[page]))
        self.assertIn("more: 2 clients hidden. Add --full.", out)
        code, out = run(["drops", "--since", "24h", "--full"], controller=FakeController(pages=[page]))
        self.assertIn("by_client[12]", out)

    def test_reversed_window_negative_gap_or_two_scopes_is_usage_error(self):
        for argv in (["--since", "10:00", "--until", "09:00"], ["--since", "10:00", "--until", "10:00"],
                     ["--gap", "-5"], ["--match", "iphone", "--client", "Alex iPhone"]):
            with self.subTest(argv=argv):
                controller = FakeController(pages=[[]])
                code, out = run(["drops", *argv], controller=controller)
                self.assertEqual(code, 2, out)
                self.assertIn("error:", out)
                self.assertEqual(controller.calls, [])


class VerifyTests(unittest.TestCase):
    def test_recorded_device_config_passes_and_sae_only_is_mismatch(self):
        text = fixture_text("verify-office.txt")
        code, out = run(["verify", "office"], ssh_fake=FakeSSH({OFFICE_IP: text}))
        self.assertEqual(code, 0, out)
        self.assertIn("5,wifi1ap2,ExampleLAN,149,20,20,FT-SAE SAE,yes", out)
        self.assertIn("result: PASS", out)
        head = "---HOSTAPD wifi1ap2\nbssid=02:00:00:00:00:02\nssid=ExampleLAN\nwps_state=disabled\nwpa=2\n"
        broken = text.replace(head + "key_mgmt=FT-SAE SAE", head + "key_mgmt=SAE")
        self.assertNotEqual(broken, text)
        code, out = run(["verify", "office"], ssh_fake=FakeSSH({OFFICE_IP: broken}))
        self.assertEqual(code, 3, out)
        self.assertIn("result: MISMATCH", out)
        self.assertIn("5,wifi1ap2,ExampleLAN,149,20,20,SAE,no", out)

    def test_verify_all_json_keeps_every_ap(self):
        code, out = run(["verify", "--all", "--json"], ssh_fake=FakeSSH({OFFICE_IP: fixture_text("verify-office.txt")}))
        data = json.loads(out)
        self.assertEqual(len(data["aps"]), 4, out)
        names = [a["verify"].split(" (")[0] for a in data["aps"]]
        self.assertEqual(sorted(names), ["AP Den", "AP Office", "AP Patio", "AP Shop"])
        self.assertTrue(all("result" in a and ("radios" in a or "radios_ctl" in a) for a in data["aps"]))
        self.assertIn("overall", data)
        code2, text = run(["verify", "--all"], ssh_fake=FakeSSH({OFFICE_IP: fixture_text("verify-office.txt")}))
        self.assertEqual(len([line for line in text.splitlines() if line.startswith("verify: ")]), 4, text)
        self.assertEqual(code, code2)
        doc = toon.Doc()
        doc.kv("a", "1")
        doc.kv("a", "2")
        self.assertEqual(json.loads(doc.json()), {"a": ["1", "2"]})

    def test_unread_device_power_or_key_mgmt_is_unverified_not_mismatch(self):
        text = fixture_text("verify-office.txt")
        no_power = text.replace("Tx-Power=20 dBm", "Tx-Power:off")
        no_keys = re.sub(r"(---HOSTAPD wifi1ap2\n(?:.*\n)*?)key_mgmt=[^\n]*\n", r"\1", text, count=1)
        self.assertNotEqual(no_keys, text)
        for label, variant in (("power", no_power), ("key_mgmt", no_keys)):
            with self.subTest(label):
                code, out = run(["verify", "office"], ssh_fake=FakeSSH({OFFICE_IP: variant}))
                self.assertEqual(code, 1, out)
                self.assertIn("result: UNVERIFIED", out)
                self.assertNotIn("MISMATCH", out)
        broken = no_power.replace("key_mgmt=FT-SAE SAE", "key_mgmt=SAE")
        code, out = run(["verify", "office"], ssh_fake=FakeSSH({OFFICE_IP: broken}))
        self.assertEqual(code, 3, out)  # a proven mismatch still wins over an unread cell
        self.assertIn("result: MISMATCH", out)

    def test_ap_query_without_letters_or_digits_is_usage_error(self):
        aps = site.build_site(fixture_json("stat-device.json")["data"]).aps
        for q in ("", "  ", "?!", "--"):
            with self.subTest(q=q), self.assertRaises(site.UsageError):
                site.resolve_ap(q, aps)
        controller = FakeController()
        code, out = run(["verify", "?!"], controller=controller)
        self.assertEqual(code, 2, out)
        self.assertEqual(controller.calls, [])
        self.assertEqual(site.resolve_ap("office", aps)["name"], "AP Office")


def monitor_gap(w: dict, roaming: tuple[str, ...]) -> bool:
    """Reference rule (independent copy): a roaming WLAN lacks FT for a client class it admits."""
    if w.get("name") not in roaming or not w.get("enabled", True):
        return False
    wpa3 = bool(w.get("wpa3_support"))
    wpa2 = not wpa3 or bool(w.get("wpa3_transition"))
    return (wpa2 and not w.get("fast_roaming_enabled")) or (wpa3 and not w.get("wpa3_fast_roaming"))


class FastRoamingTests(unittest.TestCase):
    VARIANTS = [
        dict(wpa3_support=True, wpa3_transition=False, fast_roaming_enabled=True, wpa3_fast_roaming=True),
        dict(wpa3_support=True, wpa3_transition=False, fast_roaming_enabled=True, wpa3_fast_roaming=False),
        dict(wpa3_support=True, wpa3_transition=True, fast_roaming_enabled=True, wpa3_fast_roaming=False),
        dict(wpa3_support=True, wpa3_transition=True, fast_roaming_enabled=False, wpa3_fast_roaming=True),
        dict(wpa3_support=False, wpa3_transition=False, fast_roaming_enabled=False, wpa3_fast_roaming=True),
        dict(wpa3_support=False, wpa3_transition=False, fast_roaming_enabled=True, wpa3_fast_roaming=False),
    ]

    def test_ft_rule_matches_the_reference_on_every_flag_combination(self):
        for flags in self.VARIANTS:
            w = {"name": "ExampleLAN", "enabled": True, **flags}
            required, configured = verify.ft_suites(w, ("ExampleLAN",))
            self.assertEqual(monitor_gap(w, ("ExampleLAN",)), bool(required - configured), flags)
            required, configured = verify.ft_suites(w, ())
            self.assertEqual(required, configured, flags)  # not a roaming SSID: config is the requirement

    def test_transition_mode_without_wpa3_ft_is_mismatch_only_for_a_roaming_ssid(self):
        wl = fixture_json("wlanconf.json")
        for w in wl["data"]:
            if w["name"] == "ExampleLAN":
                w.update(wpa3_transition=True, wpa3_fast_roaming=False)
        text = fixture_text("verify-office.txt").replace("key_mgmt=FT-SAE SAE", "key_mgmt=FT-PSK WPA-PSK SAE")
        code, out = run(["verify", "office"], ssh_fake=FakeSSH({OFFICE_IP: text}), controller=FakeController(wlanconf=wl))
        self.assertEqual(code, 3, out)
        self.assertIn("result: MISMATCH", out)
        with tempfile.TemporaryDirectory() as tmp:
            from helpers import make_env
            env = make_env(tmp, UNIFI_ROAMING_SSIDS="")
            code, out = run(["verify", "office"], ssh_fake=FakeSSH({OFFICE_IP: text}),
                            controller=FakeController(wlanconf=wl), env=env)
        self.assertEqual(code, 0, out)  # the device runs exactly what the config turns on


class SafetyTests(unittest.TestCase):
    def test_password_never_in_argv_stdout_or_saved_files(self):
        ssh_fake = FakeSSH.fixtures()
        with tempfile.TemporaryDirectory() as tmp:
            code, out = run(["client", "Alex iPhone", *WINDOW, "--save", "--json"], ssh_fake=ssh_fake, state_dir=Path(tmp))
            self.assertEqual(code, 0, out)
            saved = [p for p in Path(tmp).rglob("*") if p.is_file()]
            self.assertTrue(saved)
            for p in saved:
                self.assertNotIn(PASSWORD, p.read_text(errors="replace"), p)
            captures = Path(tmp) / "captures"
            self.assertEqual(captures.stat().st_mode & 0o777, 0o700)
        self.assertNotIn(PASSWORD, out)
        self.assertTrue(ssh_fake.calls)
        for argv, kwargs in ssh_fake.calls:
            self.assertFalse(any(PASSWORD in a for a in argv), argv)
            self.assertEqual(kwargs["env"]["UNIFI_AXI_SSH_PASSWORD"], PASSWORD)
            self.assertEqual(kwargs["env"]["SSH_ASKPASS_REQUIRE"], "force")
            self.assertTrue(Path(kwargs["env"]["SSH_ASKPASS"]).name == "askpass.sh")
        self.assertNotIn(PASSWORD, (SRC / "askpass.sh").read_text())

    def test_askpass_copy_is_made_when_the_packaged_file_is_not_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            config.set_active(config.Config(state_dir=Path(tmp)))
            with mock.patch("os.access", return_value=False):
                path = ssh.askpass_path()
            self.assertEqual(path, Path(tmp) / "askpass.sh")
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            self.assertIn("UNIFI_AXI_SSH_PASSWORD", path.read_text())

    def test_toon_quotes_value_with_comma(self):
        self.assertEqual(toon.toon_scalar("from AP Office, then AP Shop"), '"from AP Office, then AP Shop"')
        self.assertEqual(toon.toon_scalar("plain"), "plain")
        self.assertEqual(toon.toon_scalar('say "hi"'), '"say \\"hi\\""')

    def test_secret_fields_are_stripped_at_every_depth(self):
        self.assertEqual(api_strip({"syslog_key": "k", "key_mgmt": "SAE", "Key": 1, "x_pw": 1, "a": [{"psk": 1, "b": 2}]}),
                         {"key_mgmt": "SAE", "a": [{"b": 2}]})


def api_strip(obj):
    from unifi_axi.util import strip_secrets
    return strip_secrets(obj)


class SummaryWindowTests(unittest.TestCase):
    def test_controller_log_failure_prints_unknown_counts_and_exits_1(self):
        code, out = run(["client", "Alex iPhone", *WINDOW], controller=FakeController(fail_pages={0}))
        self.assertEqual(code, 1, out)
        for needle in ("roams=UNKNOWN", "ctl_repeat=UNKNOWN", "drops=UNKNOWN", "AP choice had no controller input"):
            self.assertIn(needle, out)

    def test_drop_just_before_since_is_not_counted(self):
        since = local("2026-11-19 10:00:00")
        pages = [[alex_event("CLIENT_DISCONNECTED_WIRELESS_2", since - 50, rssi=-91),
                  alex_event("CLIENT_CONNECTED_WIRELESS_2", since - 20, rssi=-90)]]
        code, out = run(["client", ALEX, "--since", "2026-11-19 10:00", "--until", "2026-11-19 10:10", "--no-ssh"],
                        controller=FakeController(pages=pages))
        self.assertEqual(code, 0, out)
        self.assertIn("drops=0", out)
        self.assertIn("worst_rssi=UNKNOWN", out)
        self.assertNotIn(",drop,", out)

    def test_client_read_that_raises_degrades_only_that_source(self):
        real = api.legacy_list

        def flaky(path, *a, **kw):
            if path == "rest/user":
                raise RuntimeError("boom")
            return real(path, *a, **kw)
        code, out = run(["client", "Alex iPhone", *WINDOW], extra=[mock.patch.object(api, "legacy_list", flaky)])
        self.assertEqual(code, 0, out)
        self.assertIn("rest_user=FAILED", out)
        self.assertIn("roams=6 (ft=5 full_sae=1", out)


class CoverageTests(unittest.TestCase):
    def test_partial_ap_logs_make_conflict_unknown(self):
        code, out = run(["client", "Alex iPhone", *WINDOW], ssh_fake=FakeSSH.fixtures(timeouts={PATIO_IP}))
        self.assertIn("conflict: UNKNOWN (partial AP logs: AP Patio ssh timeout 10s)", out)

    def test_disconnect_in_window_reads_all_online_aps(self):
        code, out = run(["client", "Alex iPhone", *WINDOW])
        self.assertIn("ap_logs=4/4 chosen of 4 online", out)
        pages = [[alex_event("CLIENT_DISCONNECTED_WIRELESS_2", T10 + 60)]]
        ssh_fake = FakeSSH()
        code, out = run(["client", ALEX, "--since", "2026-11-19 10:00", "--until", "2026-11-19 10:10"],
                        controller=FakeController(pages=pages), ssh_fake=ssh_fake)
        self.assertEqual(len(ssh_fake.calls), 4, out)
        self.assertIn("ap_logs=4/4 chosen of 4 online (all online: window has a disconnect)", out)

    def test_captures_default_under_local_state_not_a_served_folder(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertEqual(config.Config().captures_dir, Path.home() / ".local/state/unifi-axi/captures")
            self.assertEqual(config.Config().evidence_dir, Path.home() / ".local/state/unifi-axi/evidence")
        help_text = "".join(cli.build_parser().format_help().split())
        code, out = run(["client", "--help"])
        self.assertIn("~/.local/state/unifi-axi/captures/", "".join(out.split()))
        self.assertNotIn("Reports", help_text + out)


class WorkerFailureTests(unittest.TestCase):
    def test_one_worker_exception_degrades_that_ap_only(self):
        code, out = run(["client", "Alex iPhone", *WINDOW], ssh_fake=FakeSSH.fixtures(raises={PATIO_IP}))
        self.assertEqual(code, 0, out)
        self.assertIn("ap_logs=3/4", out)
        self.assertIn("AP Patio,internal: RuntimeError", out)
        self.assertNotIn(PASSWORD, out)
        code, out = run(["verify", "--all"], ssh_fake=FakeSSH({OFFICE_IP: fixture_text("verify-office.txt")},
                                                               raises={PATIO_IP}))
        self.assertIn("AP Patio=UNVERIFIED", out)
        self.assertIn("AP Office=PASS", out)
        self.assertNotIn(PASSWORD, out)

    def test_single_error_boundary_prints_error_on_stdout_exit_1(self):
        with mock.patch.dict(cli.HANDLERS, {"aps": mock.Mock(side_effect=KeyError("x"))}):
            code, out = run(["aps"])
        self.assertEqual(code, 1)
        self.assertIn("error: internal: KeyError in aps", out)
        self.assertNotIn("Traceback", out)


def ctl(kind: str, t: float, ap: str, from_ap: str | None = None, rssi: int | None = None, mac: str = ALEX) -> dict:
    row = {"t": t, "mac": mac, "key": kind, "band": "5", "rssi": rssi, "kind": kind, "ap": ap}
    if kind == "roam":
        row.update(from_ap=from_ap or "AP Den", prev_rssi=None)
    return row


def ap_join(t: float, ap: str = "AP Office", alg: str = "2") -> dict:
    return {"t": t, "ap": ap, "band": "5", "vap": "wifi1ap2", "kind": "join", "alg": alg, "auth_rssi": "40"}


class MergeTests(unittest.TestCase):
    since, until = T10 - 600, T10 + 600

    def merge(self, ctl_rows, events):
        logs = {"AP Office": aplog.ApLog(ap="AP Office", ok=True, events=events)}
        return timeline.merge_timeline(ctl_rows, logs, self.since, self.until)

    def test_prefers_earlier_join_over_next_events_join(self):
        rows, _ = self.merge([ctl("roam", T10, "AP Office", "AP Den"), ctl("roam", T10 + 20, "AP Patio", "AP Office"),
                              ctl("roam", T10 + 44, "AP Office", "AP Patio")],
                             [ap_join(T10 - 40, alg="2"), ap_join(T10 + 4, alg="3")])
        office = [r for r in rows if r["ap"] == "AP Office"]
        self.assertEqual([(r["src"], r["event"], r["t"]) for r in office],
                         [("ctl+ap", "roam ft", T10 - 40), ("ctl+ap", "join full_sae", T10 + 4)])

    def test_roam_after_a_drop_is_not_a_repeat(self):
        rows, stats = self.merge([ctl("roam", T10, "AP Office"), ctl("disconnect", T10 + 30, "AP Office"),
                                  ctl("connect", T10 + 60, "AP Office"), ctl("roam", T10 + 90, "AP Office")], [])
        self.assertEqual([r["event"] for r in rows if r["kind"] in ("transition", "repeat")], ["roam", "roam"])
        self.assertEqual(stats["ctl_repeat"], 0)

    def test_same_roam_twice_within_120s_is_repeat(self):
        rows, stats = self.merge([ctl("roam", T10, "AP Office"), ctl("roam", T10 + 30, "AP Office")], [])
        self.assertEqual(rows[1]["event"], "roam (repeat)")
        self.assertIn("controller repeat of 10:00:00", rows[1]["detail"])
        self.assertEqual(stats["ctl_repeat"], 1)

    def test_merge_window_edges(self):
        rows, _ = self.merge([ctl("roam", T10, "AP Office")], [ap_join(T10 - 59)])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["src"], "ctl+ap")
        self.assertIn("ctl +59s", rows[0]["detail"])
        for offset in (-61, 6):
            rows, _ = self.merge([ctl("roam", T10, "AP Office")], [ap_join(T10 + offset)])
            self.assertEqual(sorted(r["src"] for r in rows), ["ap", "ctl"], offset)
            self.assertIn("no controller event within 60 s", [r for r in rows if r["src"] == "ap"][0]["detail"])

    def drop_events(self):
        return [alex_event("CLIENT_DISCONNECTED_WIRELESS_2", T10, rssi=-80),
                alex_event("CLIENT_DISCONNECTED_WIRELESS_2", T10 + 30, ap="AP Shop"),
                alex_event("CLIENT_CONNECTED_WIRELESS_2", T10 + 60),
                alex_event("CLIENT_DISCONNECTED_WIRELESS_2", T10 + 300),
                alex_event("CLIENT_CONNECTED_WIRELESS_2", T10 + 400)]

    def test_two_disconnects_before_one_reconnect_is_one_drop(self):
        drops = timeline.find_drops(self.drop_events(), timeline.DROP_GAP_S, lambda e: True)
        self.assertEqual([(d["t"], d["gap"], d["ap"]) for d in drops],
                         [(T10 + 30, 30.0, "AP Shop"), (T10 + 300, 100.0, "AP Office")])

    def test_client_and_drops_count_the_same_events(self):
        events = self.drop_events()
        drops = timeline.find_drops(events, timeline.DROP_GAP_S, lambda e: True)
        _, stats = timeline.merge_timeline(timeline.ctl_rows(events, {ALEX}), {}, T10 - 600, T10 + 600)
        self.assertEqual(stats["drops"], len(drops))
        self.assertEqual(stats["drops"], 2)


class ApLogTests(unittest.TestCase):
    def client(self, lines):
        return run(["client", ALEX, "--since", "2026-11-19 10:00", "--until", "2026-11-19 10:05"],
                   ssh_fake=FakeSSH({OFFICE_IP: ap_output(lines)}), controller=FakeController(pages=[[]]))

    def test_ft_auth_without_connect_is_ft_attempt(self):
        code, out = self.client([f"{stamp(T10 + 60)} {KERN}vap-0(wifi1ap2): [{ALEX}]recv auth frame with algorithm 2 seq 1 rssi:30 minrssi:0"])
        self.assertIn('10:01:00,ap,AP Office,5,ft attempt,UNKNOWN,"FT auth seen, no AP-STA-CONNECTED"', out)
        self.assertIn("ft_fail=1", out)

    def test_auth_reject_line_is_auth_rejected(self):
        code, out = self.client([f"{stamp(T10 + 60)} {KERN}vap-0(wifi1ap2):mlme_recv_auth_ap_defer[812]: client[{ALEX}] rejected, reason=17"])
        self.assertIn("10:01:00,ap,AP Office,5,auth rejected,UNKNOWN,802.11 status 17", out)

    def test_utc_ap_with_10s_skew_through_cli(self):
        ap_epoch = NOW + 10

        def utc(ts):
            return time.strftime("%a %b %d %H:%M:%S %Y", time.gmtime(ts))
        lines = [f"{utc(T10 + 70)} {KERN}vap-0(wifi1ap2): [{ALEX}]recv auth frame with algorithm 2 seq 1 rssi:30 minrssi:0",
                 f"{utc(T10 + 70)} user.notice hostapd[1]: wifi1ap2: AP-STA-CONNECTED {ALEX}"]
        text = ap_output(lines, epoch=ap_epoch, date=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ap_epoch)))
        code, out = run(["client", ALEX, "--since", "2026-11-19 10:00", "--until", "2026-11-19 10:05"],
                        ssh_fake=FakeSSH({OFFICE_IP: text}), controller=FakeController(pages=[[]]))
        self.assertIn("clock_skew=AP Office +10s", out)
        self.assertIn("10:01:00,ap,AP Office,5,roam ft,", out)

    def test_same_zone_line_from_before_dst_end_maps_to_pdt(self):
        s = site.build_site(fixture_json("stat-device.json")["data"])
        text = ap_output([f"Sat Oct 31 12:00:00 2026 user.notice hostapd[1]: wifi1ap2: AP-STA-CONNECTED {ALEX}"])
        log = aplog.parse_ap_output("AP Office", text, [ALEX], s, NOW)
        self.assertTrue(log.ok)
        self.assertEqual(log.events[0]["t"], calendar.timegm((2026, 10, 31, 19, 0, 0, 0, 0, 0)))

    def test_coverage_start_reads_oldest_rotated_file_first(self):
        cmd = ssh.log_command([ALEX])
        self.assertIn("FIRST $(cat /var/log/messages.0 /var/log/messages 2>/dev/null | head -n 1)", cmd)

    def test_ap_state_is_per_mac_on_a_shared_vap(self):
        bob = "02:00:00:00:b0:02"
        vap = "wifi1ap2"
        s = site.build_site(fixture_json("stat-device.json")["data"])
        parsed = [(T10, "auth", (vap, ALEX, "2", "40")), (T10 + 1, "auth", (vap, bob, "3", "30")),
                  (T10 + 2, "connected", (vap, ALEX)), (T10 + 3, "connected", (vap, bob)),
                  (T10 + 10, "roamed", (vap, ALEX)), (T10 + 11, "kick", (ALEX, "inactivity ")),
                  (T10 + 12, "disconnected", (vap, bob))]
        out = aplog.ap_events("AP Office", parsed, s)
        self.assertEqual([e["kind"] for e in out], ["join", "join", "disconnect"])
        self.assertEqual([(e["alg"], e["auth_rssi"]) for e in out[:2]], [("2", "40"), ("3", "30")])
        self.assertIsNone(out[2]["reason"])
        same = aplog.ap_events("AP Office", [(T10, "kick", (bob, "inactivity ")), (T10 + 1, "disconnected", (vap, bob))], s)
        self.assertEqual(same[0]["reason"], "inactivity")
        noack = aplog.ap_events("AP Office", [(T10, "auth", (vap, ALEX, "2", "40")), (T10 + 1, "noack", (vap, bob))], s)
        self.assertNotIn("did not acknowledge", noack[0]["detail"])

    def test_stale_auth_gives_no_alg_and_no_rssi(self):
        s = site.build_site(fixture_json("stat-device.json")["data"])
        out = aplog.ap_events("AP Office", [(T10, "auth", ("wifi1ap2", ALEX, "2", "40")),
                                            (T10 + 15, "connected", ("wifi1ap2", ALEX))], s)
        self.assertEqual([(e["kind"], e["alg"], e["auth_rssi"]) for e in out], [("join", None, None)])


class PagingTests(unittest.TestCase):
    def read(self, controller, page_size=2, max_pages=20):
        config.set_active(config.Config())
        with mock.patch.object(api, "api_call", controller), mock.patch.object(api, "PAGE_SIZE", page_size), \
                mock.patch.object(api, "MAX_PAGES", max_pages):
            return api.system_log(T10, T10 + 600)

    def evs(self, *ns):
        return [dict(alex_event("CLIENT_ROAMED_2", T10 + n), id=f"id{n}") for n in ns]

    def test_missing_total_keeps_paging_while_full(self):
        out = self.read(FakeController(pages=[self.evs(1, 2), self.evs(3, 4), self.evs(5)], no_total=True))
        self.assertEqual(len(out.events), 5)
        self.assertTrue(out.complete, out.status())

    def test_missing_total_at_page_cap_is_incomplete(self):
        out = self.read(FakeController(pages=[self.evs(1, 2), self.evs(3, 4), self.evs(5, 6)], no_total=True), max_pages=2)
        self.assertTrue(out.capped)
        self.assertFalse(out.complete)

    def test_shifted_pages_are_deduped_by_id(self):
        out = self.read(FakeController(pages=[self.evs(1, 2), self.evs(2, 3)]))
        self.assertEqual([e["id"] for e in out.events], ["id1", "id2", "id3"])
        self.assertTrue(out.complete)

    def test_empty_result_with_zero_page_count_reads_one_of_one(self):
        out = self.read(FakeController(pages=[]))
        self.assertEqual((out.status(), out.complete, out.events), ("1/1 pages", True, []))

    def test_page_with_no_new_ids_stops_with_error(self):
        out = self.read(FakeController(pages=[self.evs(1, 2), self.evs(1, 2), self.evs(3)]))
        self.assertIn("pagination did not advance", out.error or "")
        self.assertFalse(out.complete)


class SshOutputTests(unittest.TestCase):
    def test_missing_end_marker_or_nonzero_exit_is_failure(self):
        code, out = run(["client", "Alex iPhone", *WINDOW], ssh_fake=FakeSSH.fixtures(truncated={OFFICE_IP}))
        self.assertIn("AP Office,ssh output truncated", out)
        code, out = run(["client", "Alex iPhone", *WINDOW], ssh_fake=FakeSSH.fixtures(rc={OFFICE_IP: 255}))
        self.assertIn("AP Office,ssh exit 255", out)
        self.assertIn("ap_logs=3/4", out)

    def test_mac_validation_is_full_match(self):
        for bad in ("02:00:00:00:00:ff\n", "02:00:00:00:00:ff;id", "02:00:00:00:00:ff "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ssh.log_command([bad])
        evs = [event("CLIENT_ROAMED_2", 1, "02:00:00:00:00:ff\n", "Bad")]
        self.assertEqual(site.client_candidates([], [], evs), [])


class LookupFailureTests(unittest.TestCase):
    def test_rest_user_failure_is_in_sources_and_no_match_is_not_authoritative(self):
        code, out = run(["client", "Alex iPhone", *WINDOW, "--no-ssh"], controller=FakeController(fail_paths={"/rest/user"}))
        self.assertIn("rest_user=FAILED", out)
        code, out = run(["client", "Nobody Here", *WINDOW, "--no-ssh"], controller=FakeController(fail_paths={"/rest/user"}))
        self.assertEqual(code, 1)
        self.assertNotIn("0 clients match", out)
        self.assertIn("rest/user FAILED", out)


class WriteGuardTests(unittest.TestCase):
    def test_read_path_refuses_writes_and_only_api_write_device_can_put(self):
        config.set_active(config.Config())
        legacy = config.active().legacy_api
        http = mock.Mock(return_value=({"data": []}, None))
        with mock.patch.object(api, "http_request", http):
            for method, path in (("PUT", f"{legacy}/rest/device/000000000000000000000003"),
                                 ("POST", f"{legacy}/cmd/devmgr"), ("DELETE", f"{legacy}/rest/user/x")):
                payload, err = api.api_call(method, path, {})
                self.assertIsNone(payload)
                self.assertIn("refused", err)
            http.assert_not_called()
            api.api_call("POST", config.active().v2_log, {"pageNumber": 0})
            self.assertEqual(http.call_args.args[0], "POST")
            http.reset_mock()
            http.return_value = (None, api.ApiError.of("http", "PUT failed"))
            api.api_write_device("000000000000000000000003", [{"radio": "na"}])
            self.assertEqual(http.call_count, 1)  # no retry on a write
            self.assertEqual(http.call_args.args[:3], ("PUT", f"{legacy}/rest/device/000000000000000000000003",
                                                       {"radio_table": [{"radio": "na"}]}))
            http.reset_mock()
            payload, err = api.api_write_device("../setting", [])
            self.assertIn("refused", err)
            http.assert_not_called()

    def test_source_has_one_http_entry_and_one_write_caller(self):
        users, callers = set(), set()
        for path in SRC.rglob("*.py"):
            tree = ast.parse(path.read_text())
            for fn in ast.walk(tree):
                if not isinstance(fn, ast.FunctionDef):
                    continue
                for node in ast.walk(fn):
                    name = node.attr if isinstance(node, ast.Attribute) else node.id if isinstance(node, ast.Name) else None
                    if name == "http_request":
                        users.add(fn.name)
                    if name == "api_write_device":
                        callers.add(fn.name)
        self.assertEqual(users, {"api_call", "api_write_device"})
        self.assertEqual(callers, {"set_power_apply"})


if __name__ == "__main__":
    unittest.main()

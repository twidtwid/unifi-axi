"""Test harness: a fake controller, a fake ssh, and run() that drives cli.main.

All fixtures are synthetic: locally administered MACs (02:...), documentation
IPs (192.0.2.x), sequential controller ids, made-up names. No test touches
the network or SSH: api.api_call and subprocess.run are replaced, and the real
HTTP layer (api.http_request) raises if anything reaches it.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from unittest import mock

from unifi_axi import api, cli, clock, ssh

FIXTURES = Path(__file__).parent / "fixtures"
PASSWORD = "Tr0ub4dor-fixture-pw-Q7"
API_KEY = "test-placeholder-api-key"
NOW = 1795143771  # 2026-11-19 19:02:51 PST, one minute after the stat/sta capture
ALEX = "02:00:00:00:a0:01"  # "Alex iPhone"
SAM = "02:00:00:00:a0:02"  # "Sam iPhone"
WATCH = "02:00:00:00:a0:03"  # "Alex Watch"
OFFICE_IP, DEN_IP, PATIO_IP, SHOP_IP = "192.0.2.92", "192.0.2.38", "192.0.2.169", "192.0.2.124"
AP_IPS = {OFFICE_IP: "office", DEN_IP: "den", PATIO_IP: "patio", SHOP_IP: "shop"}
OFFICE_ID = "000000000000000000000003"
WINDOW = ["--since", "2026-11-19 09:50", "--until", "2026-11-19 10:12"]
T10 = 1795111200  # 2026-11-19 10:00:00 PST
KERN = "kern.info kernel: wlan: [0:I:ANY] [UNSPECIFIED] "


def stamp(ts: float) -> str:
    return time.strftime("%a %b %d %H:%M:%S %Y", time.localtime(ts))


def local(text: str) -> float:
    return time.mktime(time.strptime(text, "%Y-%m-%d %H:%M:%S"))


def fixture_json(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text()


def ap_output(lines: list[str], epoch: int = NOW, date: str = "2026-11-19 19:02:51") -> str:
    head = [f"EPOCH {epoch}", f"DATE {date}", "FIRST Fri Oct 30 00:00:04 2026 user.warn kernel: boot", "---"]
    return "\n".join(head + lines) + "\n"


def event(key: str, ts_ms: int, mac: str, name: str, hostname: str = "iPhone", **params) -> dict:
    parameters = {"CLIENT": {"id": mac, "name": name, "hostname": hostname}}
    parameters.update(params)
    return {"key": key, "timestamp": ts_ms, "parameters": parameters}


def alex_event(key: str, ts: float, ap: str = "AP Office", rssi: int | None = None, **extra) -> dict:
    params = {"DEVICE": {"name": ap}, "RADIO_BAND": {"name": "na"}, **extra}
    if rssi is not None:
        params["SIGNAL_STRENGTH"] = {"name": str(rssi)}
    return event(key, int(ts * 1000), ALEX, "Alex iPhone", **params)


class FakeController:
    """Routes api_call(method, path, body) to fixtures. `pages` replaces system-log."""

    def __init__(self, pages: list | None = None, sta: dict | None = None, device: dict | None = None,
                 fail_pages: set[int] | None = None, fail_paths: set[str] | None = None,
                 wlanconf: dict | None = None, no_total: bool = False):
        self.sta = sta or fixture_json("stat-sta.json")
        self.device = device or fixture_json("stat-device.json")
        self.wlanconf = wlanconf
        self.pages = pages
        self.fail_pages = fail_pages or set()
        self.fail_paths = fail_paths or set()
        self.no_total = no_total
        self.calls: list[tuple[str, str, object]] = []
        self.read_kwargs: list[tuple[str, dict]] = []  # (path, kwargs) of every call that passed any
        self.read_hook = None  # called with the 1-based stat/device read number before the reply
        self.device_reads = 0
        self.clock = None  # FakeClock: with slow=True every read takes its full timeout
        self.slow = False

    def __call__(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, body))
        if kwargs:
            self.read_kwargs.append((path, kwargs))
        if self.slow and self.clock is not None and kwargs:  # only the bounded post-PUT reads
            self.clock.t += kwargs["timeout"]
        if any(path.endswith(f) for f in self.fail_paths):
            return None, f"GET {path.rsplit('/', 2)[-2]}/{path.rsplit('/', 1)[-1]} returned HTTP 500"
        if path.endswith("/stat/sta"):
            return self.sta, None
        if path.endswith("/rest/user"):
            return fixture_json("rest-user.json"), None
        if path.endswith("/stat/device"):
            self.device_reads += 1
            if self.read_hook:
                self.read_hook(self.device_reads)
            return copy.deepcopy(self.device), None  # a fresh object per read, like the wire
        if path.endswith("/rest/wlanconf"):
            return self.wlanconf or fixture_json("wlanconf.json"), None
        if path.endswith("/get/setting/mgmt"):
            return {"meta": {"rc": "ok"}, "data": [{"x_ssh_username": "fixtureuser", "x_ssh_password": PASSWORD}]}, None
        if path.endswith("/system-log/all"):
            assert method == "POST"
            number = body["pageNumber"]
            if number in self.fail_pages:
                return None, "POST system-log/all returned HTTP 500"
            if self.pages is None:
                payload = fixture_json("system-log-window.json")
                lo, hi = body["timestampFrom"], body["timestampTo"]
                payload["data"] = [e for e in payload["data"] if lo <= e["timestamp"] <= hi]
                payload["total_element_count"] = len(payload["data"])
                return payload, None
            data = self.pages[number] if number < len(self.pages) else []
            payload = {"data": data, "page_number": number, "total_element_count": sum(len(p) for p in self.pages)}
            if not self.no_total:
                payload["total_page_count"] = len(self.pages)
            return payload, None
        raise AssertionError(f"unexpected API call {method} {path}")


class FakeSSH:
    """Replaces subprocess.run for ssh. Maps the target IP to canned stdout.

    The remote end marker is appended like the real shell does, unless the IP is
    in `truncated`. `rewrite_header` (opt-in) moves EPOCH/DATE to the test clock.
    """

    def __init__(self, outputs: dict[str, str] | None = None, timeouts: set[str] | None = None,
                 rewrite_header: bool = False, truncated: set[str] | None = None,
                 rc: dict[str, int] | None = None, raises: set[str] | None = None):
        self.outputs = outputs or {}
        self.timeouts = timeouts or set()
        self.rewrite_header = rewrite_header
        self.truncated = truncated or set()
        self.rc = rc or {}
        self.raises = raises or set()
        self.calls: list[tuple[list[str], dict]] = []

    @classmethod
    def fixtures(cls, **kwargs) -> FakeSSH:
        # The fixtures were recorded a few minutes after NOW; present an AP clock
        # that agrees with the test clock so the epoch anchor adds no offset.
        outputs = {ip: fixture_text(f"ap-log-{name}.txt") for ip, name in AP_IPS.items()}
        return cls(outputs, rewrite_header=True, **kwargs)

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        target = argv[-2]
        ip = target.split("@", 1)[1]
        if ip in self.timeouts:
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 10))
        if ip in self.raises:
            raise RuntimeError(f"worker blew up near {PASSWORD}")
        text = self.outputs.get(ip, ap_output([]))
        if self.rewrite_header:
            text = re.sub(r"^EPOCH \d+", f"EPOCH {NOW}", text, flags=re.M)
            text = re.sub(r"^DATE .*$", "DATE " + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(NOW)), text,
                          flags=re.M)
        if ssh.END_MARKER in argv[-1] and ip not in self.truncated:
            text = text.rstrip("\n") + "\n" + ssh.END_MARKER + "\n"
        return subprocess.CompletedProcess(argv, self.rc.get(ip, 0), text, "")


def make_env(state_dir: str, **extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UNIFI_", "XDG_"))}
    env.update(UNIFI_API_KEY=API_KEY, UNIFI_URL="https://192.0.2.1", UNIFI_AXI_CONFIG=os.devnull + ".none",
               UNIFI_AXI_STATE_DIR=state_dir, UNIFI_ROAMING_SSIDS="ExampleLAN")
    env.update(extra)
    return env


_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


def unquote_toon(text: str) -> str:
    """Readable form for substring asserts: drop TOON string quotes and `- ` list markers.
    Strict TOON syntax is checked separately (test_toon_strict)."""
    def unq(m):
        return (m.group(1).replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\"))
    lines = [re.sub(r"^  - ", "  ", ln) for ln in text.split("\n")]
    return _QUOTED.sub(unq, "\n".join(lines))


def run(argv: list[str], controller: FakeController | None = None, ssh_fake: FakeSSH | None = None,
        state_dir: Path | None = None, extra: list | None = None, env: dict[str, str] | None = None
        , raw_output: bool = False) -> tuple[int, str]:
    controller = controller or FakeController()
    ssh_fake = ssh_fake or FakeSSH.fixtures()
    out = io.StringIO()
    with contextlib.ExitStack() as stack:
        if state_dir is None:
            state_dir = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        patches = [
            mock.patch.dict(os.environ, env if env is not None else make_env(str(state_dir)), clear=True),
            mock.patch.object(api, "api_call", controller),
            mock.patch.object(subprocess, "run", ssh_fake),
            mock.patch.object(clock, "now_ts", lambda: NOW),
            # Safety net: no test may reach the real HTTP layer, read or write.
            mock.patch.object(api, "http_request", mock.Mock(side_effect=AssertionError("real API reached"))),
        ]
        patches.extend(extra or [])
        for p in patches:
            stack.enter_context(p)
        stack.enter_context(contextlib.redirect_stdout(out))
        code = cli.main(argv)
    raw = out.getvalue()
    return code, (raw if raw_output or "--json" in argv else unquote_toon(raw))

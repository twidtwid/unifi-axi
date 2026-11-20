"""Parsing of AP-side text: syslog lines (client timeline), iwconfig +
hostapd_cli (verify), and kickout counts. Formats are those of UniFi AP
firmware 8.8.x on Qualcomm (qca_ol) radios; other firmware may differ.
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass, field
import re
import time
from typing import Any

from . import ssh
from .site import Site
from .util import UNKNOWN, int_or_none

MACP = r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
LINE_RE = re.compile(r"^(\w{3} \w{3} +\d{1,2} \d\d:\d\d:\d\d \d{4}) \S+ (.*)$")
PATTERNS = [
    ("auth", re.compile(r"vap-\d+\((\w+)\): \[" + MACP + r"\]recv auth frame with algorithm (\d+) seq \d+ rssi:(-?\d+)")),
    ("connected", re.compile(r"(\w+): AP-STA-CONNECTED " + MACP)),
    ("disconnected", re.compile(r"(\w+): AP-STA-DISCONNECTED " + MACP)),
    ("roamed", re.compile(r"(\w+): immediate disassoc for " + MACP + r" \(roamed\)")),
    ("kick", re.compile(r"Station " + MACP + r" kicked out reason: ([^,(]+)")),
    ("noack", re.compile(r"(\w+): STA " + MACP + r" IEEE 802\.11: did not acknowledge association response")),
    ("btm_req", re.compile(r"vap-\d+\((\w+)\):BTM: STA " + MACP + r" RSSI: (-?\d+)")),
    ("btm_resp", re.compile(r"vap-\d+\((\w+)\):BTM: Received response from \[" + MACP + r"\].*?status (\d+).*?bssid ([0-9a-fA-F:]{17}|n/a)")),
    ("auth_reject", re.compile(r"vap-\d+\((\w+)\):mlme_recv_auth_ap_defer\[\d+\]: client\[" + MACP + r"\] rejected, reason=(\d+)")),
    ("sample", re.compile(r"log_sta_anomalies\(\): bssid=\S+ radio=\S+ vap=(\w+) sta=" + MACP + r" signal=(-?\d+) satisfaction_now=(\d+) anomalies=(\S+)")),
]
IGNORE_RE = re.compile(r"UBNT_ROAM|STA-TRACKER|wevent|nl80211|IEEE 802\.11: (associated|disassociated|authenticated)|"
                       r"WPA: |EAPOL|RADIUS|DHCP-SM|HT: |station (re)?associated at aid|Assoc req for HT Node|No peer found|"
                       r"BTM: \[.*(quick reconnect|sent the same status)")
ALG = {"0": "open", "2": "ft", "3": "full_sae"}


@dataclass
class ApLog:
    ap: str
    ok: bool = False
    reason: str = ""
    lines: list[tuple[float, str]] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    oldest: float | None = None  # oldest line in /var/log/messages
    first_line: float | None = None  # oldest returned matched line
    capped: bool = False
    other_ts: list[float] = field(default_factory=list)
    skew: float = 0.0
    raw: str = ""

    def covers_from(self) -> float | None:
        return self.first_line if self.capped else self.oldest


def ap_clock(head: dict[str, str], now: float):
    """(to_ts, skew) from the EPOCH/DATE header. to_ts maps an AP syslog stamp
    to a UTC epoch: the AP's zone offset comes from DATE - EPOCH; when it equals
    this machine's offset the stamp is read with local rules, so lines from
    before a DST change map right. Raises KeyError/ValueError on a bad header."""
    epoch = int(head["EPOCH"])
    naive = calendar.timegm(time.strptime(head["DATE"], "%Y-%m-%d %H:%M:%S"))
    tz_shift = round((naive - epoch) / 900) * 900  # AP local-time offset from UTC
    skew = round(epoch - now)  # 1 s date resolution + SSH latency: ignore up to 2 s
    skew = skew if abs(skew) > 2 else 0
    local_offset = calendar.timegm(time.localtime(epoch)) - epoch
    same_zone = local_offset == tz_shift

    def to_ts(stamp: str) -> float | None:
        try:
            parsed = time.strptime(re.sub(r" +", " ", stamp), "%a %b %d %H:%M:%S %Y")
        except ValueError:
            return None
        base = time.mktime(parsed[:8] + (-1,)) if same_zone else calendar.timegm(parsed) - tz_shift
        return base - skew

    return to_ts, skew


def parse_ap_output(ap: str, text: str, macs: list[str], site: Site, now: float) -> ApLog:
    log = ApLog(ap=ap, ok=True, raw=text)
    header, _, body = text.partition("\n---\n")
    head = dict(line.split(" ", 1) for line in header.splitlines() if " " in line)
    try:
        to_ts, log.skew = ap_clock(head, now)
    except (KeyError, ValueError):
        return ApLog(ap=ap, ok=False, reason="shape: no EPOCH/DATE header", raw=text)
    m = LINE_RE.match(head.get("FIRST", ""))
    log.oldest = to_ts(m.group(1)) if m else None
    want = set(macs)
    parsed = []
    body_lines = [line for line in body.splitlines() if line.strip()]
    log.capped = len(body_lines) >= ssh.AP_TAIL_LINES
    for line in body_lines:
        m = LINE_RE.match(line)
        if not m:
            continue
        ts = to_ts(m.group(1))
        if ts is None:
            continue
        log.lines.append((ts, line))
        msg = m.group(2)
        for kind, rx in PATTERNS:
            hit = rx.search(msg)
            if hit:
                groups = hit.groups()
                mac = (groups[0] if kind == "kick" else groups[1]).lower()
                if mac in want:
                    parsed.append((ts, kind, groups))
                break
        else:
            if not IGNORE_RE.search(msg):
                log.other_ts.append(ts)
    if log.lines:
        log.first_line = log.lines[0][0]
    log.events = ap_events(ap, parsed, site)
    return log


def ap_events(ap: str, parsed: list[tuple], site: Site) -> list[dict]:
    """Per-station state is keyed by (vap, mac): several clients share a VAP,
    and a line about one must never complete or explain another's."""
    out: list[dict] = []
    pending: dict[tuple[str, str], tuple[float, str, str]] = {}  # (vap, mac) -> (ts, alg, rssi)
    roamed: dict[tuple[str, str], float] = {}
    noack: dict[tuple[str, str], float] = {}
    kick: dict[str, tuple[float, str]] = {}  # mac -> (ts, reason); the kick line names no VAP

    def ft_fail(key: tuple[str, str], p: tuple, until: float) -> None:
        vap = key[0]
        detail = "FT auth seen, no AP-STA-CONNECTED"
        if key in noack and p[0] - 1 <= noack[key] <= until:
            detail += "; did not acknowledge association response"
        out.append({"t": p[0], "ap": ap, "band": site.vap_band(ap, vap), "vap": vap, "kind": "ft_fail",
                    "auth_rssi": p[2], "detail": detail})

    for ts, kind, g in parsed:
        if kind == "kick":
            kick[g[0].lower()] = (ts, g[1].strip())
            continue
        key = (g[0], g[1].lower())
        if kind == "auth":
            vap, _, alg, rssi = g
            prev = pending.get(key)
            if prev and prev[1] == "2" and (alg != "2" or ts - prev[0] > 5):
                ft_fail(key, prev, ts)
            pending[key] = (ts, alg, rssi)
        elif kind == "connected":
            vap = g[0]
            p = pending.pop(key, None)
            if p and ts - p[0] > 10:
                p = None  # stale auth: neither its alg nor its RSSI belongs to this join
            out.append({"t": ts, "ap": ap, "band": site.vap_band(ap, vap), "vap": vap, "kind": "join",
                        "alg": p[1] if p else None, "auth_rssi": p[2] if p else None})
        elif kind == "roamed":
            roamed[key] = ts
        elif kind == "noack":
            noack[key] = ts
        elif kind == "disconnected":
            vap = g[0]
            if key in roamed and ts - roamed[key] <= 3:
                out.append({"t": ts, "ap": ap, "band": site.vap_band(ap, vap), "vap": vap, "kind": "left"})
            else:
                k = kick.get(key[1])
                reason = k[1] if k and 0 <= ts - k[0] <= 3 else None
                out.append({"t": ts, "ap": ap, "band": site.vap_band(ap, vap), "vap": vap, "kind": "disconnect",
                            "reason": reason})
        elif kind == "auth_reject":
            out.append({"t": ts, "ap": ap, "band": site.vap_band(ap, g[0]), "vap": g[0], "kind": "auth_reject",
                        "reason": g[2]})
        elif kind == "sample":
            out.append({"t": ts, "ap": ap, "band": site.vap_band(ap, g[0]), "vap": g[0], "kind": "sample",
                        "rssi": int(g[2]), "detail": f"mcad satisfaction_now={g[3]} anomalies={g[4]}"})
        elif kind == "btm_req":
            out.append({"t": ts, "ap": ap, "band": site.vap_band(ap, g[0]), "vap": g[0], "kind": "btm_req",
                        "rssi": int(g[2])})
        elif kind == "btm_resp":
            target = site.bssid.get(g[3].lower(), (None, None))[0] if g[3] != "n/a" else None
            out.append({"t": ts, "ap": ap, "band": site.vap_band(ap, g[0]), "vap": g[0], "kind": "btm_resp",
                        "status": int(g[2]), "target": target})
    for key, p in pending.items():
        if p[1] == "2":
            ft_fail(key, p, p[0] + 5)
    return out


# --------------------------------------------------------------------------
# verify: iwconfig + hostapd_cli get_config.

def parse_verify(text: str) -> tuple[dict[str, dict], int | None]:
    epoch = None
    ifaces: dict[str, dict] = {}
    section, current = None, None
    for line in text.splitlines():
        if line.startswith("EPOCH "):
            epoch = int_or_none(line.split()[1])
            continue
        if line.startswith("---IWCONFIG"):
            section = "iw"
            continue
        if line.startswith("---HOSTAPD "):
            section, current = "hostapd", line.split()[1]
            ifaces.setdefault(current, {})
            continue
        if section == "iw":
            m = re.match(r"^(\S+)\s+IEEE 802\.11\S*\s+ESSID:\"([^\"]*)\"", line)
            if m:
                current = m.group(1)
                ifaces.setdefault(current, {})["essid"] = m.group(2)
                continue
            if current and line.startswith(" "):
                f = re.search(r"Frequency:([\d.]+) GHz", line)
                if f:
                    ifaces[current]["freq"] = float(f.group(1))
                p = re.search(r"Tx-Power=(\d+) dBm", line)
                if p:
                    ifaces[current]["tx_power"] = int(p.group(1))
            elif line and not line.startswith(" "):
                current = None
        elif section == "hostapd" and current and "=" in line:
            k, v = line.split("=", 1)
            if k in ("ssid", "bssid", "key_mgmt"):
                ifaces[current][k] = v.strip()
    return ifaces, epoch


def freq_band_channel(freq: float | None) -> tuple[str, Any]:
    if freq is None:
        return UNKNOWN, UNKNOWN
    mhz = round(freq * 1000)
    if mhz < 3000:
        return "2.4", (mhz - 2407) // 5
    if mhz < 5925:
        return "5", (mhz - 5000) // 5
    return "6", (mhz - 5950) // 5


# --------------------------------------------------------------------------
# kickout: Qualcomm firmware station kickouts (see README "Qualcomm kickout").

KICK_RE = re.compile(r"ol_peer_sta_kickout_event_handler: Station " + MACP + r" kicked out reason: ([^,(]+)")
RETRY_MAC_RE = re.compile(r"Station " + MACP + r" kicked out reason: Excessive Retries")


@dataclass
class KickoutRead:
    ok: bool = False
    reason: str = ""
    uptime_s: float | None = None
    dmesg_count: int | None = None
    log_count: int | None = None
    log_from: float | None = None
    macs: dict[str, int] = field(default_factory=dict)  # mac -> kick lines (dmesg and log, deduped by text)
    reasons: dict[str, int] = field(default_factory=dict)


def parse_kickout(text: str, now: float) -> KickoutRead:
    out = KickoutRead(ok=True)
    head, section, dmesg, logs = {}, None, [], []
    for line in text.splitlines():
        if line == "---DMESG":
            section = "dmesg"
            continue
        if line == "---LOG":
            section = "log"
            continue
        if section is None and " " in line:
            k, v = line.split(" ", 1)
            head[k] = v
        elif section == "dmesg" and line.strip():
            dmesg.append(line)
        elif section == "log" and line.strip():
            logs.append(line)
    out.dmesg_count = int_or_none(head.get("DMESG_COUNT"))
    out.log_count = int_or_none(head.get("LOG_COUNT"))
    try:
        out.uptime_s = float(head.get("UPTIME", ""))
    except ValueError:
        out.uptime_s = None
    if out.dmesg_count is None or out.log_count is None:
        return KickoutRead(ok=False, reason="shape: no DMESG_COUNT/LOG_COUNT header")
    m = LINE_RE.match(head.get("FIRST", ""))
    if m:
        try:
            to_ts, _ = ap_clock(head, now)
            out.log_from = to_ts(m.group(1))
        except (KeyError, ValueError):
            out.log_from = None
    # dmesg holds the current boot; the syslog file can repeat the same kernel
    # lines. Count MACs from the syslog lines when there are any, else dmesg.
    for line in logs or dmesg:
        k = KICK_RE.search(line) or RETRY_MAC_RE.search(line)
        if not k:
            continue
        mac = k.group(1).lower()
        out.macs[mac] = out.macs.get(mac, 0) + 1
        reason = k.group(2).strip() if k.re is KICK_RE else "Excessive Retries"
        out.reasons[reason] = out.reasons.get(reason, 0) + 1
    return out

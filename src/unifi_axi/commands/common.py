"""Helpers shared by the commands: captures, lookup errors, AP radio rows."""

from __future__ import annotations

import os
import re
import time
from typing import Any

from .. import api, clock, config
from ..site import Ambiguous, NoMatch, Site, ap_online, build_site, resolve_ap
from ..toon import Doc
from ..util import BAND, UNKNOWN, client_label, hms, private_dir, tilde, write_private_json


class Saver:
    """--save: raw captures under <state>/captures/<ts>-<cmd>/ (mode 0700, secrets stripped)."""

    def __init__(self, enabled: bool, label: str):
        self.dir = None
        if enabled:
            root = config.active().captures_dir
            self.dir = root / f"{time.strftime('%Y%m%d-%H%M%S', time.localtime(clock.now_ts()))}-{label}"
            private_dir(self.dir, exist_ok=True)
            os.chmod(root, 0o700)
            os.chmod(root.parent, 0o700)

    def json(self, name: str, data: Any) -> None:
        if self.dir:
            write_private_json(self.dir, name, data)

    def text(self, name: str, text: str) -> None:
        if self.dir:
            path = self.dir / name
            path.write_text(text)
            os.chmod(path, 0o600)

    def report(self, doc: Doc) -> None:
        if self.dir:
            doc.kv("saved", tilde(self.dir))


def lookup_failures(**errors: str | None) -> list[str]:
    """Names of failed name-lookup sources, e.g. ['rest/user FAILED (HTTP 500)']."""
    return [f"{name} FAILED ({err})" for name, err in errors.items() if err]


def no_match(doc: Doc, query: str, failed: list[str], hint: str | None) -> int:
    if failed:
        doc.kv("error", f'cannot resolve "{query}": lookup incomplete: {"; ".join(failed)}')
    else:
        doc.kv("error", f'0 clients match "{query}"')
    if hint:
        doc.kv("help", hint)
    return 1


def print_ambiguous(doc: Doc, amb: Ambiguous, site: Site, now: float, what: str, rest: str = "") -> int:
    kind = "clients" if what in ("client", "drops") else "APs"
    doc.kv("error", f'{len(amb.candidates)} {kind} match "{amb.query}"')
    rows = []
    for c in amb.candidates:
        item = c.get("item") or {}
        ap = site.ap_name(item.get("ap_mac")) or ""
        seen = f"{int(now - item['last_seen'])}s" if isinstance(item.get("last_seen"), (int, float)) else ""
        rows.append({"name": client_label(c.get("name"), c.get("hostname"), c.get("mac") or ""), "mac": c.get("mac"),
                     "ap": ap, "last_seen": seen})
    doc.table("candidates", ["name", "mac", "ap", "last_seen"], rows)
    if what == "client":
        doc.kv("help", "unifi-axi client <mac> --since 10m")
    elif what == "drops":
        doc.kv("help", "unifi-axi drops --client <mac>")
    else:
        doc.kv("help", f"unifi-axi {what} <exact AP name>{' ' + rest if rest else ''}")
    return 1


def load_site(doc: Doc, suffix: str = "") -> Site | None:
    devices, err = api.legacy_list("stat/device")
    if err:
        doc.kv("error", f"stat/device failed: {err}{suffix}")
        doc.kv("help", "unifi-axi cert  (TLS/pin problems) or check UNIFI_URL / UNIFI_API_KEY")
        return None
    return build_site(devices)


def pick_ap(doc: Doc, site: Site, query: str, what: str, rest: str = "") -> tuple[dict | None, int]:
    """(ap, 0) or (None, exit code) with the error already in doc."""
    try:
        return resolve_ap(query, site.aps), 0
    except Ambiguous as amb:
        return None, print_ambiguous(doc, amb, site, clock.now_ts(), what, rest)
    except NoMatch:
        doc.kv("error", f'0 APs match "{query}"')
        doc.kv("help", "unifi-axi aps")
        return None, 1


def radio_rows(ap: dict) -> list[dict]:
    stats = {r.get("radio"): r for r in ap.get("radio_table_stats") or []}
    rows = []
    for cfg in ap.get("radio_table") or []:
        band = BAND.get(cfg.get("radio"), cfg.get("radio") or UNKNOWN)
        live = stats.get(cfg.get("radio"), {})
        mode = cfg.get("tx_power_mode")
        if mode == "auto":
            pwr_cfg = "auto"
        elif mode == "custom":
            pwr_cfg = cfg.get("tx_power", UNKNOWN)
        else:
            pwr_cfg = mode or UNKNOWN
        ch_cfg = cfg.get("channel", UNKNOWN)
        ch_cfg = "auto" if str(ch_cfg) in ("0", "auto") else ch_cfg
        online = ap_online(ap)
        rows.append({"ap": ap.get("name"), "band": band, "ch_cfg": ch_cfg,
                     "ch_live": live.get("channel", UNKNOWN) if online else "offline(controller)",
                     "width": cfg.get("ht", UNKNOWN), "pwr_cfg": pwr_cfg,
                     "pwr_live": live.get("tx_power", UNKNOWN) if online else UNKNOWN,
                     "util": live.get("cu_total", UNKNOWN) if online else UNKNOWN,
                     "sta": live.get("num_sta", UNKNOWN) if online else UNKNOWN,
                     "min_rssi": cfg.get("min_rssi") if cfg.get("min_rssi_enabled") else "off",
                     "pwr_range": f"{cfg.get('min_txpower', '?')}..{cfg.get('max_txpower', '?')}"})
    return rows


def mismatches(rows: list[dict]) -> list[dict]:
    out = []
    for r in rows:
        if r["ch_live"] == "offline(controller)":
            continue
        if isinstance(r["pwr_cfg"], int) and r["pwr_live"] != UNKNOWN and str(r["pwr_cfg"]) != str(r["pwr_live"]):
            out.append({"ap": r["ap"], "band": r["band"], "field": "pwr", "cfg": r["pwr_cfg"], "live": r["pwr_live"]})
        if r["ch_cfg"] not in ("auto", UNKNOWN) and r["ch_live"] != UNKNOWN and str(r["ch_cfg"]) != str(r["ch_live"]):
            out.append({"ap": r["ap"], "band": r["band"], "field": "ch", "cfg": r["ch_cfg"], "live": r["ch_live"]})
    return out


def aps_header(site: Site, now: float) -> str:
    online = sum(1 for a in site.aps if ap_online(a))
    versions = sorted({a.get("version") or UNKNOWN for a in site.aps})
    if not versions:
        fw = UNKNOWN
    else:
        fw = f"{versions[0]} (all)" if len(versions) == 1 else "mixed(" + ",".join(versions) + ")"
    clients = sum(int(a.get("num_sta") or 0) for a in site.aps if ap_online(a))
    return f"{online} of {len(site.aps)} online  fw={fw}  wifi_clients={clients}  as_of={hms(now)}"


def ap_slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (name or "ap").lower()).strip("-") or "ap"

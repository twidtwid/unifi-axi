"""`clients`: wireless clients from stat/sta, weakest signal first."""

from __future__ import annotations

from .. import api
from ..site import build_site
from ..toon import Doc
from ..util import BAND, UNKNOWN, client_label

CLIENTS_CAP = 50


def cmd_clients(args, doc: Doc) -> int:
    sta, err = api.legacy_list("stat/sta")
    if err:
        doc.kv("error", f"stat/sta failed: {err}")
        doc.kv("help", "check UNIFI_URL and the API key; unifi-axi cert shows the controller certificate")
        return 1
    devices, _ = api.legacy_list("stat/device")
    site = build_site(devices or [])
    wireless = [s for s in sta if s.get("is_wired") is False]
    if args.grep:
        g = args.grep.lower()
        wireless = [s for s in wireless if g in f"{s.get('name') or ''} {s.get('hostname') or ''} {s.get('mac') or ''}".lower()]
    wireless.sort(key=lambda s: s.get("signal") if isinstance(s.get("signal"), int) else 0)
    scope = f" matching {args.grep!r}" if args.grep else ""
    doc.kv("summary", f"{len(wireless)} wireless{scope} ({len(sta)} total in stat/sta)")
    if not wireless:
        doc.kv("help", "unifi-axi clients  (no --grep) or unifi-axi drops --since 24h")
        return 0
    rows = [{"name": client_label(s.get("name"), s.get("hostname"), s.get("mac") or ""), "mac": s.get("mac"),
             "ap": site.ap_name(s.get("ap_mac")) or UNKNOWN,
             "band": BAND.get(s.get("radio"), UNKNOWN), "signal": s.get("signal", UNKNOWN),
             "hostname": s.get("hostname"), "ip": s.get("ip"), "essid": s.get("essid"),
             "channel": s.get("channel"), "satisfaction": s.get("satisfaction")} for s in wireless]
    cap = len(rows) if args.full else CLIENTS_CAP
    doc.table("clients", ["name", "mac", "ap", "band", "signal"], rows[:cap])
    if len(rows) > cap:
        doc.kv("more", f"{len(rows) - cap} rows hidden. Add --full.")
    doc.kv("help", 'unifi-axi client "<name|mac>" --since 30m')
    return 0

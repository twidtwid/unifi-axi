"""`aps`: configured vs live channel and power per radio (controller telemetry)."""

from __future__ import annotations

from .. import clock
from ..site import ap_online
from ..toon import Doc
from ..util import UNKNOWN, uptime_text
from .common import aps_header, load_site, mismatches, pick_ap, radio_rows


def cmd_aps(args, doc: Doc) -> int:
    site = load_site(doc)
    if site is None:
        return 1
    aps = site.aps
    if args.name:
        ap, code = pick_ap(doc, site, args.name, "aps")
        if ap is None:
            return code
        aps = [ap]
    doc.kv("aps", aps_header(site, clock.now_ts()))
    if not aps:
        doc.kv("radios", "0 access points on this site (stat/device has no type=uap devices)")
        return 0
    offline = [a for a in aps if not ap_online(a)]
    if offline:
        doc.table("offline", ["ap", "state"], [{"ap": a.get("name"), "state": f"offline(controller) state={a.get('state', UNKNOWN)}"}
                                               for a in offline])
    rows = [r for ap in aps for r in radio_rows(ap)]
    cols = ["ap", "band", "ch_cfg", "ch_live", "width", "pwr_cfg", "pwr_live", "util", "sta"]
    if args.name:
        ap = aps[0]
        up = ap.get("uplink") or {}
        doc.kv("ap", f"{ap.get('name')}  model={ap.get('model', UNKNOWN)}  ip={ap.get('ip', UNKNOWN)}  "
                     f"uplink={up.get('speed', UNKNOWN)}{' FD' if up.get('full_duplex') else ''}  "
                     f"uptime={uptime_text(ap.get('uptime'))}  fw={ap.get('version', UNKNOWN)}")
        cols += ["min_rssi", "pwr_range"]
    doc.table("radios", cols, rows)
    mm = mismatches(rows)
    if mm:
        doc.table("mismatch", ["ap", "band", "field", "cfg", "live"], mm)
    else:
        doc.kv("mismatch", "none")
    doc.kv("help", "pwr_live is controller telemetry; unifi-axi verify <ap> reads the device")
    return 0

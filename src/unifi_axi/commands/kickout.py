"""`kickout`: Qualcomm firmware station kickouts per AP (read-only).

U7/E7 APs (qca_ol driver) disconnect a client after a run of unacknowledged
frames: `ol_peer_sta_kickout_event_handler: Station <mac> kicked out reason:
Excessive Retries`. The controller shows only a disconnect. Per AP this
counts those lines in dmesg (current boot) and `Excessive Retries` lines in
/var/log/messages, lists the most-kicked MACs, and the AP uptime (a reboot
clears dmesg and any runtime workaround). It changes nothing on the AP.
"""

from __future__ import annotations

import time

from .. import api, aplog, clock, ssh
from ..aplog import KickoutRead
from ..site import ap_online, build_site
from ..toon import Doc
from ..util import UNKNOWN, client_label, hm, parallel, uptime_text
from .common import Saver, ap_slug, pick_ap

TOP_CAP = 10


def since_text(ts: float | None, now: float) -> str:
    """HH:MM for today, MM/DD HH:MM otherwise (a rotated log can be weeks old)."""
    if not ts:
        return UNKNOWN
    same_day = time.strftime("%Y%m%d", time.localtime(ts)) == time.strftime("%Y%m%d", time.localtime(now))
    return hm(ts) if same_day else time.strftime("%m/%d %H:%M", time.localtime(ts))


def cmd_kickout(args, doc: Doc) -> int:
    devices, err = api.legacy_list("stat/device")
    if err:
        doc.kv("error", f"stat/device failed: {err}")
        doc.kv("help", "check UNIFI_URL and the API key; unifi-axi cert shows the controller certificate")
        return 1
    site = build_site(devices)
    targets = site.aps
    if args.ap:
        ap, code = pick_ap(doc, site, args.ap, "kickout")
        if ap is None:
            return code
        targets = [ap]
    if not targets:
        doc.kv("kickout", "0 access points on this site (stat/device has no type=uap devices)")
        return 0
    user, password, cred_err = ssh.ssh_creds()
    saver = Saver(args.save, "kickout")
    now = clock.now_ts()

    def fetch(ap: dict) -> KickoutRead:
        if not ap_online(ap):
            return KickoutRead(reason="offline(controller)")
        if cred_err:
            return KickoutRead(reason=f"no SSH credentials: {cred_err}")
        text, e, _ = ssh.ssh_run(ap.get("ip"), user, password, ssh.KICKOUT_COMMAND)
        if e:
            return KickoutRead(reason=e)
        saver.text(f"kickout-{ap_slug(ap.get('name') or 'ap')}.txt", text)
        return aplog.parse_kickout(text, now)

    reads = parallel(fetch, targets, lambda ap, exc: KickoutRead(reason=f"internal: {type(exc).__name__}"))
    sta, _ = api.legacy_list("stat/sta")
    users, _ = api.legacy_list("rest/user")
    names = {}
    for item in (users or []) + (sta or []):
        mac = (item.get("mac") or "").lower()
        if mac:
            names[mac] = client_label(item.get("name"), item.get("hostname"), mac)

    rows, bad, per_mac = [], [], {}
    for ap, r in zip(targets, reads):
        name = ap.get("name")
        if not r.ok:
            bad.append({"ap": name, "reason": r.reason})
            continue
        uptime = r.uptime_s if r.uptime_s is not None else ap.get("uptime")
        rows.append({"ap": name, "dmesg_kicks": r.dmesg_count, "log_retries": r.log_count,
                     "log_from": since_text(r.log_from, now), "uptime": uptime_text(uptime),
                     "model": ap.get("model"), "fw": ap.get("version")})
        for mac, n in r.macs.items():
            entry = per_mac.setdefault(mac, {"mac": mac, "client": names.get(mac, client_label(None, None, mac)),
                                             "kicks": 0, "aps": set()})
            entry["kicks"] += n
            entry["aps"].add(name)
    total_dmesg = sum(r["dmesg_kicks"] for r in rows)
    total_log = sum(r["log_retries"] for r in rows)
    doc.kv("kickout", f"{total_dmesg} dmesg kicks, {total_log} 'Excessive Retries' log lines "
                      f"on {len(rows)}/{len(targets)} APs read")
    if bad:
        doc.table("unreachable", ["ap", "reason"], bad)
    if rows:
        doc.table("aps", ["ap", "dmesg_kicks", "log_retries", "log_from", "uptime"], rows)
    top = sorted(per_mac.values(), key=lambda e: (-e["kicks"], e["mac"]))
    cap = len(top) if args.full else TOP_CAP
    if top:
        doc.table("top_clients", ["client", "mac", "kicks", "aps"],
                  [{**e, "aps": "/".join(sorted(e["aps"]))} for e in top[:cap]])
        if len(top) > cap:
            doc.kv("more", f"{len(top) - cap} clients hidden. Add --full.")
        doc.kv("help", "unifi-axi client <mac> --since 24h  (kick -> disconnect -> drop rows)")
    elif rows:
        doc.kv("top_clients", "0 kicked stations in the lines read")
    saver.report(doc)
    return 1 if bad else 0

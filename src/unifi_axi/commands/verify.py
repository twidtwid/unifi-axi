"""`verify`: read iwconfig + hostapd_cli on the AP and compare with the controller.

FT rule (ft_suites): WPA3 clients are admitted when wpa3_support is on, WPA2
clients when it is off or in transition mode. Every enabled WLAN is checked
against its own flags (the device must run the FT suites its config turns on).
A WLAN named in UNIFI_ROAMING_SSIDS must also have FT for every admitted class.

Result words: PASS; MISMATCH (exit 3) when a device value differs from the
controller; UNVERIFIED (exit 1) when a device value could not be read. An
unread value is never reported as MISMATCH.
"""

from __future__ import annotations

from .. import api, aplog, config, ssh
from ..site import ap_online
from ..toon import Doc
from ..util import UNKNOWN, UsageError, is_int, parallel, tokens
from .common import load_site, pick_ap, radio_rows

FT_SUITES = {"wpa2": "FT-PSK", "wpa3": "FT-SAE"}


def ft_suites(w: dict, roaming_ssids: tuple[str, ...] | None = None) -> tuple[set[str], set[str]]:
    """(required, configured) FT key suites for one wlanconf row. `required -
    configured` non-empty means a roaming SSID lacks FT for a client class."""
    roaming = config.active().roaming_ssids if roaming_ssids is None else roaming_ssids
    wpa3 = bool(w.get("wpa3_support"))
    wpa2 = not wpa3 or bool(w.get("wpa3_transition"))
    configured = set()
    if wpa2 and w.get("fast_roaming_enabled"):
        configured.add(FT_SUITES["wpa2"])
    if wpa3 and w.get("wpa3_fast_roaming"):
        configured.add(FT_SUITES["wpa3"])
    if w.get("name") in roaming and w.get("enabled", True):
        required = {FT_SUITES[c] for c, on in (("wpa2", wpa2), ("wpa3", wpa3)) if on}
    else:
        required = set(configured)
    return required, configured


def verify_failed(doc: Doc, ap: dict, err: str) -> str:
    doc.kv("verify", f"{ap.get('name')} ({ap.get('ip', UNKNOWN)})  fw={ap.get('version', UNKNOWN)}  ssh=FAILED ({err})")
    doc.table("radios_ctl", ["band", "ch_cfg", "ch_live", "pwr_cfg", "pwr_live"],
              [{k: r[k] for k in ("band", "ch_cfg", "ch_live", "pwr_cfg", "pwr_live")} for r in radio_rows(ap)])
    doc.kv("result", "UNVERIFIED  controller values only (labelled radios_ctl); device not read")
    return "UNVERIFIED"


def verify_one(ap: dict, creds, wlans: list[dict], doc: Doc, out_rows: list | None = None) -> str:
    name = ap.get("name")
    cfg_rows = {r["band"]: r for r in radio_rows(ap)}
    if not ap_online(ap):
        text, err, took = None, "offline(controller)", 0.0
    elif creds[2]:
        text, err, took = None, f"no SSH credentials: {creds[2]}", 0.0
    else:
        text, err, took = ssh.ssh_run(ap.get("ip"), creds[0], creds[1], ssh.VERIFY_COMMAND)
    if err:
        return verify_failed(doc, ap, err)
    doc.kv("verify", f"{name} ({ap.get('ip', UNKNOWN)})  fw={ap.get('version', UNKNOWN)}  ssh=ok {took:.1f}s")
    wlan_by_name = {w.get("name"): w for w in wlans}
    ifaces, _ = aplog.parse_verify(text)
    rows, power_checked, ft_need, ft_ok, bad, unread_any = [], {}, 0, 0, False, False
    for iface in sorted(ifaces):
        info = ifaces[iface]
        ssid = info.get("ssid") or info.get("essid")
        if ssid not in wlan_by_name:
            continue
        band, ch = aplog.freq_band_channel(info.get("freq"))
        cfg = cfg_rows.get(band, {})
        key_mgmt = info.get("key_mgmt", UNKNOWN)
        required, _ = ft_suites(wlan_by_name[ssid])
        missing = required - set(key_mgmt.split())
        marks, unread = [], []  # unread: the device value was not read, so nothing is proven
        if not required:
            ft = "n/a"
        elif key_mgmt == UNKNOWN:
            ft = UNKNOWN
            ft_need += 1
            unread.append("key_mgmt")
        else:
            ft = "yes" if not missing else "no"
            ft_need += 1
            ft_ok += not missing
            if missing:
                marks.append("ft(" + "/".join(sorted(missing)) + ")" if missing != required else "ft")
        pwr_dev = info.get("tx_power", UNKNOWN)
        pwr_cfg = cfg.get("pwr_cfg", UNKNOWN)
        if isinstance(pwr_cfg, int):
            if not is_int(pwr_dev):
                power_checked[band] = False
                unread.append("pwr")
            else:
                same = pwr_dev == pwr_cfg
                power_checked[band] = power_checked.get(band, True) and same
                if not same:
                    marks.append("pwr")
        ch_cfg = cfg.get("ch_cfg", UNKNOWN)
        if ch_cfg not in ("auto", UNKNOWN) and str(ch_cfg) != str(ch):
            marks.append("ch")
        bad |= bool(marks)
        unread_any |= bool(unread)
        rows.append({"band": band, "iface": iface, "ssid": ssid, "ch_dev": ch, "pwr_dev": pwr_dev, "pwr_cfg": pwr_cfg,
                     "key_mgmt": key_mgmt, "ft": ft, "mismatch": ",".join(marks), "unread": ",".join(unread)})
    cols = ["band", "iface", "ssid", "ch_dev", "pwr_dev", "pwr_cfg", "key_mgmt", "ft"]
    if bad:
        cols.append("mismatch")
    if unread_any:
        cols.append("unread")
    rows.sort(key=lambda r: (float(r["band"]) if r["band"] != UNKNOWN else 99, r["iface"]))
    doc.table("radios", cols, rows)
    if out_rows is not None:
        out_rows.extend(rows)
    power_ok = sum(1 for v in power_checked.values() if v)
    # A proven difference is MISMATCH; a device value that was not read is
    # UNVERIFIED (exit 1), never MISMATCH (the same rule as band_check).
    word = "MISMATCH" if bad else ("UNVERIFIED" if unread_any else "PASS")
    if not rows:
        word = "UNVERIFIED"
    doc.kv("result", f"{word}  power {power_ok}/{len(power_checked)} custom radios match; "
                     f"FT on {ft_ok}/{ft_need} FT-configured radios")
    return word


def cmd_verify(args, doc: Doc) -> int:
    if args.all and args.ap:
        raise UsageError("verify takes <ap> or --all, not both")
    if not args.all and not args.ap:
        raise UsageError("verify needs <ap> or --all")
    if args.ap and not tokens(args.ap):  # usage error before any read
        raise UsageError(f"AP name {args.ap!r} has no letters or digits")
    site = load_site(doc)
    if site is None:
        return 1
    if args.all:
        targets = site.aps
        if not targets:
            doc.kv("verify", "0 access points on this site (stat/device has no type=uap devices)")
            return 0
    else:
        ap, code = pick_ap(doc, site, args.ap, "verify")
        if ap is None:
            return code
        targets = [ap]
    wlans, werr = api.legacy_list("rest/wlanconf")
    if werr:
        doc.kv("error", f"rest/wlanconf failed: {werr}")
        return 1
    creds = ssh.ssh_creds()
    docs = [Doc(doc.fields) for _ in targets]
    def failed_verify(pair, exc: Exception) -> str:
        pair[1].blocks.clear()
        return verify_failed(pair[1], pair[0], f"internal: {type(exc).__name__}")

    results = parallel(lambda pair: verify_one(pair[0], creds, wlans, pair[1]), list(zip(targets, docs)),
                       failed_verify)
    for d in docs:
        if len(targets) > 1:
            doc.group("aps", d)
        else:
            doc.blocks.extend(d.blocks)
    if len(targets) > 1:
        doc.kv("overall", " ".join(f"{t.get('name')}={r}" for t, r in zip(targets, results)))
    if "UNVERIFIED" in results:
        return 1
    return 3 if "MISMATCH" in results else 0

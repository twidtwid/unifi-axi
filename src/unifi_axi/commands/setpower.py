"""`set-power`: the one command that writes, and only with --confirm after every guard.

Flow: preview by default (nothing sent). With --confirm and the exact AP name
or MAC: refuse unless online, the radio exists, the target is inside
min_txpower..max_txpower, SSH credentials and wlanconf are readable and the
radio serves an SSID; re-read stat/device and refuse if any non-derived
radio_table field changed; write evidence (before.json, put.json); send ONE
PUT of the full radio_table (api.api_write_device, no retry); poll until
state 1 AND cfgversion/provisioned_at moved (or a non-1 state was seen) AND
the target is in radio_table; read Tx-Power on the device until it matches,
all inside POLL_LIMIT_S of the write. The device value decides: PASS (0),
MISMATCH or drift (3), UNVERIFIED / timeout / failure (1). Every path after
the PUT prints the change-log stub and the undo command.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
import re
import shlex
import time

from .. import api, clock, config, ssh
from ..api import DEVICE_ID_RE
from ..site import ap_online, build_site, exact_ap
from ..toon import Doc
from ..util import BAND, BAND_TOKENS, UNKNOWN, UsageError, hms, is_int, private_dir, tilde, write_private_json
from .common import ap_slug, pick_ap
from .verify import verify_one

POLL_SETTLE_S = 10  # first wait after the PUT: provisioning may not have started yet
POLL_EVERY_S = 5
POLL_LIMIT_S = 120  # from the PUT; bounds the poll, the on-device re-reads and every read in them
READ_LIMIT_S = 20  # one bounded stat/device read in the poll (no retry)
LIVE_CALL_TEXT = "do not apply during a live call or walk test; the change can drop clients on this radio"


def radio_index(ap: dict, radio: str) -> tuple[int | None, str | None]:
    hits = [i for i, r in enumerate(ap.get("radio_table") or []) if isinstance(r, dict) and r.get("radio") == radio]
    if not hits:
        return None, f"{ap.get('name')} has no {BAND[radio]} GHz radio in radio_table"
    if len(hits) > 1:
        return None, f"{ap.get('name')} has {len(hits)} {radio} entries in radio_table; refusing"
    return hits[0], None


def power_text(cfg: dict) -> str:
    if cfg.get("tx_power_mode") == "custom":
        return str(cfg.get("tx_power", UNKNOWN))
    return str(cfg.get("tx_power_mode") or UNKNOWN)


def target_text(target: int | str, auto_power: int | None = None) -> str:
    if target == "auto":
        return "auto" if auto_power is None else f"auto (tx_power {auto_power})"
    return f"{target} dBm"


def target_args(target: int | str, auto_power: int | None = None) -> str:
    """The set-power arguments that reach this target (help and undo lines)."""
    return f"auto --tx-power {auto_power}" if target == "auto" and auto_power is not None else str(target)


def parse_target(text: str) -> int | str:
    if text.strip().lower() == "auto":
        return "auto"
    if re.fullmatch(r"-?\d+", text.strip()):
        return int(text)
    raise UsageError(f"dBm {text!r}: use a whole number of dBm or auto")


def table_diff(old: list[dict], new: list[dict]) -> set[tuple[int, str]]:
    """(radio index, field) for every field that differs; (-1, 'length') if the list size changed."""
    if not isinstance(old, list) or not isinstance(new, list) or len(old) != len(new):
        return {(-1, "length")}
    out = set()
    for i, (a, b) in enumerate(zip(old, new)):
        if not isinstance(a, dict) or not isinstance(b, dict):
            if a != b:
                out.add((i, "*"))
            continue
        for k in set(a) | set(b):
            if k not in a or k not in b or a[k] != b[k]:
                out.add((i, k))
    return out


# radio_table fields the controller fills from what the device reports, not
# from the config we PUT: they may change after any provisioning without
# anyone touching the config, so the post-write drift check ignores them.
#   current_antenna_gain: computed from the antenna model and band
#   radio_caps, radio_caps2: capability bitmasks the radio reports
#   min_txpower, max_txpower: the allowed range for the regulatory domain (AFC can move it)
#   has_*, is_11*: capability flags (DFS, HT160, 802.11ax/be ...)
DERIVED_RADIO_FIELDS = frozenset({"current_antenna_gain", "radio_caps", "radio_caps2", "min_txpower", "max_txpower"})


def is_derived(field: str) -> bool:
    return field in DERIVED_RADIO_FIELDS or field.startswith(("has_", "is_11"))


def drift_fields(body: list[dict], fresh: list[dict], idx: int) -> list[tuple[int, str]]:
    """Fields that differ between what we sent and what the controller now holds,
    except tx_power_mode/tx_power of the target radio and the derived fields."""
    diff = table_diff(body, fresh) - {(idx, "tx_power_mode"), (idx, "tx_power")}
    return sorted(d for d in diff if not is_derived(d[1]))


def power_body(radio_table: list[dict], idx: int, target: int | str, auto_power: int | None = None) -> list[dict]:
    """The FULL fetched radio_table with one radio changed. U7s revert radio_table_overrides.
    A number sets custom + tx_power; auto sets the mode and leaves tx_power as fetched,
    unless auto_power (--tx-power) gives the value to store with it (the undo of auto)."""
    body = copy.deepcopy(radio_table)
    if target == "auto":
        body[idx]["tx_power_mode"] = "auto"
        if auto_power is not None:
            body[idx]["tx_power"] = auto_power
    else:
        body[idx]["tx_power_mode"] = "custom"
        body[idx]["tx_power"] = target
    return body


def at_target(cfg: dict, target: int | str, auto_power: int | None = None) -> bool:
    if target == "auto":
        return cfg.get("tx_power_mode") == "auto" and (auto_power is None or cfg.get("tx_power") == auto_power)
    return cfg.get("tx_power_mode") == "custom" and cfg.get("tx_power") == target


def power_guard(ap: dict, radio: str, target: int | str,
                auto_power: int | None = None) -> tuple[int | None, list | None, str | None]:
    """(radio index, PUT radio_table, refusal). Every refusal means nothing is sent.
    The other-field guard is the re-read just before the PUT (set_power_apply)."""
    name, band = ap.get("name"), BAND[radio]
    if not ap_online(ap):
        return None, None, f"{name} is not online (state={ap.get('state', UNKNOWN)}); nothing sent"
    if not isinstance(ap.get("_id"), str) or not DEVICE_ID_RE.fullmatch(ap["_id"]):
        return None, None, f"{name} has no usable _id in stat/device; nothing sent"
    idx, err = radio_index(ap, radio)
    if err:
        return None, None, err + "; nothing sent"
    value = auto_power if target == "auto" else target
    if value is not None:
        cfg = ap["radio_table"][idx]
        lo, hi = cfg.get("min_txpower"), cfg.get("max_txpower")
        if not (is_int(lo) and is_int(hi)):
            return None, None, (f"{name} {band} GHz power range is {UNKNOWN} (min_txpower={lo if lo is not None else UNKNOWN}, "
                                f"max_txpower={hi if hi is not None else UNKNOWN}); nothing sent")
        if not lo <= value <= hi:
            return None, None, f"{value} dBm is outside {name} {band} GHz range {lo}..{hi}; nothing sent"
    return idx, power_body(ap["radio_table"], idx, target, auto_power), None


def served_ssids(ap: dict, radio: str, wlans: list[dict]) -> list[str]:
    """Enabled wlanconf SSIDs that the AP serves on this radio (vap_table). The
    on-device check reads only interfaces whose SSID is in wlanconf."""
    enabled = {w.get("name") for w in wlans if w.get("enabled", True)}
    return sorted({v.get("essid") for v in ap.get("vap_table") or []
                   if v.get("radio") == radio and v.get("essid") in enabled})


def evidence_dir(ap_name: str) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M", time.localtime(clock.now_ts()))
    base = config.active().evidence_dir / f"unifi-change-{stamp}-{ap_slug(ap_name)}-power"
    path, n = base, 2
    while path.exists():
        path, n = base.with_name(f"{base.name}-{n}"), n + 1
    private_dir(path.parent, exist_ok=True)
    os.chmod(path.parent.parent, 0o700)
    return private_dir(path)


MARKER_FIELDS = ("cfgversion", "provisioned_at")  # stat/device: config hash, last provision time


def config_marker(ap: dict) -> tuple:
    return tuple(ap.get(f) for f in MARKER_FIELDS)


def poll_applied(device_id: str, idx: int, radio: str, target: int | str, marker0: tuple,
                 start: float, deadline: float, auto_power: int | None = None) -> tuple[dict | None, float, str]:
    """Wait until the AP is in state 1 AND it has been provisioned since the PUT
    (cfgversion/provisioned_at moved, or a state other than 1 was seen) AND the
    fresh radio_table[idx] holds the target. (fresh record or None, seconds since
    the PUT, reason). Every read is bounded by the time left before `deadline`."""
    seen_down, last = False, "no stat/device read yet"
    clock.sleep(max(0.0, min(POLL_SETTLE_S, deadline - clock.monotonic())))
    while True:
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            return None, clock.monotonic() - start, last
        devices, err = api.legacy_list("stat/device", timeout=min(READ_LIMIT_S, remaining))
        ap = None if err else next((d for d in devices if d.get("_id") == device_id), None)
        if err:
            last = f"stat/device: {err}"
        elif ap is None:
            last = "AP missing from stat/device"
        elif not ap_online(ap):
            seen_down, last = True, f"state={ap.get('state', UNKNOWN)}"
        else:
            moved = [f for f, a, b in zip(MARKER_FIELDS, marker0, config_marker(ap)) if a != b]
            table = ap.get("radio_table") or []
            cfg = table[idx] if idx < len(table) and isinstance(table[idx], dict) else {}
            if not (moved or seen_down):
                last = "state 1 but cfgversion and provisioned_at unchanged (not provisioned yet)"
            elif cfg.get("radio") != radio or not at_target(cfg, target, auto_power):
                last = f"state 1 but radio_table[{idx}] is {cfg.get('tx_power_mode', UNKNOWN)}/{cfg.get('tx_power', UNKNOWN)}"
            else:
                why = "/".join(moved) + " changed" if moved else "cfgversion unchanged; state left 1"
                return ap, clock.monotonic() - start, why
        if clock.monotonic() + POLL_EVERY_S >= deadline:
            return None, clock.monotonic() - start, last
        clock.sleep(POLL_EVERY_S)


def band_check(rows: list[dict], band: str, target: int | str) -> tuple[str, int]:
    band_rows = [r for r in rows if r["band"] == band]
    ifaces = ",".join(r["iface"] for r in band_rows)
    if not band_rows:
        return f"UNVERIFIED  no {band} GHz radio read from the device", 1
    if not all(is_int(r["pwr_dev"]) for r in band_rows):
        return f"UNVERIFIED  device Tx-Power not read on {ifaces}", 1
    live = "/".join(str(r["pwr_dev"]) for r in band_rows)
    if target == "auto":
        return (f"PASS  controller tx_power_mode=auto; device Tx-Power {live} dBm on {ifaces} "
                "(reported, not compared)"), 0
    if all(r["pwr_dev"] == target for r in band_rows):
        return f"PASS  device Tx-Power {target} dBm on {ifaces} = target {target}", 0
    return f"MISMATCH  device Tx-Power {live} dBm on {ifaces}, target {target}", 3


def undo_text(ap: dict, radio: str, old_cfg: dict, evidence: Path) -> str:
    old, mode = old_cfg.get("tx_power"), old_cfg.get("tx_power_mode")
    cmd = f"unifi-axi set-power {shlex.quote(ap.get('name') or '')} {BAND[radio]}"
    if mode == "custom" and is_int(old):
        return f"{cmd} {old} --confirm"
    if mode == "auto":  # restore the stored tx_power too, not only the mode
        return f"{cmd} {target_args('auto', old if is_int(old) else None)} --confirm"
    return (f"old mode was {mode or UNKNOWN} (tx_power={old if old is not None else UNKNOWN}); "
            f"undo is manual: PUT radio_table from {tilde(evidence)}/before.json")


def changelog_stub(ap: dict, radio: str, old_cfg: dict, target: int | str, sent_at: float, result: str,
                   evidence: Path, undo: str, auto_power: int | None = None) -> list[str]:
    name, band = ap.get("name"), BAND[radio]
    old_mode, old_pwr = old_cfg.get("tx_power_mode") or UNKNOWN, old_cfg.get("tx_power", UNKNOWN)
    if target == "auto":
        new = f"auto/{auto_power if auto_power is not None else old_pwr}"
    else:
        new = f"custom/{target}"
    return [f"## {time.strftime('%Y-%m-%d %H:%M', time.localtime(sent_at))} {name} {band} GHz power "
            f"{power_text(old_cfg)} -> {target_text(target, auto_power)}",
            "Trigger: <agent fills in>",
            f"- {hms(sent_at)}: `{name}` `{radio}` tx_power_mode/tx_power {old_mode}/{old_pwr} -> {new}; "
            "full `radio_table` PUT (unifi-axi set-power).",
            f"- Verified: {result}",
            f"- Evidence: `{tilde(evidence)}/` (before.json, put.json, after.json)",
            f"- Rollback: {undo}"]


def set_power_apply(ap: dict, idx: int, body: list[dict], radio: str, target: int | str,
                    creds: tuple, wlans: list[dict], doc: Doc, auto_power: int | None = None) -> int:
    """Re-read, send the one PUT, wait for the AP, verify on the device.
    Callers have run power_guard and fetched creds + wlanconf."""
    name, band = ap.get("name"), BAND[radio]
    devices, err = api.legacy_list("stat/device")
    cur = None if err else next((d for d in devices if d.get("_id") == ap["_id"]), None)
    if cur is None:
        doc.kv("error", f"stat/device re-read before the PUT failed ({err or 'AP missing'}); nothing sent")
        return 1
    # Only config fields count: a controller refresh of the derived fields (the
    # ones drift_fields ignores after the write) must not refuse the write.
    changed = sorted(d for d in table_diff(ap["radio_table"], cur.get("radio_table")) if not is_derived(d[1]))
    if changed:
        doc.kv("error", f"{name} radio_table changed since it was read {changed}; re-run the preview; nothing sent")
        return 1
    if not ap_online(cur):
        doc.kv("error", f"{name} is not online at the re-read (state={cur.get('state', UNKNOWN)}); nothing sent")
        return 1
    # Rebuild the body from the re-read so the PUT carries the current derived
    # values, and re-check the range (min/max_txpower are derived and can move).
    idx, body, refusal = power_guard(cur, radio, target, auto_power)
    if refusal:
        doc.kv("error", f"at the re-read: {refusal}")
        return 1
    marker0 = config_marker(cur)
    old_cfg = copy.deepcopy(cur["radio_table"][idx])
    try:
        evidence = evidence_dir(name)
        write_private_json(evidence, "before.json", cur)
        write_private_json(evidence, "put.json", {"radio_table": body})
    except OSError as exc:
        doc.kv("error", f"cannot write evidence under {tilde(config.active().evidence_dir)}: {type(exc).__name__}; nothing sent")
        return 1
    doc.kv("evidence", tilde(evidence))
    undo = undo_text(ap, radio, old_cfg, evidence)
    sent_at = clock.now_ts()

    def finish(result: str, code: int) -> int:
        doc.items("changelog", changelog_stub(ap, radio, old_cfg, target, sent_at, result, evidence, undo,
                                              auto_power))
        doc.kv("undo", undo)
        return code

    start = clock.monotonic()
    try:
        payload, err = api.api_write_device(ap["_id"], body)
    except Exception as exc:  # noqa: BLE001 - a raised PUT may still have applied
        payload, err = None, f"{type(exc).__name__} during the PUT"
    rc = (payload.get("meta") or {}).get("rc") if isinstance(payload, dict) else None
    if not err and rc not in (None, "ok"):
        err = f"controller rc={rc}"
    if err:
        doc.kv("error", f"PUT rest/device failed: {err}. The write may still have applied; "
                        f"re-read with `unifi-axi aps {shlex.quote(name or '')}`")
        return finish("NOT VERIFIED: PUT failed, state unknown", 1)
    doc.kv("put", f"rest/device/{ap['_id']} full radio_table ({len(body)} radios) rc=ok, write sent at {hms(sent_at)}")
    try:
        deadline = start + POLL_LIMIT_S
        fresh, waited, why = poll_applied(ap["_id"], idx, radio, target, marker0, start, deadline, auto_power)
        if fresh is None:
            doc.kv("error", f"write sent at {hms(sent_at)}; {name} not back to state 1 with the new config within "
                            f"{POLL_LIMIT_S} s ({why}); verify did not run")
            return finish(f"NOT VERIFIED: AP not back to state 1 with the new config within {POLL_LIMIT_S} s", 1)
        doc.kv("poll", f"state 1 with the new config after {waited:.0f} s (marker={why})")
        try:
            write_private_json(evidence, "after.json", fresh)
        except OSError:
            doc.kv("warn_evidence", "after.json not written")
        reads = 0
        while True:  # the radio can report the old Tx-Power for a while after provisioning
            rows: list[dict] = []
            vdoc = Doc(doc.fields)
            verify_one(fresh, creds, wlans, vdoc, rows)
            reads += 1
            check, code = band_check(rows, band, target)
            if code != 3 or clock.monotonic() + POLL_EVERY_S + ssh.SSH_LIMIT_S > deadline:
                break
            clock.sleep(POLL_EVERY_S)
        doc.blocks.extend(vdoc.blocks)
        if reads > 1:
            doc.kv("device_reads", f"{reads} (every {POLL_EVERY_S} s, limit {POLL_LIMIT_S} s from the write)")
        drift = drift_fields(body, fresh.get("radio_table"), idx)
        if drift:
            doc.kv("drift", f"{drift} differ between the PUT body and the controller after the write")
            check, code = f"{check}; DRIFT {drift}", 3
        doc.kv("check", check)
        return finish(check, code)
    except Exception as exc:  # noqa: BLE001 - after a write, always print the stub and the undo
        doc.kv("error", f"write sent at {hms(sent_at)}; internal {type(exc).__name__} after the write; "
                        "verify did not complete")
        return finish("NOT VERIFIED: internal error after write", 1)


def cmd_set_power(args, doc: Doc) -> int:
    radio = BAND_TOKENS.get(args.band.lower())
    if not radio:
        raise UsageError(f"band {args.band!r}: use 2.4, 5, 6 or ng, na, 6e")
    target = parse_target(args.dbm)
    auto_power = args.tx_power
    if auto_power is not None and target != "auto":
        raise UsageError("--tx-power goes with auto only (a number already sets custom power)")
    devices, err = api.legacy_list("stat/device")
    if err:
        doc.kv("error", f"stat/device failed: {err}; nothing sent")
        return 1
    site = build_site(devices)
    ap, code = pick_ap(doc, site, args.ap, "set-power", f"{args.band} {args.dbm}")
    if ap is None:
        return code
    name, band = ap.get("name"), BAND[radio]
    idx, body, refusal = power_guard(ap, radio, target, auto_power)
    if refusal:
        doc.kv("error", refusal)
        return 1
    cfg = ap["radio_table"][idx]
    if at_target(cfg, target, auto_power):
        doc.kv("set-power", f"{name} {band} GHz  already {power_text(cfg)}{' dBm' if target != 'auto' else ''}  "
                            "no-op (nothing sent)")
        return 0
    live = next((r for r in ap.get("radio_table_stats") or [] if r.get("radio") == radio), {})
    sta = live.get("num_sta", UNKNOWN)
    exact = exact_ap(args.ap, ap)
    doc.kv("set-power", f"{name} {band} GHz  {power_text(cfg)} -> {target_text(target, auto_power)}  "
                        f"{'APPLY' if args.confirm and exact else 'PREVIEW (nothing sent)'}")
    doc.kv("radio", f"mode={cfg.get('tx_power_mode') or UNKNOWN} ch={live.get('channel', cfg.get('channel', UNKNOWN))} "
                    f"width={cfg.get('ht', UNKNOWN)} sta={sta}  "
                    f"body: only {radio} tx_power_mode/tx_power change; other radios and fields sent as read")
    doc.kv("warn", LIVE_CALL_TEXT)
    doc.kv("clients", f"{sta} on {name} {band} GHz now")
    again = f"unifi-axi set-power {shlex.quote(name or '')} {band} {target_args(target, auto_power)} --confirm"
    if not args.confirm:
        doc.kv("help", again)
        return 0
    if not exact:
        doc.kv("error", f'exact AP name required for --confirm ("{args.ap}" is a fuzzy match for {name}); nothing sent')
        doc.kv("help", again)
        return 1
    user, password, cerr = ssh.ssh_creds()
    if cerr:
        doc.kv("error", f"no SSH credentials ({cerr}); the on-device check cannot run; nothing sent")
        return 1
    wlans, werr = api.legacy_list("rest/wlanconf")
    if werr:
        doc.kv("error", f"rest/wlanconf failed ({werr}); the on-device check cannot run; nothing sent")
        return 1
    if not served_ssids(ap, radio, wlans):
        doc.kv("error", f"no served SSID on {name} {band} GHz (vap_table has no enabled wlanconf SSID on {radio}); "
                        "the on-device check cannot read it; nothing sent")
        return 1
    return set_power_apply(ap, idx, body, radio, target, (user, password, None), wlans, doc, auto_power)

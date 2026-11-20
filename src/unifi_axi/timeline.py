"""The merged client timeline: controller events + AP log events, and drop counting.

Merge rule: controller roam/connect events lag the AP line by up to ~40 s, so a
controller row takes the closest EARLIER AP join within MERGE_BEFORE_S (or one
up to MERGE_AFTER_S later as a fallback). Summary counts use in-window rows only.
One drop per outage: a reconnect pairs with the LAST disconnect before it, in
both merge_timeline (client summary) and find_drops (drops command).
"""

from __future__ import annotations

from .api import param
from .aplog import ALG, ApLog
from .util import BAND, UNKNOWN, client_label, hms, int_or_none

MERGE_BEFORE_S = 60
MERGE_AFTER_S = 5
BTM_RUN_GAP_S = 90
DROP_GAP_S = 180
TIMELINE_CAP = 40
HIDEABLE = ("btm_req", "btm_resp", "sample")


def ctl_rows(events: list[dict], macs: set[str]) -> list[dict]:
    rows = []
    for e in events:
        mac = (param(e, "CLIENT", "id") or "").lower()
        if mac not in macs:
            continue
        key = e.get("key") or ""
        base = {"t": e.get("timestamp", 0) / 1000, "mac": mac, "key": key,
                "band": BAND.get(param(e, "RADIO_BAND"), UNKNOWN), "rssi": int_or_none(param(e, "SIGNAL_STRENGTH"))}
        if key.startswith("CLIENT_ROAMED"):
            base.update(kind="roam", ap=param(e, "DEVICE_TO") or UNKNOWN, from_ap=param(e, "DEVICE_FROM") or UNKNOWN,
                        prev_rssi=int_or_none(param(e, "PREVIOUS_SIGNAL_STRENGTH")))
        elif key.startswith("CLIENT_CONNECTED_WIRELESS"):
            base.update(kind="connect", ap=param(e, "DEVICE") or UNKNOWN)
        elif key.startswith("CLIENT_DISCONNECTED_WIRELESS"):
            base.update(kind="disconnect", ap=param(e, "DEVICE") or UNKNOWN, duration=param(e, "DURATION"))
        else:
            base.update(kind="other", ap=param(e, "DEVICE") or "", detail=key)
        rows.append(base)
    return sorted(rows, key=lambda r: r["t"])


def join_label(alg: str | None, prefix: str) -> str:
    if alg == "2":
        return f"{prefix} ft"
    if alg == "3":
        return "join full_sae" if prefix == "roam" else f"{prefix} full_sae"
    if alg is None:
        return "join" if prefix == "roam" else prefix
    return f"join {ALG.get(alg, 'alg ' + alg)}" if prefix == "roam" else f"{prefix} {ALG.get(alg, 'alg ' + alg)}"


def merge_timeline(ctl: list[dict], logs: dict[str, ApLog], since: float, until: float) -> tuple[list[dict], dict]:
    joins = [e for log in logs.values() if log.ok for e in log.events if e["kind"] == "join"]
    ap_disc = [e for log in logs.values() if log.ok for e in log.events if e["kind"] == "disconnect"]
    used: set[int] = set()
    rows: list[dict] = []
    rssi_notes: list[tuple[int, str, float]] = []  # (rssi, ap, row time); filtered to the window below

    def take(pool: list[dict], ap: str, t: float) -> dict | None:
        """Controller events lag AP lines: prefer the closest EARLIER AP line (up to
        MERGE_BEFORE_S); a line up to MERGE_AFTER_S later is only a fallback."""
        free = [e for e in pool if id(e) not in used and e["ap"] == ap]
        before = [e for e in free if t - MERGE_BEFORE_S <= e["t"] <= t]
        after = [e for e in free if t < e["t"] <= t + MERGE_AFTER_S]
        best = max(before, key=lambda e: e["t"]) if before else (min(after, key=lambda e: e["t"]) if after else None)
        if best is not None:
            used.add(id(best))
        return best

    def note_rssi(value: int | None, ap: str, t: float) -> None:
        if isinstance(value, int):
            rssi_notes.append((value, ap, t))

    last_disc: dict[str, float] = {}
    prev_roam: dict | None = None
    for c in ctl:
        if c["kind"] in ("roam", "connect"):
            hit = take(joins, c["ap"], c["t"])
            row = {"t": hit["t"] if hit else c["t"], "src": "ctl+ap" if hit else "ctl", "ap": c["ap"],
                   "band": c["band"] if c["band"] != UNKNOWN or not hit else hit["band"], "rssi": c["rssi"],
                   "mac": c["mac"]}
            note_rssi(c["rssi"], c["ap"], row["t"])
            parts = []
            if c["kind"] == "roam":
                note_rssi(c.get("prev_rssi"), c["from_ap"], row["t"])
                prev = "" if c.get("prev_rssi") is None else f" ({c['prev_rssi']})"
                parts.append(f"from {c['from_ap']}{prev}")
                repeat = (prev_roam is not None and not hit and prev_roam["ap"] == c["ap"]
                          and prev_roam["from_ap"] == c["from_ap"] and c["t"] - prev_roam["t"] <= 120)
                if repeat:
                    row.update(event="roam (repeat)", kind="repeat")
                    parts.append(f"controller repeat of {hms(prev_roam['t'])}")
                elif hit:
                    row.update(event=join_label(hit["alg"], "roam"), kind="transition", alg=hit["alg"])
                else:
                    row.update(event="roam", kind="transition", alg="unknown")
                    reach = logs.get(c["ap"])
                    parts.append("FT UNKNOWN (" + ("no AP join line" if reach and reach.ok else "AP log not read") + ")")
                prev_roam = c
            else:
                prev_roam = None  # a (re)connect breaks a controller repeat run
                row.update(event=join_label(hit["alg"], "connect") if hit else "connect", kind="connect")
                gap = c["t"] - last_disc[c["mac"]] if c["mac"] in last_disc else None
                if gap is not None and gap <= DROP_GAP_S:
                    row.update(event="drop", kind="drop")
                    parts.append(f"gap={int(round(gap))}s after disconnect at {hms(last_disc[c['mac']])}")
                    if hit and hit.get("alg"):
                        parts.append(f"auth={ALG.get(hit['alg'], 'alg ' + hit['alg'])}")
                last_disc.pop(c["mac"], None)
            if hit and c["t"] - hit["t"] > MERGE_AFTER_S:
                parts.append(f"ctl +{int(round(c['t'] - hit['t']))}s")
            row["detail"] = "; ".join(parts)
            rows.append(row)
        elif c["kind"] == "disconnect":
            prev_roam = None
            hit = take(ap_disc, c["ap"], c["t"])
            note_rssi(c["rssi"], c["ap"], hit["t"] if hit else c["t"])
            detail = []
            if hit and hit.get("reason"):
                detail.append(f"kicked out: {hit['reason']}")
            if c.get("duration"):
                detail.append(f"connected {c['duration']}")
            rows.append({"t": hit["t"] if hit else c["t"], "src": "ctl+ap" if hit else "ctl", "ap": c["ap"],
                         "band": c["band"], "event": "disconnect", "kind": "disconnect", "rssi": c["rssi"],
                         "detail": "; ".join(detail), "mac": c["mac"]})
            last_disc[c["mac"]] = c["t"]
        else:
            rows.append({"t": c["t"], "src": "ctl", "ap": c["ap"], "band": c["band"], "event": "event",
                         "kind": "other", "rssi": c["rssi"], "detail": c.get("detail", "")})

    # AP-only rows.
    for log in logs.values():
        if not log.ok:
            continue
        for e in log.events:
            if id(e) in used:
                continue
            base = {"t": e["t"], "src": "ap", "ap": e["ap"], "band": e["band"], "rssi": None}
            if e["kind"] == "join":
                rows.append({**base, "event": join_label(e["alg"], "roam"), "kind": "transition", "alg": e["alg"],
                             "detail": "no controller event within 60 s"})
            elif e["kind"] == "ft_fail":
                rows.append({**base, "event": "ft attempt", "kind": "ft_fail", "detail": e["detail"]})
            elif e["kind"] == "disconnect":
                rows.append({**base, "event": "disconnect", "kind": "disconnect",
                             "detail": f"kicked out: {e['reason']}" if e.get("reason") else "AP-STA-DISCONNECTED"})
            elif e["kind"] == "left":
                rows.append({**base, "event": "left (roamed)", "kind": "left", "detail": "immediate disassoc (roamed)"})
            elif e["kind"] == "auth_reject":
                rows.append({**base, "event": "auth rejected", "kind": "auth_reject",
                             "detail": f"802.11 status {e['reason']}"})
            elif e["kind"] == "sample":
                rows.append({**base, "event": "signal", "kind": "sample", "rssi": e["rssi"], "detail": e["detail"]})
            elif e["kind"] == "btm_req":
                rows.append({**base, "event": "btm_req", "kind": "btm_req", "rssi": e["rssi"], "n": 1,
                             "rssis": [e["rssi"]], "until": e["t"]})
            elif e["kind"] == "btm_resp":
                rows.append({**base, "event": "btm_resp", "kind": "btm_resp", "statuses": [e["status"]],
                             "targets": [e.get("target")], "until": e["t"]})

    # Summary counts come from in-window rows only: the controller read is padded by MERGE_BEFORE_S.
    rows = [r for r in rows if since <= r["t"] <= until]
    rows.sort(key=lambda r: (r["t"], r["kind"] in HIDEABLE))
    for r in rows:
        if r["kind"] in ("btm_req", "sample"):
            note_rssi(r["rssi"], r["ap"], r["t"])
    in_window = [n for n in rssi_notes if since <= n[2] <= until]
    stats = {"ctl_repeat": sum(1 for r in rows if r["kind"] == "repeat"),
             "drops": sum(1 for r in rows if r["kind"] == "drop"),
             "worst": min(in_window, key=lambda n: n[0]) if in_window else None}
    rows = collapse_btm(rows)
    annotate_stale_peers(rows)
    return rows, stats


def collapse_btm(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    open_runs: dict[tuple[str, str], dict] = {}
    for r in rows:
        if r["kind"] not in ("btm_req", "btm_resp"):
            out.append(r)
            continue
        key = (r["ap"], r["kind"])
        run = open_runs.get(key)
        if run is not None and r["t"] - run["until"] <= BTM_RUN_GAP_S:
            run["until"] = r["t"]
            run["n"] = run.get("n", 1) + 1
            if r["kind"] == "btm_req":
                run["rssis"].append(r["rssi"])
            else:
                run["statuses"] += r["statuses"]
                run["targets"] += r["targets"]
            continue
        r = dict(r, n=1)
        open_runs[key] = r
        out.append(r)
    for r in out:
        if r["kind"] == "btm_req":
            if r["n"] > 1:
                r["event"] = f"btm_req x{r['n']}"
                r["rssi"] = f"{max(r['rssis'])}..{min(r['rssis'])}"
                r["detail"] = f"until {hms(r['until'])}"
            else:
                r["detail"] = ""
        elif r["kind"] == "btm_resp":
            if r["n"] > 1:
                r["event"] = f"btm_resp x{r['n']}"
            groups: dict[int, int] = {}
            for s in r["statuses"]:
                groups[s] = groups.get(s, 0) + 1
            parts = []
            for s, k in groups.items():
                word = "accept" if s == 0 else "reject"
                parts.append(f"status {s}" + (f" x{k}" if k > 1 else "") + f" ({word})")
            targets = sorted({t for s, t in zip(r["statuses"], r["targets"]) if s == 0 and t})
            if targets:
                parts.append("to " + "/".join(targets))
            r["detail"] = "; ".join(parts)
            r["rssi"] = None
    return out


def annotate_stale_peers(rows: list[dict]) -> None:
    """An AP-side kickout after the client already joined another AP is a stale peer."""
    last_join: tuple[float, str] | None = None
    for r in rows:
        if r["kind"] in ("transition", "connect", "drop"):
            last_join = (r["t"], r["ap"])
        elif r["kind"] == "disconnect" and r["src"] == "ap" and last_join and last_join[1] != r["ap"]:
            r["detail"] += f"; client joined {last_join[1]} at {hms(last_join[0])}"


def truncate(rows: list[dict], full: bool) -> tuple[list[dict], dict[str, int]]:
    hidden = {"btm": 0, "signal": 0, "left": 0}
    if full:
        return rows, hidden
    keep = [r for r in rows if r["kind"] != "left"]
    hidden["left"] = len(rows) - len(keep)
    excess = len(keep) - TIMELINE_CAP
    if excess > 0:
        drop_ids = set()
        for kinds, label in ((("sample",), "signal"), (("btm_req", "btm_resp"), "btm")):
            for r in keep:  # signal samples, then BTM rows; oldest first
                if excess <= 0:
                    break
                if r["kind"] in kinds and id(r) not in drop_ids:
                    drop_ids.add(id(r))
                    hidden[label] += 1
                    excess -= 1
        keep = [r for r in keep if id(r) not in drop_ids]
    return keep, hidden


def find_drops(events: list[dict], gap: int, keep) -> list[dict]:
    by_mac: dict[str, list[dict]] = {}
    for e in events:
        key = e.get("key") or ""
        if not (key.startswith("CLIENT_DISCONNECTED_WIRELESS") or key.startswith("CLIENT_CONNECTED_WIRELESS")):
            continue
        if not keep(e):
            continue
        mac = (param(e, "CLIENT", "id") or "").lower()
        by_mac.setdefault(mac, []).append(e)
    # One drop per outage: a connect pairs with the LAST disconnect before it,
    # so two disconnects then one reconnect count once. merge_timeline (the
    # `client` summary) applies the same rule through its last_disc map.
    drops = []
    for mac, items in by_mac.items():
        items.sort(key=lambda e: e.get("timestamp", 0))
        last: dict | None = None
        for nxt in items:
            if (nxt.get("key") or "").startswith("CLIENT_DISCONNECTED"):
                last = nxt
                continue
            e, last = last, None
            if e is None:
                continue
            g = (nxt["timestamp"] - e["timestamp"]) / 1000
            if g <= gap:
                c = (e.get("parameters") or {}).get("CLIENT") or {}
                drops.append({"mac": mac, "client": client_label(c.get("name"), c.get("hostname"), mac),
                              "t": e["timestamp"] / 1000, "reconnect": nxt["timestamp"] / 1000, "gap": g,
                              "band": BAND.get(param(e, "RADIO_BAND"), UNKNOWN), "ap": param(e, "DEVICE") or UNKNOWN})
    return sorted(drops, key=lambda d: d["t"])

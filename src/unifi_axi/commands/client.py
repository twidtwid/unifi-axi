"""`client`: one client's timeline from controller events, AP logs and the live link.

Rows name their source (ctl, ap, ctl+ap); absent fields print UNKNOWN;
disagreements print `conflict:`. The command reports observations, not causes.
"""

from __future__ import annotations

import time

from .. import api, aplog, clock, ssh
from ..api import LogRead, param
from ..aplog import ApLog
from ..site import Ambiguous, NoMatch, Site, ap_online, build_site, resolve_client
from ..timeline import MERGE_AFTER_S, MERGE_BEFORE_S, ctl_rows, merge_timeline, truncate
from ..toon import Doc, toon_scalar
from ..util import BAND, UNKNOWN, hm, hms, parallel, tokens, window, window_line
from .common import Saver, ap_slug, lookup_failures, no_match, print_ambiguous

RAW_LINES_CAP = 200


def cmd_client(args, doc: Doc) -> int:
    now = clock.now_ts()
    since, until = window(args.since, args.until, now)
    saver = Saver(args.save, "client")
    # Four independent reads in parallel; each keeps its own error.
    reads = {"stat/sta": lambda: api.legacy_list("stat/sta"), "rest/user": lambda: api.legacy_list("rest/user"),
             "stat/device": lambda: api.legacy_list("stat/device"),
             "system-log": lambda: api.system_log(since - MERGE_BEFORE_S, until + MERGE_BEFORE_S)}

    def read_failed(name: str, exc: Exception):
        err = f"internal: {type(exc).__name__}"
        return LogRead(error=err) if name == "system-log" else (None, err)

    results = dict(zip(reads, parallel(lambda name: reads[name](), list(reads), read_failed)))
    (sta, sta_err), (users, users_err) = results["stat/sta"], results["rest/user"]
    devices, dev_err = results["stat/device"]
    logread = results["system-log"]
    if dev_err:
        doc.kv("error", f"stat/device failed: {dev_err}")
        return 1
    site = build_site(devices)
    ctl_ok = logread.complete
    try:
        match = resolve_client(args.who, sta or [], users or [], logread.events)
    except Ambiguous as amb:
        return print_ambiguous(doc, amb, site, now, "client")
    except NoMatch:
        failed = lookup_failures(**{"stat/sta": sta_err, "rest/user": users_err, "system-log": logread.error})
        first = tokens(args.who)[0] if tokens(args.who) else args.who
        return no_match(doc, args.who, failed, f'unifi-axi clients --grep "{first}"')
    macs = set(match.macs)
    ctl = ctl_rows(logread.events, macs)
    sta_row = next((s for s in (sta or []) if (s.get("mac") or "").lower() in macs), None)
    ip = (sta_row or {}).get("ip") or next((param(e, "CLIENT", "ip") for e in logread.events
                                            if (param(e, "CLIENT", "id") or "").lower() in macs), None) or UNKNOWN
    mac_text = f"mac={match.macs[0]}" if len(match.macs) == 1 else f"macs={'/'.join(match.macs)}"
    doc.kv("client", f"{match.name}  {mac_text}  ip={ip}  match={match.how}")
    doc.kv("window", window_line(since, until))

    # AP choice: APs named in the client's events in the window, plus the current AP.
    # A disconnect in the window can hide a failed FT attempt on an AP the
    # controller never names, so then every online AP is read.
    current_ap = site.by_mac.get(((sta_row or {}).get("ap_mac") or "").lower(), {}).get("name")
    online = [a.get("name") for a in site.aps if ap_online(a)]
    choice_note = ""
    if args.all_aps:
        chosen = [a.get("name") for a in site.aps]
    else:
        named = {c["ap"] for c in ctl}  # ctl already spans the padded read window
        named |= {c.get("from_ap") for c in ctl if c.get("from_ap")}
        if current_ap:
            named.add(current_ap)
        if any(c["kind"] == "disconnect" for c in ctl):
            named |= set(online)
            choice_note = " (all online: window has a disconnect)"
        chosen = [a.get("name") for a in site.aps if a.get("name") in named]
    logs: dict[str, ApLog] = {}
    if not args.no_ssh and chosen:
        user, password, cred_err = ssh.ssh_creds()
        if cred_err:
            for name in chosen:
                logs[name] = ApLog(ap=name, reason=f"no SSH credentials: {cred_err}")
        else:
            cmd = ssh.log_command(sorted(macs))

            def fetch(name: str) -> ApLog:
                ap = site.by_name[name]
                if not ap_online(ap):
                    return ApLog(ap=name, reason="offline(controller)")
                start = clock.now_ts()
                text, err, took = ssh.ssh_run(ap.get("ip"), user, password, cmd)
                if err:
                    return ApLog(ap=name, reason=err)
                # The AP prints EPOCH early in the session: compare it with the session midpoint.
                return aplog.parse_ap_output(name, text, sorted(macs), site, start + took / 2)

            def failed_fetch(name: str, exc: Exception) -> ApLog:
                return ApLog(ap=name, reason=f"internal: {type(exc).__name__}")

            for log in parallel(fetch, chosen, failed_fetch):
                logs[log.ap] = log
                saver.text(f"ap-log-{ap_slug(log.ap).removeprefix('ap-')}.txt", log.raw)
    saver.json("system-log.json", logread.events)
    saver.json("stat-sta-client.json", sta_row)

    ok_logs = [l for l in logs.values() if l.ok]
    client_events = [c for c in ctl if since <= c["t"] <= until]
    in_window = [e for e in logread.events if since * 1000 <= e.get("timestamp", 0) <= until * 1000]
    if logread.error:
        ctl_text = f"controller=FAILED({logread.error}; {logread.status()})"
    else:
        ctl_text = (f"controller=ok({len(client_events)} client events of {len(in_window)}; {logread.status()}"
                    + ("" if logread.complete else "; INCOMPLETE") + ")")
    if args.no_ssh:
        ap_text = "ap_logs=skipped(--no-ssh)"
    else:
        ap_text = f"ap_logs={len(ok_logs)}/{len(chosen)} chosen of {len(online)} online{choice_note}"
        if not ctl_ok and not args.all_aps:
            ap_text += " (AP choice had no controller input)"
        late = [f"{l.ap} covers from {hm(l.covers_from())}" for l in ok_logs
                if l.covers_from() is not None and l.covers_from() > since]
        if late:
            ap_text += " (" + "; ".join(late) + ")"
        others = sum(1 for l in ok_logs for t in l.other_ts if since <= t <= until)
        if others:
            ap_text += f" other_lines={others}"
        skews = [f"{l.ap} {l.skew:+.0f}s" for l in ok_logs if abs(l.skew) > 5]
        if skews:
            ap_text += " clock_skew=" + ",".join(skews)
    doc.kv("sources", f"{ctl_text}  {ap_text}  stat_sta={'ok' if not sta_err else 'FAILED'}"
                      f"  rest_user={'ok' if not users_err else 'FAILED'}")
    bad = [l for l in logs.values() if not l.ok]
    if bad:
        doc.table("unreachable", ["ap", "reason"], [{"ap": l.ap, "reason": l.reason} for l in bad])

    if sta_row:
        age = int(now - sta_row["last_seen"]) if isinstance(sta_row.get("last_seen"), (int, float)) else None
        retries = sta_row.get("wifi_tx_retries_percentage")
        doc.kv("now", "  ".join([
            f"ap={site.by_mac.get((sta_row.get('ap_mac') or '').lower(), {}).get('name', UNKNOWN)}",
            f"band={BAND.get(sta_row.get('radio'), UNKNOWN)}", f"ch={sta_row.get('channel', UNKNOWN)}",
            f"signal={sta_row.get('signal', UNKNOWN)}", f"last_seen={age if age is not None else UNKNOWN}s",
            f"retries={retries if retries is not None else UNKNOWN}%",
            f"satisfaction={sta_row.get('satisfaction', UNKNOWN)}",
            f"11r_ctl={toon_scalar(sta_row['is_11r']) if 'is_11r' in sta_row else UNKNOWN}", "(stat/sta)"]))
    else:
        doc.kv("now", "not in stat/sta (offline or unknown to the controller)")

    rows, stats = merge_timeline(ctl, logs, since, until)
    btm_req = sum(r.get("n", 1) for r in rows if r["kind"] == "btm_req")
    statuses = [s for r in rows if r["kind"] == "btm_resp" for s in r["statuses"]]
    if ctl_ok:
        transitions = [r for r in rows if r["kind"] == "transition"]
        ft = sum(1 for r in transitions if r.get("alg") == "2")
        sae = sum(1 for r in transitions if r.get("alg") == "3")
        unknown = sum(1 for r in transitions if r.get("alg") in (None, "unknown"))
        other_alg = len(transitions) - ft - sae - unknown
        parts = [f"roams={len(transitions)} (ft={ft} full_sae={sae} unknown={unknown}"
                 + (f" other={other_alg}" if other_alg else "") + ")"]
    else:
        why = "FAILED" if logread.error else "INCOMPLETE"
        parts = [f"roams={UNKNOWN} (controller log {why})"]
    ft_fail = sum(1 for r in rows if r["kind"] == "ft_fail")
    if ft_fail:
        parts.append(f"ft_fail={ft_fail}")
    if not ctl_ok:
        parts.append(f"ctl_repeat={UNKNOWN}")
    elif stats["ctl_repeat"]:
        parts.append(f"ctl_repeat={stats['ctl_repeat']}")
    parts.append(f"drops={stats['drops'] if ctl_ok else UNKNOWN}")
    parts.append(f"btm_req={btm_req} accepted={statuses.count(0)} rejected={len(statuses) - statuses.count(0)}")
    worst = stats["worst"]
    parts.append(f"worst_rssi={worst[0]} ({worst[1]} {hms(worst[2])})" if worst else f"worst_rssi={UNKNOWN}")
    doc.kv("summary", "  ".join(parts))
    doc.kv("conflict", conflict_text(sta_row, rows, site, now, list(logs.values()), args.no_ssh, since))

    shown, hidden = truncate(rows, args.full)
    if not rows:
        oldest = min((l.oldest for l in ok_logs if l.oldest), default=None)
        same_day = oldest is not None and time.strftime("%Y%m%d", time.localtime(oldest)) == time.strftime("%Y%m%d", time.localtime(since))
        oldest_text = "" if oldest is None else f" (oldest line {hm(oldest) if same_day else time.strftime('%m/%d %H:%M', time.localtime(oldest))})"
        ctl_word = "ok" if ctl_ok else ("FAILED" if logread.error else "INCOMPLETE")
        ap_word = "skipped" if args.no_ssh else f"{len(ok_logs)}/{len(chosen)}"
        doc.kv("timeline", f"0 events for {match.name} in {hm(since)}-{hm(until)}. controller={ctl_word} ap_logs={ap_word}{oldest_text}.")
    else:
        table_rows = [{**r, "t": hms(r["t"]), "rssi": UNKNOWN if r.get("rssi") is None else r["rssi"]} for r in shown]
        doc.table("timeline", ["t", "src", "ap", "band", "event", "rssi", "detail"], table_rows)
        if any(hidden.values()):
            bits = [f"{n} {k}" for k, n in hidden.items() if n]
            doc.kv("more", f"{sum(hidden.values())} rows hidden ({', '.join(bits)}). Add --full.")
    if args.full:
        raw = []
        for log in ok_logs:
            lines = [(t, line) for t, line in log.lines if since <= t <= until]
            for t, line in lines[:RAW_LINES_CAP]:
                raw.append({"ap": log.ap, "t": hms(t), "text": line.split(" ", 5)[-1]})
            if len(lines) > RAW_LINES_CAP:
                raw.append({"ap": log.ap, "t": "", "text": f"{len(lines) - RAW_LINES_CAP} more lines not shown"})
        doc.table("lines", ["ap", "t", "text"], raw)
    saver.report(doc)
    return 0 if ctl_ok else 1


def conflict_text(sta_row, rows, site: Site, now: float, logs: list[ApLog], no_ssh: bool, since: float) -> str:
    """stat/sta vs the newest AP-side join. `none` only when every chosen AP log covers the window."""
    ok_logs = [l for l in logs if l.ok]
    if no_ssh or not ok_logs:
        return f"{UNKNOWN} (AP logs not read)"
    if not sta_row:
        return "none"
    sta_ap = site.by_mac.get((sta_row.get("ap_mac") or "").lower(), {}).get("name")
    ap_joins = [r for r in rows if r["kind"] in ("transition", "connect", "drop") and r["src"] != "ctl"]
    if ap_joins and sta_ap:
        newest = ap_joins[-1]
        assoc = sta_row.get("latest_assoc_time") or sta_row.get("assoc_time")
        if newest["ap"] != sta_ap and (assoc is None or newest["t"] > assoc + MERGE_AFTER_S):
            age = int(now - sta_row["last_seen"]) if isinstance(sta_row.get("last_seen"), (int, float)) else UNKNOWN
            return (f"stat/sta says {sta_ap} (last_seen {age}s); AP log shows {newest['event']} to {newest['ap']} "
                    f"at {hms(newest['t'])}. Controller record is stale.")
    partial = [f"{l.ap} {l.reason}" for l in logs if not l.ok]
    partial += [f"{l.ap} covers from {hm(l.covers_from())}" for l in ok_logs
                if l.covers_from() is not None and l.covers_from() > since]
    if partial:
        return f"{UNKNOWN} (partial AP logs: {'; '.join(partial)})"
    return "none"

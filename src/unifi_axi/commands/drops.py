"""`drops`: a wireless disconnect followed by a reconnect within --gap seconds.

Default scope is every wireless client. `--match <text>` keeps clients whose
name or hostname contains the text (e.g. `--match iphone`); `--client` narrows
to one client. A per-day baseline prints only when UNIFI_DROP_BASELINE_PER_DAY
is configured, and only for the default scope and gap.
"""

from __future__ import annotations

import time

from .. import api, clock, config
from ..api import LogRead, param
from ..site import Ambiguous, NoMatch, build_site, resolve_client
from ..timeline import DROP_GAP_S, find_drops
from ..toon import Doc
from ..util import UsageError, hms, span_text, window
from .common import Saver, lookup_failures, no_match, print_ambiguous

BY_CLIENT_CAP = 10


class LookupNoMatch(NoMatch):
    def __init__(self, query: str, failed: list[str]):
        super().__init__(query)
        self.failed = failed


def client_text(e: dict) -> str:
    c = (e.get("parameters") or {}).get("CLIENT") or {}
    return f"{c.get('name') or ''} {c.get('hostname') or ''}".lower()


def drops_scope(args, logread: LogRead):
    if args.client:
        sta, sta_err = api.legacy_list("stat/sta")
        users, users_err = api.legacy_list("rest/user")
        try:
            match = resolve_client(args.client, sta or [], users or [], logread.events)
        except NoMatch:
            raise LookupNoMatch(args.client, lookup_failures(**{"stat/sta": sta_err, "rest/user": users_err})) from None
        macs = set(match.macs)
        return match.name, lambda e: (param(e, "CLIENT", "id") or "").lower() in macs
    if args.match:
        needle = args.match.lower()
        return f"clients matching {args.match!r}", lambda e: needle in client_text(e)
    return "all wireless clients", lambda e: True


def baseline_text(cfg: config.Config, n: int, seconds: float) -> str:
    per_day = n / max(seconds / 86400, 1e-9)
    text = f"  per_day={per_day:.1f}"
    if cfg.drop_baseline_per_day is not None:
        text += f" baseline_per_day={cfg.drop_baseline_per_day:g} (configured)"
    return text


def cmd_drops(args, doc: Doc) -> int:
    now = clock.now_ts()
    since, until = window(args.since, args.until, now)
    if args.gap < 0:
        raise UsageError(f"--gap {args.gap}: use 0 or more seconds")
    if args.client and args.match:
        raise UsageError("--client and --match are exclusive; use one")
    logread = api.system_log(since, until)
    saver = Saver(args.save, "drops")
    saver.json("system-log.json", logread.events)
    try:
        scope, keep = drops_scope(args, logread)
    except Ambiguous as amb:
        devices, _ = api.legacy_list("stat/device")
        return print_ambiguous(doc, amb, build_site(devices or []), now, "drops")
    except LookupNoMatch as exc:
        return no_match(doc, args.client, exc.failed, "unifi-axi clients --grep <text>")
    span = span_text(until - since)
    if not logread.complete:
        why = logread.error or f"page cap {api.MAX_PAGES} reached"
        doc.kv("drops", f"INCOMPLETE ({logread.status()}) {why}")
        doc.kv("events", f"{len(logread.events)} read; {logread.status()}; incomplete")
        doc.kv("help", "unifi-axi drops --since <shorter window>")
        return 1
    drops = find_drops(logread.events, args.gap, keep)
    head = f"{len(drops)} in {span} ({scope}; reconnect within {args.gap} s)"
    default_scope = not args.client and not args.match and args.gap == DROP_GAP_S
    doc.kv("drops", head + (baseline_text(config.active(), len(drops), until - since) if default_scope else ""))
    doc.kv("events", f"{len(logread.events)} read; {logread.status()}; complete")
    saver.report(doc)
    if not drops:
        return 0
    hours = max((until - since) / 3600, 1e-9)

    def tally(key):
        out: dict[str, int] = {}
        for d in drops:
            out[d[key]] = out.get(d[key], 0) + 1
        return out

    bands = tally("band")
    doc.table("by_band", ["band", "drops", "per_h"], [{"band": b, "drops": n, "per_h": f"{n / hours:.2f}"}
                                                      for b, n in sorted(bands.items(), key=lambda x: -x[1])])
    clients: dict[str, dict] = {}
    for d in drops:
        c = clients.setdefault(d["mac"], {"client": d["client"], "drops": 0, "worst_gap_s": 0, "last": 0, "mac": d["mac"]})
        c["drops"] += 1
        c["worst_gap_s"] = max(c["worst_gap_s"], int(round(d["gap"])))
        c["last"] = max(c["last"], d["t"])
    crow = sorted(clients.values(), key=lambda c: (-c["drops"], -c["last"]))
    cap = len(crow) if args.full else BY_CLIENT_CAP
    shown = [{**c, "last": hms(c["last"])} for c in crow[:cap]]
    doc.table("by_client", ["client", "drops", "worst_gap_s", "last"], shown)
    if len(crow) > cap:
        doc.kv("more", f"{len(crow) - cap} clients hidden. Add --full.")
    aps = tally("ap")
    doc.table("by_ap", ["ap", "drops"], [{"ap": a, "drops": n} for a, n in sorted(aps.items(), key=lambda x: -x[1])])
    hours_map: dict[str, int] = {}
    one_date = time.strftime("%Y%m%d", time.localtime(since)) == time.strftime("%Y%m%d", time.localtime(until))
    for d in drops:
        h = time.strftime("%H" if one_date else "%m-%d %H", time.localtime(d["t"]))
        hours_map[h] = hours_map.get(h, 0) + 1
    doc.table("by_hour", ["hour", "drops"], [{"hour": h, "drops": n} for h, n in hours_map.items()])
    if args.full:
        doc.table("drop_list", ["t", "client", "ap", "band", "gap_s"],
                  [{"t": hms(d["t"]), "client": d["client"], "ap": d["ap"], "band": d["band"],
                    "gap_s": int(round(d["gap"]))} for d in drops])
    doc.kv("help", 'unifi-axi client "<name|mac>" --since <time> --until <time>')
    return 0

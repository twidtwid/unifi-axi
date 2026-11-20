"""Device maps and name resolution for clients and APs."""

from __future__ import annotations

from dataclasses import dataclass
import re

from .util import BAND, MAC_RE, UNKNOWN, UsageError, client_label, norm_mac, tokens


@dataclass
class Site:
    aps: list[dict]
    by_mac: dict[str, dict]
    by_name: dict[str, dict]
    bssid: dict[str, tuple[str, str]]  # bssid -> (ap name, band)

    def vap_band(self, ap_name: str, vap: str) -> str:
        ap = self.by_name.get(ap_name) or {}
        for v in ap.get("vap_table") or []:
            if v.get("name") == vap:
                return BAND.get(v.get("radio"), UNKNOWN)
        m = re.match(r"wifi(\d)", vap or "")
        return {"0": "2.4", "1": "5", "2": "6"}.get(m.group(1), UNKNOWN) if m else UNKNOWN

    def ap_name(self, mac: str | None) -> str | None:
        return self.by_mac.get((mac or "").lower(), {}).get("name")


def build_site(devices: list[dict]) -> Site:
    aps = sorted((d for d in devices if d.get("type") == "uap"), key=lambda d: d.get("name") or "")
    bssid = {}
    for ap in aps:
        for v in ap.get("vap_table") or []:
            if v.get("bssid"):
                bssid[v["bssid"].lower()] = (ap.get("name"), BAND.get(v.get("radio"), UNKNOWN))
    return Site(aps, {(a.get("mac") or "").lower(): a for a in aps}, {a.get("name"): a for a in aps}, bssid)


def ap_online(ap: dict) -> bool:
    return ap.get("state") == 1


@dataclass
class Match:
    macs: list[str]
    name: str
    how: str


class Ambiguous(Exception):
    def __init__(self, query: str, candidates: list[dict]):
        super().__init__(query)
        self.query = query
        self.candidates = candidates


class NoMatch(Exception):
    pass


def client_candidates(sta: list[dict], users: list[dict], events: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for src, items in (("sta", sta), ("user", users)):
        for item in items:
            mac = (item.get("mac") or "").lower()
            if mac and mac not in seen:
                seen[mac] = {"mac": mac, "name": item.get("name"), "hostname": item.get("hostname"),
                             "src": src, "item": item}
    for e in events:
        c = (e.get("parameters") or {}).get("CLIENT") or {}
        mac = (c.get("id") or "").lower()
        if MAC_RE.fullmatch(mac) and mac not in seen:
            seen[mac] = {"mac": mac, "name": c.get("name"), "hostname": c.get("hostname"), "src": "event", "item": {}}
    return list(seen.values())


def resolve_client(query: str, sta: list[dict], users: list[dict], events: list[dict]) -> Match:
    """MAC (any format), then exact name/hostname, then all tokens, then substring.
    One name on several MACs (private-address rotation) follows the live ones."""
    cands = client_candidates(sta, users, events)
    mac = norm_mac(query)
    if mac:
        hit = next((c for c in cands if c["mac"] == mac), None)
        name = client_label(hit["name"], hit["hostname"], mac) if hit else mac
        return Match([mac], name, "mac")
    q = query.strip().lower()
    qt = tokens(query)
    stages = [
        ("exact", lambda c: q in {(c["name"] or "").lower(), (c["hostname"] or "").lower()}),
        (f'tokens("{" ".join(qt)}")', lambda c: bool(qt) and all(t in tokens(f"{c['name'] or ''} {c['hostname'] or ''}") for t in qt)),
        ("substring", lambda c: bool(q) and (q in (c["name"] or "").lower() or q in (c["hostname"] or "").lower())),
    ]
    for how, test in stages:
        hits = [c for c in cands if test(c)]
        if not hits:
            continue
        if len(hits) == 1:
            h = hits[0]
            return Match([h["mac"]], client_label(h["name"], h["hostname"], h["mac"]), how)
        names = {(h["name"] or "").lower() for h in hits}
        if len(names) == 1 and "" not in names:
            live = [h for h in hits if h["src"] in ("sta", "event")] or hits
            return Match([h["mac"] for h in live], hits[0]["name"], how + "; same name, several MACs")
        raise Ambiguous(query, hits)
    raise NoMatch(query)


def exact_ap(query: str, ap: dict) -> bool:
    """Case-insensitive full name, or the AP's MAC in any format (set-power --confirm)."""
    mac = norm_mac(query)
    return (ap.get("name") or "").lower() == query.strip().lower() or bool(mac and mac == (ap.get("mac") or "").lower())


def resolve_ap(query: str, aps: list[dict]) -> dict:
    qt = tokens(query)
    if not qt:  # all([]) and `"" in name` would match every AP
        raise UsageError(f"AP name {query!r} has no letters or digits")
    q = query.strip().lower()
    for test in (lambda a: exact_ap(query, a),
                 lambda a: all(t in tokens(a.get("name") or "") for t in qt),
                 lambda a: q in (a.get("name") or "").lower()):
        hits = [a for a in aps if test(a)]
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            raise Ambiguous(query, [{"name": a.get("name"), "mac": a.get("mac"), "item": {}} for a in hits])
    raise NoMatch(query)

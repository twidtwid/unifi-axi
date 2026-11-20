"""No-argument home view: identity, controller, live AP summary and 24 h drops."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys

from .. import api, clock, config
from ..site import build_site
from ..timeline import DROP_GAP_S, find_drops
from ..toon import Doc
from ..util import tilde
from .common import aps_header
from .drops import baseline_text

DESCRIPTION = "Wi-Fi client and AP diagnosis for a UniFi Network site (read-only except set-power --confirm)"


def bin_path() -> str:
    argv0 = sys.argv[0] if sys.argv and sys.argv[0] else "unifi-axi"
    found = shutil.which(argv0) if os.sep not in argv0 else argv0
    path = Path(found).resolve() if found and Path(found).exists() else None
    return tilde(path) if path else "unifi-axi"


def tls_mode(cfg: config.Config) -> str:
    if cfg.cert_sha256:
        return "pinned"
    return "insecure" if cfg.insecure else "verified"


def identity(doc: Doc) -> None:
    doc.kv("bin", bin_path())
    doc.kv("description", DESCRIPTION)


def cmd_home(args, doc: Doc) -> int:
    cfg = config.active()
    now = clock.now_ts()
    default = "  (default; set UNIFI_URL)" if cfg.url_is_default else ""
    doc.kv("controller", f"{cfg.url}{default}  site={cfg.site}  tls={tls_mode(cfg)}")
    devices, err = api.legacy_list("stat/device")
    doc.kv("aps", aps_header(build_site(devices), now) if not err else f"FAILED ({err})")
    if err:
        doc.kv("drops", "not read (controller unreachable)")
        doc.items("help", ["unifi-axi cert  (TLS and pin check; sends no API key)",
                           "unifi-axi --help  (config: UNIFI_URL, UNIFI_API_KEY, UNIFI_CERT_SHA256)"])
        return 1
    logread = api.system_log(now - 86400, now)
    if logread.complete:
        drops = find_drops(logread.events, DROP_GAP_S, lambda e: True)
        doc.kv("drops", f"{len(drops)} in 24h (all wireless clients; reconnect within {DROP_GAP_S} s)"
                        + baseline_text(cfg, len(drops), 86400))
    else:
        doc.kv("drops", f"INCOMPLETE ({logread.status()}) {logread.error or ''}".strip())
    doc.items("help", ['unifi-axi client "<name|mac>" --since 10m',
                       "unifi-axi --help  (aps, clients, drops, verify, kickout, cert, set-power)"])
    return 0 if logread.complete else 1

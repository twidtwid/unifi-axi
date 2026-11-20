"""`cert`: show the controller's TLS leaf certificate and the line that pins it.

Read-only. It opens a TLS connection, reads the certificate and closes the
connection: no HTTP request, so no API key, is ever sent. Compare the
fingerprint out of band (openssl, or the console's own settings) before you
pin it; a pin taken over a hostile network pins the attacker.
"""

from __future__ import annotations

import calendar
import time

from .. import api, clock, config
from ..toon import Doc
from ..util import UNKNOWN

OID_NAMES = {b"\x55\x04\x03": "CN", b"\x55\x04\x06": "C", b"\x55\x04\x07": "L", b"\x55\x04\x08": "ST",
             b"\x55\x04\x0a": "O", b"\x55\x04\x0b": "OU"}


class DerError(ValueError):
    pass


def tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """(tag, value start, value end) of the DER element at pos."""
    if pos + 2 > len(data):
        raise DerError("short element")
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise DerError("bad length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if pos + length > len(data):
        raise DerError("element overruns")
    return tag, pos, pos + length


def children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out, pos = [], start
    while pos < end:
        tag, a, b = tlv(data, pos)
        out.append((tag, a, b))
        pos = b
    return out


def name_text(data: bytes, start: int, end: int) -> str:
    parts = []
    for _, sa, sb in children(data, start, end):  # SET
        for _, qa, qb in children(data, sa, sb):  # SEQUENCE { OID, value }
            items = children(data, qa, qb)
            if len(items) < 2:
                continue
            oid = data[items[0][1]:items[0][2]]
            raw = data[items[1][1]:items[1][2]]
            value = raw.decode("utf-8", "replace") if items[1][0] != 0x1E else raw.decode("utf-16-be", "replace")
            parts.append(f"{OID_NAMES.get(oid, 'OID')}={value}")
    return ", ".join(parts) or UNKNOWN


def time_value(tag: int, raw: bytes) -> float:
    text = raw.decode("ascii")
    fmt = "%y%m%d%H%M%SZ" if tag == 0x17 else "%Y%m%d%H%M%SZ"
    return calendar.timegm(time.strptime(text, fmt))


def parse_certificate(der: bytes) -> dict:
    """subject, issuer, not_before, not_after from an X.509 DER blob."""
    tag, a, b = tlv(der, 0)
    if tag != 0x30:
        raise DerError("not a certificate")
    tag, ta, tb = children(der, a, b)[0]  # tbsCertificate
    fields = children(der, ta, tb)
    if fields and fields[0][0] == 0xA0:  # explicit version
        fields = fields[1:]
    if len(fields) < 5:
        raise DerError("short tbsCertificate")
    issuer, validity, subject = fields[2], fields[3], fields[4]
    times = children(der, validity[1], validity[2])
    return {"subject": name_text(der, subject[1], subject[2]), "issuer": name_text(der, issuer[1], issuer[2]),
            "not_before": time_value(times[0][0], der[times[0][1]:times[0][2]]),
            "not_after": time_value(times[1][0], der[times[1][1]:times[1][2]])}


def cmd_cert(args, doc: Doc) -> int:
    cfg = config.active()
    der, verified, err = api.peer_certificate()
    if err or der is None:
        doc.kv("error", err or "no certificate")
        doc.kv("help", "check UNIFI_URL (https://<console address>) and that the console is reachable")
        return 1
    digest = api.fingerprint(der)
    pretty = api.colon_hex(digest)
    chain = {True: "yes", False: "no (self-signed or unknown CA)", None: UNKNOWN}[verified]
    doc.kv("cert", f"{cfg.url}  chain_verified={chain}")
    try:
        info = parse_certificate(der)
    except (DerError, ValueError, IndexError):
        info = None
    if info:
        days = int((info["not_after"] - clock.now_ts()) // 86400)
        fmt = "%Y-%m-%d"
        doc.kv("subject", info["subject"])
        doc.kv("issuer", info["issuer"])
        doc.kv("valid", f"{time.strftime(fmt, time.gmtime(info['not_before']))}..{time.strftime(fmt, time.gmtime(info['not_after']))}"
                        f" UTC ({'expired ' + str(-days) + ' days ago' if days < 0 else 'expires in ' + str(days) + ' days'})")
    else:
        doc.kv("subject", f"{UNKNOWN} (certificate fields not parsed)")
    doc.kv("sha256", pretty)
    code = 0
    if cfg.cert_sha256 == digest:
        doc.kv("pin", "UNIFI_CERT_SHA256 matches this certificate")
    elif cfg.cert_sha256:
        doc.kv("pin", f"MISMATCH: UNIFI_CERT_SHA256 is {api.colon_hex(cfg.cert_sha256)}; requests are refused")
        code = 1
    else:
        doc.kv("pin", "not pinned")
    host = cfg.url.removeprefix("https://")
    if ":" not in host:
        host += ":443"
    doc.items("help", [f"export UNIFI_CERT_SHA256={pretty}",
                       f'or in config.toml: cert_sha256 = "{pretty}"',
                       f"check first: openssl s_client -connect {host} </dev/null 2>/dev/null"
                       " | openssl x509 -noout -fingerprint -sha256"])
    return code

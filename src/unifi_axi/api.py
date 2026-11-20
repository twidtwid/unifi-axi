"""The UniFi Network client. Three layers, each the only way to the one below:

http_request      one HTTPS request (http.client). The TLS handshake and, when
                  UNIFI_CERT_SHA256 is set, the certificate pin check both run
                  BEFORE any request bytes (and so before the API key) are sent.
api_call          the READ path: GET, plus the POST `system-log/all` query.
                  Any other method or path is refused. One retry.
api_write_device  the ONLY write: PUT rest/device/<id> {"radio_table": [...]},
                  no retry. Called only from commands.setpower.set_power_apply.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import http.client
import json
import re
import socket
import ssl
from typing import Any
from urllib.parse import urlsplit

from . import config

DEVICE_ID_RE = re.compile(r"[0-9a-f]{24}")
MAX_PAGES = 20
PAGE_SIZE = 500


class ApiError(str):
    """An error string that also carries a coarse kind (auth, timeout, tls, pin, ...)."""

    kind = "other"

    @classmethod
    def of(cls, kind: str, text: str) -> ApiError:
        error = cls(text[-500:])
        error.kind = kind
        return error


class PinMismatch(Exception):
    def __init__(self, got: str, want: str):
        super().__init__(got)
        self.got, self.want = got, want


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def colon_hex(hexdigest: str) -> str:
    return ":".join(hexdigest[i:i + 2] for i in range(0, len(hexdigest), 2)).upper()


def tls_context(cfg: config.Config) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if cfg.cert_sha256 or cfg.insecure:
        # Pinned: the chain is self-signed, so trust comes from the fingerprint
        # check in open_connection instead. Insecure: no check at all (warned).
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def open_connection(cfg: config.Config, timeout: float) -> http.client.HTTPSConnection:
    """Connect and finish the TLS handshake. With a pin, compare the leaf
    certificate's SHA-256 before returning: no request can be sent on a
    connection that failed the pin."""
    parts = urlsplit(cfg.url)
    conn = http.client.HTTPSConnection(parts.hostname or "", parts.port or 443, timeout=timeout,
                                       context=tls_context(cfg))
    conn.connect()
    if cfg.cert_sha256:
        der = conn.sock.getpeercert(binary_form=True) if conn.sock else None
        got = fingerprint(der or b"")
        if not der or got != cfg.cert_sha256:
            conn.close()
            raise PinMismatch(got if der else "none", cfg.cert_sha256)
    return conn


def error_kind(exc: BaseException) -> str:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "tls"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, ValueError):
        return "invalid"
    return "network"


def http_request(method: str, path: str, body: Any = None, timeout: float = 20) -> tuple[Any | None, ApiError | None]:
    """One HTTPS request. Never raises for network, TLS, pin or HTTP errors."""
    cfg = config.active()
    if not cfg.api_key:
        return None, ApiError.of("no_key", "no API key (UNIFI_API_KEY or --api-key-file)")
    headers = {"X-API-KEY": cfg.api_key, "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    conn = None
    try:
        conn = open_connection(cfg, timeout)
        conn.request(method, path, body=data, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        if response.status == 401 or response.status == 403:
            return None, ApiError.of("auth", f"{method} {path} returned HTTP {response.status} (API key rejected)")
        if response.status >= 400:
            return None, ApiError.of("http", f"{method} {path} returned HTTP {response.status}")
        return json.loads(raw.decode("utf-8")), None
    except PinMismatch as exc:
        return None, ApiError.of("pin", f"certificate pin mismatch: controller presented sha256 "
                                        f"{colon_hex(exc.got) if exc.got != 'none' else 'none'}; "
                                        f"UNIFI_CERT_SHA256 is {colon_hex(exc.want)}; nothing sent")
    except ssl.SSLCertVerificationError as exc:
        return None, ApiError.of("tls", f"TLS certificate not trusted ({getattr(exc, 'verify_message', None) or 'verify failed'}); "
                                        "pin it with UNIFI_CERT_SHA256 (see `unifi-axi cert`)")
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return None, ApiError.of(error_kind(exc), f"{method} {path} failed: {type(exc).__name__}: {exc}"[:300])
    finally:
        if conn is not None:
            conn.close()


def peer_certificate(timeout: float = 10) -> tuple[bytes | None, bool | None, str | None]:
    """(leaf DER, chain_verified, error) for `unifi-axi cert`. Sends no request and no key."""
    cfg = config.active()
    probe = config.Config(url=cfg.url, insecure=True)
    try:
        conn = open_connection(probe, timeout)
    except (OSError, ValueError) as exc:
        return None, None, f"TLS connect to {cfg.url} failed: {type(exc).__name__}: {exc}"[:300]
    try:
        der = conn.sock.getpeercert(binary_form=True) if conn.sock else None
    finally:
        conn.close()
    verified: bool | None
    try:
        strict = open_connection(config.Config(url=cfg.url), timeout)
        strict.close()
        verified = True
    except ssl.SSLCertVerificationError:
        verified = False
    except (OSError, ValueError):
        verified = None
    return der, verified, None if der else "controller sent no certificate"


# --------------------------------------------------------------------------
# The read path and the one write.

def api_call(method: str, path: str, body: Any = None, timeout: float = 20,
             retry: bool = True) -> tuple[Any | None, str | None]:
    """The READ path: one controller request with one retry. Only GET and the
    system-log POST; anything else is refused. Writes use api_write_device.
    The set-power poll passes retry=False and the time left, so a read cannot
    run past the poll deadline."""
    if method != "GET" and not (method == "POST" and path == config.active().v2_log):
        return None, f"refused: {method} {path} is not a read"
    payload, error = http_request(method, path, body, timeout=timeout)
    if error and retry and error.kind not in ("pin", "tls", "auth", "no_key"):
        payload, error = http_request(method, path, body, timeout=timeout)
    return payload, (str(error) if error else None)


def api_write_device(device_id: str, radio_table: list[dict]) -> tuple[Any | None, str | None]:
    """The ONLY write path: PUT rest/device/<id> with {"radio_table": [...]}.

    No retry (a timed-out PUT may still have applied). Called only from
    set_power_apply after every guard has passed.
    """
    if not isinstance(device_id, str) or not DEVICE_ID_RE.fullmatch(device_id):
        return None, f"refused: device id {device_id!r} is not a controller _id"
    payload, error = http_request("PUT", f"{config.active().legacy_api}/rest/device/{device_id}",
                                  {"radio_table": radio_table}, timeout=20)
    return payload, (str(error) if error else None)


def legacy_list(path: str, timeout: float | None = None) -> tuple[list[dict] | None, str | None]:
    """GET <legacy api>/<path> and return its data array. timeout set: one bounded read, no retry."""
    full = f"{config.active().legacy_api}/{path}"
    if timeout is None:
        payload, error = api_call("GET", full)
    else:
        payload, error = api_call("GET", full, timeout=timeout, retry=False)
    if error:
        return None, error
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        return None, f"GET {path}: shape: no data array"
    return [d for d in data if isinstance(d, dict)], None


# --------------------------------------------------------------------------
# The controller event log (v2 system-log), offset-paged.

def param(e: dict, key: str, sub: str = "name") -> Any:
    return ((e.get("parameters") or {}).get(key) or {}).get(sub)


@dataclass
class LogRead:
    events: list[dict] = field(default_factory=list)
    pages_read: int = 0
    pages_total: int = 0
    error: str | None = None
    capped: bool = False

    @property
    def complete(self) -> bool:
        return self.error is None and not self.capped and self.pages_read >= self.pages_total

    def status(self) -> str:
        return f"{self.pages_read}/{self.pages_total} pages"


def event_id(e: dict) -> str:
    return str(e.get("id") or f"{e.get('key')}|{e.get('timestamp')}|{param(e, 'CLIENT', 'id')}")


def system_log(t_from: float, t_to: float) -> LogRead:
    """Events are deduped by id (pages shift as new events land). Without
    total_page_count, keep paging while the page is full, up to MAX_PAGES."""
    out = LogRead()
    seen: set[str] = set()
    number = 0
    path = config.active().v2_log
    while True:
        body = {"timestampFrom": int(t_from * 1000), "timestampTo": int(t_to * 1000),
                "pageSize": PAGE_SIZE, "pageNumber": number}
        payload, error = api_call("POST", path, body)
        if error or not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            out.error = error or "shape: system-log returned no data array"
            out.pages_total = max(out.pages_total, number + 1)
            return out
        data = [e for e in payload["data"] if isinstance(e, dict)]
        new = [e for e in data if event_id(e) not in seen]
        seen.update(event_id(e) for e in new)
        out.events.extend(new)
        out.pages_read += 1
        total = payload.get("total_page_count")
        if isinstance(total, int):
            more = number + 1 < total
            out.pages_total = max(total, out.pages_read)  # an empty result reports 0 pages
        else:
            more = len(data) >= PAGE_SIZE
            out.pages_total = out.pages_read + (1 if more else 0)
        if number > 0 and data and not new:
            out.error = f"pagination did not advance (page {number} repeated earlier ids)"
            return out
        number += 1
        if not more:
            return out
        if number >= MAX_PAGES:
            out.capped = True
            return out

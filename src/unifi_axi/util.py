"""Small shared helpers: usage errors, time text, MAC text, secrets, private dirs, threads."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import time
from typing import Any

UNKNOWN = "UNKNOWN"
BAND = {"ng": "2.4", "na": "5", "6e": "6"}
BAND_TOKENS = {"2.4": "ng", "ng": "ng", "5": "na", "na": "na", "6": "6e", "6e": "6e"}
MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")  # always .fullmatch(): `$` passes a trailing newline
TIME_HELP = "10m, 2h, 24h, 3d, HH:MM (today), 'YYYY-MM-DD HH:MM' or YYYY-MM-DDTHH:MM"


class UsageError(Exception):
    """Bad arguments. cli.main prints it as `error:` + `help:` with exit 2."""


# --------------------------------------------------------------------------
# Time. All printed times are this machine's local time.

def hms(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


def hm(ts: float) -> str:
    return time.strftime("%H:%M", time.localtime(ts))


def span_text(seconds: float) -> str:
    seconds = int(round(seconds))
    if seconds % 86400 == 0 and seconds >= 86400:
        return f"{seconds // 86400}d" if seconds > 86400 * 2 else f"{seconds // 3600}h"
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    h, m = divmod(seconds // 60, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m"


def parse_time_arg(text: str, now: float) -> float:
    text = text.strip()
    m = re.fullmatch(r"(\d+)([smhd])", text)
    if m:
        return now - int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    today = time.strftime("%Y-%m-%d", time.localtime(now))
    for fmt, prefix in (("%Y-%m-%d %H:%M:%S", ""), ("%Y-%m-%d %H:%M", ""), ("%Y-%m-%dT%H:%M:%S", ""),
                        ("%Y-%m-%dT%H:%M", ""), ("%Y-%m-%d %H:%M:%S", today + " "), ("%Y-%m-%d %H:%M", today + " ")):
        try:
            return time.mktime(time.strptime(prefix + text, fmt))
        except ValueError:
            continue
    raise UsageError(f"cannot read time {text!r}; use {TIME_HELP}")


def window(args_since: str, args_until: str | None, now: float) -> tuple[float, float]:
    since = parse_time_arg(args_since, now)
    until = parse_time_arg(args_until, now) if args_until else now
    if until <= since:
        raise UsageError("--until must be after --since")
    return since, until


def window_line(since: float, until: float) -> str:
    a, b = time.localtime(since), time.localtime(until)
    date_a = time.strftime("%Y-%m-%d", a)
    end = time.strftime("%H:%M:%S", b) if date_a == time.strftime("%Y-%m-%d", b) else time.strftime("%Y-%m-%d %H:%M:%S", b)
    return f"{date_a} {time.strftime('%H:%M:%S', a)}-{end} {time.strftime('%Z', b)} ({span_text(until - since)})"


def uptime_text(seconds: Any) -> str:
    if not isinstance(seconds, (int, float)) or isinstance(seconds, bool):
        return UNKNOWN
    s = int(seconds)
    return f"{s // 86400}d{s % 86400 // 3600}h"


# --------------------------------------------------------------------------
# MACs, names, numbers.

def norm_mac(text: str) -> str | None:
    hexes = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(hexes) == 12 and re.fullmatch(r"[0-9a-fA-F:\-\. ]+", text.strip()):
        return ":".join(hexes[i:i + 2] for i in range(0, 12, 2)).lower()
    return None


def tokens(text: str) -> list[str]:
    text = re.sub(r"'s\b", "", text.lower().replace("\u2019", "'"))
    return re.findall(r"[a-z0-9]+", text)


def short_mac(mac: str) -> str:
    return ":".join(mac.split(":")[:3]) + ":.."


def client_label(name: str | None, hostname: str | None, mac: str) -> str:
    if name:
        return name
    return f"{hostname or 'client'} ({short_mac(mac)})"


def int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# --------------------------------------------------------------------------
# Secrets and private files.

SECRET_KEY_RE = re.compile(r"^x_|pass|psk|secret|token|authkey|(^|_)key$", re.I)


def strip_secrets(obj: Any) -> Any:
    """Drop x_*, *pass*, *psk*, *secret*, *token*, *authkey* and *_key fields at every depth."""
    if isinstance(obj, dict):
        return {k: strip_secrets(v) for k, v in obj.items() if not SECRET_KEY_RE.search(k)}
    if isinstance(obj, list):
        return [strip_secrets(v) for v in obj]
    return obj


def private_dir(path: Path, exist_ok: bool = False) -> Path:
    """mkdir -p with mode 0700 (chmod too: mkdir's mode is masked by the umask)."""
    path.mkdir(parents=True, exist_ok=exist_ok, mode=0o700)
    os.chmod(path, 0o700)
    return path


def write_private_json(path: Path, name: str, data: Any) -> None:
    """The one JSON writer for captures and change evidence: secrets stripped."""
    (path / name).write_text(json.dumps(strip_secrets(data), indent=1) + "\n")


def tilde(path: Path | str) -> str:
    home, text = str(Path.home()), str(path)
    return "~" + text[len(home):] if text == home or text.startswith(home + os.sep) else text


# --------------------------------------------------------------------------
# Threads.

def parallel(fn, items: list, on_error) -> list:
    """Run fn over items in threads. An exception in one worker becomes on_error(item, exc)."""
    if not items:
        return []

    def guarded(item):
        try:
            return fn(item)
        except Exception as exc:  # noqa: BLE001 - one AP must not sink the others
            return on_error(item, exc)

    with ThreadPoolExecutor(max_workers=len(items)) as pool:
        return list(pool.map(guarded, items))

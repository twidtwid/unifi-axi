"""Configuration: CLI flag > environment > config file > default. No site data is built in.

Environment                     config.toml key          default
UNIFI_URL                       url                      https://192.168.1.1 (the UniFi console default)
UNIFI_API_KEY                   (env only)               none: required
UNIFI_API_KEY_FILE              api_key_file             none (or --api-key-file)
UNIFI_SITE                      site                     default
UNIFI_INSECURE=1                insecure = true          off: TLS chain and hostname are verified
UNIFI_CERT_SHA256               cert_sha256              none (pin the console's self-signed leaf cert)
UNIFI_ROAMING_SSIDS             roaming_ssids            none (comma list / array)
UNIFI_DROP_BASELINE_PER_DAY     drop_baseline_per_day    none
UNIFI_AXI_CONFIG                -                        $XDG_CONFIG_HOME/unifi-axi/config.toml
UNIFI_AXI_STATE_DIR             -                        $XDG_STATE_HOME/unifi-axi (~/.local/state/unifi-axi)
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
from typing import Any

DEFAULT_URL = "https://192.168.1.1"
DEFAULT_SITE = "default"
SITE_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}")


class ConfigError(Exception):
    """Bad or missing configuration. Carries a `help` line for the agent."""

    def __init__(self, message: str, help_text: str):
        super().__init__(message)
        self.help = help_text


@dataclass
class Config:
    url: str = DEFAULT_URL
    url_is_default: bool = True
    api_key: str | None = None
    api_key_source: str = ""
    site: str = DEFAULT_SITE
    insecure: bool = False
    cert_sha256: str | None = None  # 64 lowercase hex chars
    roaming_ssids: tuple[str, ...] = ()
    drop_baseline_per_day: float | None = None
    state_dir: Path = field(default_factory=lambda: default_state_dir())
    config_file: Path | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def captures_dir(self) -> Path:
        return self.state_dir / "captures"

    @property
    def evidence_dir(self) -> Path:
        return self.state_dir / "evidence"

    @property
    def known_hosts(self) -> Path:
        return self.state_dir / "known_hosts"

    @property
    def legacy_api(self) -> str:
        return f"/proxy/network/api/s/{self.site}"

    @property
    def v2_log(self) -> str:
        return f"/proxy/network/v2/api/site/{self.site}/system-log/all"

    def require_api_key(self) -> None:
        if not self.api_key:
            raise ConfigError("no API key: set UNIFI_API_KEY or pass --api-key-file <path>",
                              "create a key in UniFi Network > Settings > Control Plane > Integrations, "
                              "then: export UNIFI_API_KEY=<key>")


def default_state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME")
    return (Path(base) if base else Path.home() / ".local/state") / "unifi-axi"


def default_config_file() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    return (Path(base) if base else Path.home() / ".config") / "unifi-axi" / "config.toml"


def normalize_fingerprint(text: str) -> str:
    """Accept `AB:CD:...` (openssl style) or plain hex, any case. Returns 64 lowercase hex chars."""
    value = re.sub(r"[\s:]", "", text.strip()).lower()
    if value.startswith("sha256="):  # openssl prints `sha256 Fingerprint=...`; tolerate a pasted prefix
        value = value[len("sha256="):]
    if value.startswith("sha256fingerprint="):
        value = value[len("sha256fingerprint="):]
    if not FINGERPRINT_RE.fullmatch(value):
        raise ConfigError(f"certificate fingerprint {text.strip()[:80]!r} is not a SHA-256 hex digest",
                          "unifi-axi cert  (prints the fingerprint and the line to pin it)")
    return value


def truthy(text: str | None) -> bool:
    return (text or "").strip().lower() in ("1", "true", "yes", "on")


# --------------------------------------------------------------------------
# Config file: tomllib on 3.11+, a tiny flat parser on 3.10 (key = value lines only).

def parse_toml(text: str) -> dict[str, Any]:
    try:
        import tomllib  # type: ignore[import-not-found]
    except ModuleNotFoundError:  # Python 3.10
        return parse_flat_toml(text)
    return tomllib.loads(text)


def parse_flat_toml(text: str) -> dict[str, Any]:
    """The subset this tool documents: `key = "string" | number | true/false | ["a", "b"]`."""
    out: dict[str, Any] = {}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.fullmatch(r"([A-Za-z0-9_-]+)\s*=\s*(.+?)\s*(#.*)?", line)
        if not m:
            raise ValueError(f"line {n}: expected key = value")
        key, value = m.group(1), m.group(2)
        out[key] = _flat_value(value, n)
    return out


def _flat_value(value: str, n: int) -> Any:
    if value in ("true", "false"):
        return value == "true"
    if re.fullmatch(r'"[^"\\]*"', value) or re.fullmatch(r"'[^']*'", value):
        return value[1:-1]
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"-?\d+\.\d+", value):
        return float(value)
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        return [] if not inner else [_flat_value(v.strip(), n) for v in inner.split(",") if v.strip()]
    raise ValueError(f"line {n}: cannot read value {value[:40]!r}")


KNOWN_KEYS = {"url", "api_key_file", "site", "insecure", "cert_sha256", "roaming_ssids", "drop_baseline_per_day"}


def read_config_file(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise ConfigError(f"cannot read config file {_tilde(path)}: {type(exc).__name__}",
                          f"check the permissions of {_tilde(path)}") from None
    try:
        data = parse_toml(text)
    except ValueError as exc:  # tomllib.TOMLDecodeError is a ValueError
        raise ConfigError(f"config file {_tilde(path)} is not valid TOML ({exc})",
                          "use key = value lines, e.g. url = \"https://192.168.1.1\"") from None
    if "api_key" in data:
        raise ConfigError(f"config file {_tilde(path)} has api_key; keys are not read from the config file",
                          "put the key in its own file (mode 0600) and set api_key_file = \"<path>\"")
    unknown = sorted(set(data) - KNOWN_KEYS)
    if unknown:
        raise ConfigError(f"config file {_tilde(path)} has unknown keys: {', '.join(unknown)}",
                          "valid keys: " + ", ".join(sorted(KNOWN_KEYS)))
    return data


def _tilde(path: Path) -> str:
    home = str(Path.home())
    text = str(path)
    return "~" + text[len(home):] if text == home or text.startswith(home + os.sep) else text


def _list(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, list):
        items = [str(v) for v in value]
    else:
        items = []
    return tuple(v.strip() for v in items if v.strip())


def load(api_key_file: str | None = None, insecure: bool = False, cert_sha256: str | None = None,
         env: dict[str, str] | None = None) -> Config:
    """Build the Config for one run. Raises ConfigError with a help line."""
    env = os.environ if env is None else env
    path = Path(env["UNIFI_AXI_CONFIG"]).expanduser() if env.get("UNIFI_AXI_CONFIG") else default_config_file()
    data = read_config_file(path)
    cfg = Config(config_file=path if data else None)

    url = env.get("UNIFI_URL") or data.get("url")
    if url:
        cfg.url, cfg.url_is_default = str(url).rstrip("/"), False
    if not re.fullmatch(r"https://[^/\s?#]+", cfg.url):
        raise ConfigError(f"UNIFI_URL {cfg.url!r} must be https://<host>[:port] with no path",
                          "export UNIFI_URL=https://<console address>")

    site = env.get("UNIFI_SITE") or data.get("site") or DEFAULT_SITE
    if not SITE_RE.fullmatch(str(site)):
        raise ConfigError(f"UNIFI_SITE {site!r} must be letters, digits, '-' or '_'",
                          "the site id is the path part after /manage/ in the UniFi URL (often 'default')")
    cfg.site = str(site)

    if env.get("UNIFI_API_KEY"):
        cfg.api_key, cfg.api_key_source = env["UNIFI_API_KEY"].strip(), "UNIFI_API_KEY"
    else:
        key_path = api_key_file or env.get("UNIFI_API_KEY_FILE") or data.get("api_key_file")
        if key_path:
            p = Path(str(key_path)).expanduser()
            try:
                cfg.api_key = p.read_text().strip() or None
            except OSError as exc:
                raise ConfigError(f"cannot read API key file {_tilde(p)}: {type(exc).__name__}",
                                  "pass --api-key-file <path> to a readable file holding only the key") from None
            cfg.api_key_source = "api_key_file"
            if cfg.api_key is None:
                raise ConfigError(f"API key file {_tilde(p)} is empty", "write the key into that file")
    if cfg.api_key and not re.fullmatch(r"[\x21-\x7e]+", cfg.api_key):
        raise ConfigError("the API key has spaces or control characters", "check UNIFI_API_KEY / the key file")

    pin = cert_sha256 or env.get("UNIFI_CERT_SHA256") or data.get("cert_sha256")
    if pin:
        cfg.cert_sha256 = normalize_fingerprint(str(pin))
    cfg.insecure = bool(insecure or truthy(env.get("UNIFI_INSECURE")) or data.get("insecure") is True)
    if cfg.insecure and cfg.cert_sha256:
        cfg.insecure = False  # the pin is the stronger check; it wins
        cfg.warnings.append("UNIFI_INSECURE ignored: UNIFI_CERT_SHA256 pins the certificate")
    elif cfg.insecure:
        cfg.warnings.append("TLS verification is off (UNIFI_INSECURE); pin the certificate instead: "
                            "unifi-axi cert")

    cfg.roaming_ssids = _list(env.get("UNIFI_ROAMING_SSIDS") or data.get("roaming_ssids"))
    baseline = env.get("UNIFI_DROP_BASELINE_PER_DAY") or data.get("drop_baseline_per_day")
    if baseline not in (None, ""):
        try:
            cfg.drop_baseline_per_day = float(baseline)
        except (TypeError, ValueError):
            raise ConfigError(f"UNIFI_DROP_BASELINE_PER_DAY {baseline!r} is not a number",
                              "export UNIFI_DROP_BASELINE_PER_DAY=<drops per day>") from None

    if env.get("UNIFI_AXI_STATE_DIR"):
        cfg.state_dir = Path(env["UNIFI_AXI_STATE_DIR"]).expanduser()
    elif env is not os.environ and env.get("XDG_STATE_HOME"):
        cfg.state_dir = Path(env["XDG_STATE_HOME"]) / "unifi-axi"
    return cfg


# The active configuration for this process. cli.main sets it once per run.
_ACTIVE: Config | None = None


def set_active(cfg: Config) -> None:
    global _ACTIVE
    _ACTIVE = cfg


def active() -> Config:
    if _ACTIVE is None:
        set_active(Config())
    assert _ACTIVE is not None
    return _ACTIVE


"""Argument parsing, configuration and the single error boundary.

Every outcome is printed by main() on stdout, as TOON (or JSON with --json):
data, `error:` + `help:` lines, never a traceback. Exit codes: 0 answered
(including previews and no-ops), 1 could not answer or partial, 2 usage or
configuration error (unknown flags are rejected with the command's valid
flags listed), 3 the device differs from the controller (verify, set-power).
"""

from __future__ import annotations

import argparse
import sys

from . import config
from ._version import VERSION
from .commands.aps import cmd_aps
from .commands.cert import cmd_cert
from .commands.client import cmd_client
from .commands.clients import cmd_clients
from .commands.drops import cmd_drops
from .commands.home import cmd_home, identity
from .commands.kickout import cmd_kickout
from .commands.setpower import LIVE_CALL_TEXT, POLL_EVERY_S, POLL_LIMIT_S, cmd_set_power
from .commands.verify import cmd_verify
from .timeline import DROP_GAP_S
from .toon import Doc
from .util import TIME_HELP, UsageError

COMMANDS = ("client", "aps", "clients", "drops", "verify", "kickout", "cert", "set-power")
HANDLERS = {"client": cmd_client, "aps": cmd_aps, "clients": cmd_clients, "drops": cmd_drops, "verify": cmd_verify,
            "kickout": cmd_kickout, "cert": cmd_cert, "set-power": cmd_set_power, None: cmd_home}
NEEDS_KEY = set(COMMANDS) - {"cert"}
EXIT_CODES = "Exit codes: 0 answered, 1 could not answer (or partial), 2 usage error."
CONFIG_HELP = """Configuration (flag > env > ~/.config/unifi-axi/config.toml):
  UNIFI_URL            controller, default https://192.168.1.1
  UNIFI_API_KEY        API key (or --api-key-file / UNIFI_API_KEY_FILE)
  UNIFI_SITE           site id, default `default`
  UNIFI_CERT_SHA256    pin the console's self-signed certificate (see `unifi-axi cert`)
  UNIFI_INSECURE=1     skip TLS verification (prefer the pin)
  UNIFI_ROAMING_SSIDS  SSIDs that must offer FT (802.11r) to every client class
  UNIFI_DROP_BASELINE_PER_DAY  print this baseline next to the drop rate"""

SET_POWER_HELP = f"""Examples:
  unifi-axi set-power office 5 18                preview only; sends nothing
  unifi-axi set-power "AP Office" 5 18 --confirm write, wait for the AP, verify on the device
  unifi-axi set-power "AP Office" 5 auto --confirm
  unifi-axi set-power "AP Office" 5 auto --tx-power 20 --confirm   auto, and store tx_power 20

Sets tx_power_mode=custom and tx_power (or tx_power_mode=auto, tx_power kept unless
--tx-power) on ONE radio by a PUT of the full radio_table (rest/device/<id>).
--confirm needs the exact AP name (any case) or its MAC. Refused, nothing sent: AP not
online, radio missing, value outside min_txpower..max_txpower (or range UNKNOWN), no SSH
credentials or rest/wlanconf, no served SSID on that radio, or radio_table changed
between the read and the PUT. Already at the target: no-op, nothing sent, exit 0.
After the PUT it waits for state 1 AND a new cfgversion/provisioned_at (or a non-1
state) AND the target in radio_table, then reads Tx-Power on the device every
{POLL_EVERY_S} s until it matches, all within {POLL_LIMIT_S} s of the write. Success is the
device value, not HTTP 200. Evidence (secrets stripped, mode 0700):
~/.local/state/unifi-axi/evidence/unifi-change-<YYYYMMDD-HHMM>-<ap>-power/.
Prints a change-log stub and the undo command.

WARNING: {LIVE_CALL_TEXT}. The tool cannot detect a call; it prints the radio's client count.

Exit codes: 0 preview, no-op, or device matches the target; 1 refused, write failed, poll
timeout, device not read, or internal error after the write; 2 usage error; 3 device
differs from the target or another radio_table field drifted (undo printed)."""


class Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("allow_abbrev", False)  # --sin must not silently mean --since
        kwargs.setdefault("formatter_class", argparse.RawDescriptionHelpFormatter)
        super().__init__(*args, **kwargs)

    def error(self, message):  # usage errors go to stdout, exit 2 (AXI principle 6)
        raise UsageError(message)

    def print_help(self, file=None):
        sys.stdout.write(self.format_help())


def add_globals(p: argparse.ArgumentParser, sub: bool) -> None:
    """Flags every command accepts, before or after the command name."""
    d = argparse.SUPPRESS if sub else None
    p.add_argument("--json", action="store_true", default=d if sub else False, help="same data as JSON")
    p.add_argument("--fields", default=d, help="extra table columns, comma separated")
    p.add_argument("--api-key-file", default=d, metavar="PATH", help="read the API key from this file")
    p.add_argument("--insecure", action="store_true", default=d if sub else False,
                   help="skip TLS verification (prefer --cert-sha256)")
    p.add_argument("--cert-sha256", default=d, metavar="HEX", help="pin the controller certificate (SHA-256)")


def add_full(p, what: str = "no truncation") -> None:
    p.add_argument("--full", action="store_true", help=what)


def add_save(p) -> None:
    p.add_argument("--save", action="store_true",
                   help="keep raw captures in ~/.local/state/unifi-axi/captures/<ts>-<cmd>/ (mode 0700)")


def add_window(p, default: str) -> None:
    p.add_argument("--since", default=default, help=f"window start: {TIME_HELP} (default {default})")
    p.add_argument("--until", default=None, help="window end, same forms as --since (default now)")


def build_parser() -> Parser:
    p = Parser(prog="unifi-axi", description="Wi-Fi client and AP diagnosis for a UniFi Network site "
               "(read-only except set-power --confirm). No command: live summary.",
               epilog=CONFIG_HELP + "\n\n" + EXIT_CODES + " 3 device differs from the controller (verify, set-power).")
    p.add_argument("-v", "-V", "--version", action="version", version=VERSION)
    add_globals(p, sub=False)
    sp = p.add_subparsers(dest="cmd", parser_class=Parser, metavar="<command>")

    c = sp.add_parser("client", help="one client's timeline: controller events + AP logs + live link",
                      epilog='Examples:\n  unifi-axi client "Alex\'s iPhone" --since 30m\n'
                      '  unifi-axi client 02:00:00:00:a0:01 --since 09:50 --until 10:12 --full\n' + EXIT_CODES)
    c.add_argument("who", help="name, hostname or MAC (any format)")
    add_window(c, "10m")
    c.add_argument("--all-aps", action="store_true", help="read every AP log, not only APs in the client's events")
    c.add_argument("--no-ssh", action="store_true", help="skip AP logs (controller only, fast)")
    add_full(c, "no row cap; also print the raw matched AP lines")
    add_save(c)
    add_globals(c, sub=True)

    a = sp.add_parser("aps", help="radios: configured vs live channel and power",
                      epilog="Examples:\n  unifi-axi aps\n  unifi-axi aps office   (adds model, uplink, uptime, min_rssi)\n"
                      + EXIT_CODES)
    a.add_argument("name", nargs="?", help="one AP (fuzzy name or MAC)")
    add_globals(a, sub=True)

    cl = sp.add_parser("clients", help="wireless clients, weakest signal first",
                       epilog="Examples:\n  unifi-axi clients\n  unifi-axi clients --grep iphone --fields ip,essid\n"
                       + EXIT_CODES)
    cl.add_argument("--grep", default=None, help="substring of name, hostname or MAC")
    add_full(cl, "no row cap (default 50)")
    add_globals(cl, sub=True)

    d = sp.add_parser("drops", help=f"disconnect then reconnect within --gap s (default {DROP_GAP_S})",
                      epilog="Examples:\n  unifi-axi drops --since 24h\n  unifi-axi drops --since 7d --match iphone\n"
                      '  unifi-axi drops --client "Alex iPhone" --full\n' + EXIT_CODES)
    add_window(d, "24h")
    d.add_argument("--gap", type=int, default=DROP_GAP_S,
                   help=f"count a drop when the reconnect comes within this many seconds (default {DROP_GAP_S})")
    d.add_argument("--match", default=None, metavar="TEXT",
                   help="only clients whose name or hostname contains TEXT (default: all wireless clients)")
    d.add_argument("--client", default=None, help="only one client: name, hostname or MAC")
    add_full(d, "no client cap (default 10); also list every drop")
    add_save(d)
    add_globals(d, sub=True)

    v = sp.add_parser("verify", help="read iwconfig + hostapd_cli on the AP and compare with the controller",
                      epilog="Examples:\n  unifi-axi verify office\n  unifi-axi verify --all --json\n"
                      "Exit codes: 0 PASS, 1 UNVERIFIED (device value not read), 2 usage error, 3 MISMATCH "
                      "(device differs from the controller).")
    v.add_argument("ap", nargs="?", help="AP name (fuzzy) or MAC")
    v.add_argument("--all", action="store_true", help="verify every AP")
    add_globals(v, sub=True)

    k = sp.add_parser("kickout", help="Qualcomm firmware kickouts per AP (dmesg + syslog counts, top MACs)",
                      epilog="Examples:\n  unifi-axi kickout\n  unifi-axi kickout office --full\n"
                      "Read-only. The runtime workaround (iwpriv wifiN sta_kickout 320) is in the README.\n"
                      + EXIT_CODES)
    k.add_argument("ap", nargs="?", help="one AP (default: every AP)")
    add_full(k, "no cap on the top-clients table (default 10)")
    add_save(k)
    add_globals(k, sub=True)

    ce = sp.add_parser("cert", help="controller TLS certificate and the line to pin it (sends no API key)",
                       epilog="Examples:\n  unifi-axi cert\n  UNIFI_URL=https://192.0.2.1 unifi-axi cert\n"
                       "Exit codes: 0 shown, 1 not reachable or the configured pin does not match, 2 usage error.")
    add_globals(ce, sub=True)

    s = sp.add_parser("set-power", help="set one radio's tx power (preview unless --confirm)", epilog=SET_POWER_HELP)
    s.add_argument("ap", help="AP name (fuzzy for preview; exact name or MAC for --confirm)")
    s.add_argument("band", help="2.4, 5, 6 (or ng, na, 6e)")
    s.add_argument("dbm", help="target dBm inside the radio's min_txpower..max_txpower, or auto")
    s.add_argument("--tx-power", type=int, default=None, metavar="N",
                   help="with auto only: also store tx_power N (the undo of a change from auto/N)")
    s.add_argument("--confirm", action="store_true",
                   help="send the write, wait for the AP, verify on the device (without it: preview only)")
    add_globals(s, sub=True)
    return p


def subparser(parser: Parser, cmd: str | None) -> argparse.ArgumentParser:
    if cmd is None:
        return parser
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices[cmd]
    return parser


def valid_flags(p: argparse.ArgumentParser) -> list[str]:
    flags = []
    for action in p._actions:
        if action.option_strings and action.dest != "help":
            flags.append(max(action.option_strings, key=len))
    return flags


def usage_lines(parser: Parser, argv: list[str], message: str) -> list[tuple[str, str]]:
    """Turn an argparse message into a one-turn fix: the error and the command's valid flags."""
    cmd = next((a for a in argv if a in COMMANDS), None)
    where = f"`{cmd}`" if cmd else "`unifi-axi`"
    sub = subparser(parser, cmd)
    flags = ", ".join(valid_flags(sub))
    if message.startswith("unrecognized arguments:"):
        extras = message.split(":", 1)[1].split()
        unknown = [x for x in extras if x.startswith("-")]
        if unknown:
            first = unknown[0].split("=", 1)[0]
            return [("error", f"unknown flag {first} for {where}"),
                    ("help", f"valid flags for {where}: {flags} (--help always allowed)")]
        return [("error", f"unexpected argument {extras[0]!r} for {where}"),
                ("help", f"unifi-axi {cmd + ' ' if cmd else ''}--help")]
    if "invalid choice" in message and cmd is None:
        bad = next((a for a in argv if not a.startswith("-")), "?")
        return [("error", f"unknown command {bad!r}"), ("help", f"commands: {', '.join(COMMANDS)}")]
    return [("error", message), ("help", f"unifi-axi {cmd + ' ' if cmd else ''}--help")]


def emit(doc: Doc, as_json: bool) -> None:
    sys.stdout.write(doc.json() if as_json else doc.toon())
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    as_json = "--json" in argv
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except UsageError as exc:
        doc = Doc()
        for k, v in usage_lines(parser, argv, str(exc)):
            doc.kv(k, v)
        emit(doc, as_json)
        return 2
    except SystemExit as exc:  # --help / --version
        return int(exc.code or 0)
    doc = Doc([f for f in (args.fields or "").split(",") if f])
    cmd = args.cmd
    if cmd is None:
        identity(doc)
    try:
        cfg = config.load(api_key_file=args.api_key_file, insecure=args.insecure, cert_sha256=args.cert_sha256)
        if cmd in NEEDS_KEY or cmd is None:
            cfg.require_api_key()
    except config.ConfigError as exc:
        doc.kv("error", str(exc))
        doc.kv("help", exc.help)
        emit(doc, args.json)
        return 2
    config.set_active(cfg)
    for warning in cfg.warnings:
        doc.kv("warn", warning)
    try:
        code = HANDLERS[cmd](args, doc)
    except UsageError as exc:
        doc = Doc()
        doc.kv("error", str(exc))
        doc.kv("help", f"unifi-axi {cmd + ' ' if cmd else ''}--help")
        code = 2
    except KeyboardInterrupt:
        doc.kv("error", "interrupted; output above may be partial")
        code = 130
    except Exception as exc:  # noqa: BLE001 - errors go to stdout with exit 1, never a traceback
        doc.kv("error", f"internal: {type(exc).__name__} in {cmd or 'home'}; output above may be partial")
        doc.kv("help", "re-run with the same arguments; report it if it repeats")
        code = 1
    emit(doc, args.json)
    return code

# Changelog

## 0.1.2

- A key printed more than once (two `warn:` lines, e.g. `--insecure` with `set-power`) now prints as one `key[N]:` list, so strict TOON decoders accept it. The strict CI check covers `--insecure`.

## 0.1.1

Fixes from an independent source review against the AXI principles.

- TOON output now follows the TOON spec (section 7.2): strings are quoted when they contain a colon, bracket, brace, comma or quote, look like a number or literal, or start with `-`. `help[N]:` and other lists use `- ` items. `verify --all` prints one `aps[N]:` list of objects instead of repeated keys, and `clients` names its count line `summary:`. Every command's output decodes with the official `@toon-format/cli` (CI runs it).
- An unknown `--fields` name prints a `warn:` line with the available columns.
- An unknown flag placed before the command is named in the error, with the global flags.
- `clients`, `kickout` and `set-power` controller-read errors now carry a `help:` line.

## 0.1.0

First standalone release.

- Commands: home view, `client` (merged controller + AP-log timeline), `aps`, `clients`, `drops`, `verify`, `kickout`, `cert`, `set-power`.
- `kickout`: read-only per-AP count of Qualcomm `ol_peer_sta_kickout_event_handler` lines (dmesg) and `Excessive Retries` lines (syslog), top MACs, AP uptime. The `iwpriv wifiN sta_kickout 320` workaround is documented, not applied.
- TLS: verification on by default; certificate pinning with `UNIFI_CERT_SHA256` / `--cert-sha256` (checked after the handshake and before any request); `UNIFI_INSECURE=1` as a warned fallback. `cert` prints the fingerprint and the pin line without sending a request.
- Configuration by flag, environment or `~/.config/unifi-axi/config.toml`; no site data built in. Site id, roaming SSIDs and drop baseline are settings.
- `drops` counts every wireless client by default; `--match <text>` narrows by name or hostname. The baseline prints only when configured.
- `verify` checks every enabled WLAN against its own FT flags; `UNIFI_ROAMING_SSIDS` adds the every-client-class FT requirement.
- State (known_hosts, captures, set-power evidence) under `~/.local/state/unifi-axi/`, mode 0700, secrets stripped.
- AXI contract: TOON on stdout, `error:`/`help:` lines, exit 2 for unknown flags with the command's valid flags listed, `--help` with examples on every command, bare `-v`/`-V`/`--version` before the CLI loads, one error boundary.

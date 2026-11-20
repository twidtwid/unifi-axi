# Changelog

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

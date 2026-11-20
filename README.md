# unifi-axi

Agent-ergonomic Wi-Fi diagnosis for a [UniFi Network](https://ui.com/) site. One command answers "what happened to this client in the last N minutes": it merges the controller's event log, the AP-side syslog (over SSH) and the live link into one timeline. It also counts drops, checks the device against the controller, counts Qualcomm firmware kickouts, and changes radio power behind a guard.

It is an [AXI](https://github.com/kunchenguid/axi): output is [TOON](https://toonformat.dev/) on stdout, errors are structured, exit codes mean something, and the tool reports observations, not causes.

- Read-only, except `set-power --confirm`.
- Python 3.10+, standard library only. No dependencies.
- Unofficial. It uses the UniFi Network application's local API, including undocumented endpoints.

## Install

```sh
uv tool install git+https://github.com/twidtwid/unifi-axi
# or
pipx install git+https://github.com/twidtwid/unifi-axi

unifi-axi --version
```

`ssh` must be on `PATH` for the commands that read the APs (`client`, `verify`, `kickout`, `set-power --confirm`).

## Configure

Create an API key in UniFi Network: **Settings > Control Plane > Integrations**. Then:

```sh
export UNIFI_URL=https://192.168.1.1        # your console; this is the default
export UNIFI_API_KEY=<key>                  # or --api-key-file / UNIFI_API_KEY_FILE
unifi-axi cert                              # shows the console certificate and the pin line
export UNIFI_CERT_SHA256=<fingerprint>      # recommended for a self-signed console
unifi-axi
```

| Setting | Env | `config.toml` key | Default |
|---|---|---|---|
| Controller URL | `UNIFI_URL` | `url` | `https://192.168.1.1` (the UniFi console default) |
| API key | `UNIFI_API_KEY` | (not read from the file) | required |
| API key file | `UNIFI_API_KEY_FILE`, `--api-key-file` | `api_key_file` | none |
| Site id | `UNIFI_SITE` | `site` | `default` |
| Certificate pin | `UNIFI_CERT_SHA256`, `--cert-sha256` | `cert_sha256` | none |
| Skip TLS checks | `UNIFI_INSECURE=1`, `--insecure` | `insecure` | off |
| Roaming SSIDs | `UNIFI_ROAMING_SSIDS` (comma list) | `roaming_ssids` (array) | none |
| Drop baseline | `UNIFI_DROP_BASELINE_PER_DAY` | `drop_baseline_per_day` | none |

Precedence: flag, then environment, then `~/.config/unifi-axi/config.toml` (`$XDG_CONFIG_HOME` is honored; `UNIFI_AXI_CONFIG` names another file), then default. On Python 3.10 the config file may use only `key = value` lines.

```toml
url = "https://192.168.1.1"
api_key_file = "~/.config/unifi-axi/api-key"
cert_sha256 = "AB:CD:...:EF"
roaming_ssids = ["HomeLAN"]
```

The API key never goes in `config.toml`; the tool refuses a file that has one.

### TLS: pin the certificate

UniFi consoles ship a self-signed certificate, so normal verification fails. Pin it instead of turning verification off.

1. Read the fingerprint from the console over a network you trust:
   ```sh
   openssl s_client -connect 192.168.1.1:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
   ```
2. Compare it with `unifi-axi cert`, which prints the same SHA-256 and the exact line to set. `cert` opens a TLS connection only; it sends no request and no API key.
3. Set `UNIFI_CERT_SHA256` (colon-separated or plain hex, any case).

With a pin, the tool completes the TLS handshake without chain or hostname checks, then compares the SHA-256 of the leaf certificate with the pin. It sends the request (and the API key) only when they match. A mismatch is an `error:` line, exit 1, and nothing is sent. A console that renews its certificate needs a new pin; `unifi-axi cert` shows the new value.

`UNIFI_INSECURE=1` skips all checks and prints a `warn:` line in every output. If both are set, the pin wins.

### State on disk

Everything the tool writes is under `~/.local/state/unifi-axi/` (`$XDG_STATE_HOME`, or `UNIFI_AXI_STATE_DIR`), mode 0700:

- `known_hosts`: AP SSH host keys (first use accepted; a changed key is refused).
- `captures/<ts>-<cmd>/`: raw captures, only with `--save`.
- `evidence/unifi-change-<ts>-<ap>-power/`: `before.json`, `put.json`, `after.json` for each `set-power --confirm`.

Fields named `x_*`, `*pass*`, `*psk*`, `*secret*`, `*token*`, `*authkey*` and `*_key` are removed from every saved file. Keep this directory out of any synced or web-served folder.

### AP SSH

`client`, `verify` and `kickout` read the APs over SSH with the site's device SSH credentials, which the tool reads from the controller (`get/setting/mgmt`). Set them in **UniFi Devices > Device Updates and Settings > Device SSH Authentication** (Ubiquiti's [SSH help article](https://help.ui.com/hc/en-us/articles/204909374-Connecting-to-UniFi-with-Debug-Tools-SSH); older versions put it under Settings > System). The password reaches `ssh` only through an `SSH_ASKPASS` helper and the child's environment. It is never in argv, output or saved files. Only read commands run on the AP: `date`, `cat`, `head`, `grep`, `tail`, `cut`, `ls`, `dmesg`, `iwconfig` and `hostapd_cli get_config`. A command whose output lacks the `---END` marker counts as truncated. Without SSH, use `--no-ssh` (on `client`); the timeline then shows controller rows only.

## AXI principles

| # | Principle | Here |
|---|---|---|
| 1 | Token-efficient output | TOON tables on stdout; `--json` gives the same data |
| 2 | Minimal schemas | 4 to 9 columns; `--fields` adds columns that exist in the rows |
| 3 | Truncation | Row caps with `more: N rows hidden. Add --full.` |
| 4 | Pre-computed aggregates | `summary:` (roams, FT, drops, BTM accept/reject, worst RSSI), drops by band/client/AP/hour |
| 5 | Definitive empty states | `timeline: 0 events for X in 12:00-12:10. controller=ok ap_logs=4/4 ...` |
| 6 | Structured errors | `error:` + `help:` on stdout; unknown flags exit 2 with the command's valid flags; no prompts; no tracebacks; no-ops exit 0 |
| 7 | Ambient context | Not offered. Wi-Fi diagnosis is occasional; a session hook would cost tokens in every session. A skill stub ships in `skills/unifi-axi/` |
| 8 | Content first | `unifi-axi` with no arguments shows the live AP summary and 24 h drops |
| 9 | Contextual disclosure | At most two `help:` lines, with complete commands |
| 10 | Help | `--help` on every command with examples; bare `-v`/`-V`/`--version` answers before the CLI loads |

Source map for reviewers: `src/unifi_axi/entry.py` (version fast path), `cli.py` (parser, unknown-flag errors, the single error boundary), `api.py` (HTTP, pin check, read guard, the one write), `commands/setpower.py` (the guarded write), `toon.py` (output).

Claim grammar: every timeline row names its source (`ctl`, `ap`, `ctl+ap`). A missing value prints `UNKNOWN`. Disagreeing sources print `conflict:`. Partial reads say what is missing.

## Commands

Samples below come from the synthetic test fixtures (made-up names, `02:...` MACs, `192.0.2.x` addresses).

### `unifi-axi` (home)

```
bin: ~/.local/bin/unifi-axi
description: Wi-Fi client and AP diagnosis for a UniFi Network site (read-only except set-power --confirm)
controller: https://192.0.2.1  site=default  tls=pinned
aps: 4 of 4 online  fw=8.8.14.20179 (all)  wifi_clients=41  as_of=19:02:51
drops: 3 in 24h (all wireless clients; reconnect within 180 s)  per_day=3.0
help[2]:
  unifi-axi client "<name|mac>" --since 10m
  unifi-axi --help  (aps, clients, drops, verify, kickout, cert, set-power)
```

### `client <name|mac> [--since 10m] [--until T] [--all-aps] [--no-ssh] [--full] [--save]`

Name, hostname or MAC in any format. `Alex's iPhone` matches `Alex iPhone`. One name on several MACs (private-address rotation) follows the live ones. Times: `10m`, `2h`, `3d`, `HH:MM`, `YYYY-MM-DD HH:MM`.

```
client: Alex iPhone  mac=02:00:00:00:a0:01  ip=192.0.2.13  match=tokens("alex iphone")
window: 2026-11-19 09:50:00-10:12:00 PST (22m)
sources: controller=ok(7 client events of 14; 1/1 pages)  ap_logs=4/4 chosen of 4 online  stat_sta=ok  rest_user=ok
now: ap=AP Office  band=5  ch=149  signal=-62  last_seen=60s  retries=14.1%  satisfaction=100  11r_ctl=no  (stat/sta)
summary: roams=6 (ft=5 full_sae=1 unknown=0)  ft_fail=1  ctl_repeat=1  drops=0  btm_req=14 accepted=2 rejected=3  worst_rssi=-92 (AP Patio 09:56:53)
conflict: none
timeline[18]{t,src,ap,band,event,rssi,detail}:
  09:51:44,ctl+ap,AP Shop,5,roam ft,-72,from AP Office (-80); ctl +20s
  09:52:02,ap,AP Den,2.4,ft attempt,UNKNOWN,"FT auth seen, no AP-STA-CONNECTED; did not acknowledge association response"
  09:52:03,ctl+ap,AP Den,2.4,join full_sae,-49,from AP Shop (-77)
  09:52:07,ap,AP Office,5,disconnect,UNKNOWN,kicked out: Excessive Retries; client joined AP Den at 09:52:03
  09:53:39,ctl+ap,AP Office,5,roam ft,-47,from AP Den (-57)
  ...
more: 4 rows hidden (4 left). Add --full.
```

- Controller roam events lag the AP line by up to about 40 s. A controller row takes the closest earlier AP join within 60 s and prints `ctl +Ns`.
- A controller-only roam prints `FT UNKNOWN`. An FT auth with no `AP-STA-CONNECTED` is an `ft attempt` row.
- It reads the APs named in the client's events plus its current AP. If the window has a disconnect, it reads every online AP. `sources:` shows the coverage.
- If the controller log read fails or is incomplete, `roams`, `drops` and `ctl_repeat` print `UNKNOWN` and the exit code is 1. If an AP log is missing or starts after `--since`, `conflict:` is `UNKNOWN`, not `none`.
- AP clocks: the tool reads each AP's `date` and corrects zone, DST and skew (`clock_skew=` when over 5 s).

### `aps [<ap>]`

```
aps: 4 of 4 online  fw=8.8.14.20179 (all)  wifi_clients=41  as_of=19:02:51
radios[11]{ap,band,ch_cfg,ch_live,width,pwr_cfg,pwr_live,util,sta}:
  AP Office,5,149,149,40,20,20,4,7
  AP Patio,5,157,157,40,auto,25,15,1
  ...
mismatch: none
```

`pwr_live` is controller telemetry. One AP adds model, uplink, uptime, `min_rssi` and the power range.

### `clients [--grep text] [--full]`

```
clients: 4 wireless (4 total in stat/sta)
clients[4]{name,mac,ap,band,signal}:
  Alex Watch,02:00:00:00:a0:03,AP Office,5,-70
  Sam iPhone,02:00:00:00:a0:02,AP Office,5,-63
  ...
```

### `drops [--since 24h] [--gap 180] [--match text | --client who] [--full] [--save]`

A drop is a wireless disconnect followed by a reconnect of the same client within `--gap` seconds. Two disconnects before one reconnect count once. Default scope is every wireless client. `--match iphone` keeps clients whose name or hostname contains the text. `per_day` is always printed for the default scope; `baseline_per_day` appears only when you configure it.

```
drops: 3 in 24h (all wireless clients; reconnect within 180 s)  per_day=3.0
events: 9 read; 2/2 pages; complete
by_band[2]{band,drops,per_h}:
  5,2,0.08
  2.4,1,0.04
by_client[3]{client,drops,worst_gap_s,last}:
  Sam iPhone,1,9,08:00:00
  ...
```

An incomplete event-log read prints `drops: INCOMPLETE (...)` and exits 1. It never prints a partial count as the answer.

### `verify <ap> | --all`

Reads `iwconfig` and `hostapd_cli get_config` on the AP and compares channel, power and FT key management with the controller.

```
verify: AP Office (192.0.2.92)  fw=8.8.14.20179  ssh=ok 0.4s
radios[3]{band,iface,ssid,ch_dev,pwr_dev,pwr_cfg,key_mgmt,ft}:
  2.4,wifi0ap0,ExampleLAN,6,18,18,FT-SAE SAE,yes
  2.4,wifi0ap6,ExampleIoT,6,18,18,WPA-PSK SAE,n/a
  5,wifi1ap2,ExampleLAN,149,20,20,FT-SAE SAE,yes
result: PASS  power 2/2 custom radios match; FT on 2/2 FT-configured radios
```

FT rule: every enabled WLAN must run the FT suites its own flags turn on (`fast_roaming_enabled` gives `FT-PSK` to WPA2 clients, `wpa3_fast_roaming` gives `FT-SAE` to WPA3 clients). A WLAN in `UNIFI_ROAMING_SSIDS` must also offer FT to every client class it admits; a WPA3 transition network with only `FT-PSK` then fails. Exit 0 `PASS`, 3 `MISMATCH` (a device value differs), 1 `UNVERIFIED` (a device value was not read; never reported as a mismatch).

### `kickout [<ap>] [--full] [--save]`

Read-only. See [Qualcomm firmware kickout](#qualcomm-firmware-kickout).

```
kickout: 2 dmesg kicks, 5 'Excessive Retries' log lines on 4/4 APs read
aps[4]{ap,dmesg_kicks,log_retries,log_from,uptime}:
  AP Den,0,1,11/18 17:20,1d0h
  AP Office,2,4,11/18 17:20,1d0h
  ...
top_clients[2]{client,mac,kicks,aps}:
  Alex iPhone,02:00:00:00:a0:01,4,AP Den/AP Office
  Sam iPhone,02:00:00:00:a0:02,1,AP Office
help: unifi-axi client <mac> --since 24h  (kick -> disconnect -> drop rows)
```

`dmesg_kicks` covers the current boot (see `uptime`). `log_retries` covers the syslog files from `log_from`.

### `cert`

```
cert: https://192.0.2.1  chain_verified=no (self-signed or unknown CA)
subject: CN=unifi.example
issuer: CN=Example CA
valid: 2025-01-01..2035-01-01 UTC (expires in 2964 days)
sha256: 9F:...:4C
pin: not pinned
help[3]:
  export UNIFI_CERT_SHA256=9F:...:4C
  or in config.toml: cert_sha256 = "9F:...:4C"
  check first: openssl s_client -connect 192.0.2.1:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

### `set-power <ap> <band> <dBm|auto> [--tx-power N] [--confirm]`

```
set-power: AP Office 5 GHz  20 -> 18 dBm  PREVIEW (nothing sent)
radio: mode=custom ch=149 width=40 sta=7  body: only na tx_power_mode/tx_power change; other radios and fields sent as read
warn: do not apply during a live call or walk test; the change can drop clients on this radio
clients: 7 on AP Office 5 GHz now
help: unifi-axi set-power 'AP Office' 5 18 --confirm
```

## set-power safety model

`set-power` is the only command that writes, and it writes only with `--confirm`.

1. **Preview by default.** Without `--confirm` it prints old and new values, the radio's client count and the exact confirm command. Nothing is sent.
2. **Exact target.** `--confirm` needs the AP's exact name (any case) or its MAC. A fuzzy match prints the preview and exits 1.
3. **Refusals, nothing sent:** AP not online; radio missing; dBm outside `min_txpower..max_txpower` or the range unknown; no SSH credentials, no `rest/wlanconf`, or no served SSID on that radio (the device check could not run).
4. **Idempotent.** Already at the target: `no-op`, exit 0, nothing sent.
5. **Full body, one write.** It PUTs the full fetched `radio_table` to `rest/device/<id>` with one radio's `tx_power_mode`/`tx_power` changed. It does not use `radio_table_overrides`, which U7 APs revert. `api.api_write_device` is the only function that can send a non-read request, and only `set_power_apply` calls it. The read path (`api.api_call`) refuses every method except GET and the event-log query. The write is never retried.
6. **Optimistic concurrency.** Just before the PUT it re-reads the AP and refuses if any configuration field of `radio_table` changed. Derived fields the controller refreshes on its own (`current_antenna_gain`, `radio_caps*`, `min/max_txpower`, `has_*`, `is_11*`) are ignored, and the body is rebuilt from the re-read.
7. **Evidence before the write.** `before.json` and `put.json` are written first; a failure to write them refuses the change.
8. **Wait for provisioning.** After the PUT it waits until the AP is in state 1 AND its `cfgversion` or `provisioned_at` moved (or a non-1 state was seen) AND the fresh `radio_table` holds the target. Every read is bounded by the time left.
9. **The device decides.** It reads `Tx-Power` on the device over SSH every 5 s until it matches, all within 120 s of the write. HTTP 200 is not success. A value it could not read is `UNVERIFIED` (exit 1), never `MISMATCH`. For `auto` the device power is reported, not compared.
10. **Drift.** Any other non-derived field that differs between the PUT body and the controller after the write is `DRIFT`, exit 3.
11. **Undo always printed.** Every path after the PUT, including a failed PUT or an internal error, prints the write time, a change-log stub and the undo command. Undo from `auto` restores both mode and stored power (`auto --tx-power N`).

The tool cannot detect a live call. Do not apply a change during a call or a walk test.

## Qualcomm firmware kickout

U7 and E7 APs run a Qualcomm driver (`qca_ol`) that disconnects a client after a run of unacknowledged frames. It acts below hostapd and the controller, so the dashboard shows only a disconnect. It fires at good signal and often on idle phones in power save.

- **Symptom:** `unifi-axi client` shows `disconnect ... kicked out: Excessive Retries`, then a `drop` with a 10 to 50 s gap.
- **Proof on the AP:** `dmesg | grep kickout` shows `ol_peer_sta_kickout_event_handler: Station <mac> kicked out reason: Excessive Retries (1)`. `unifi-axi kickout` counts these per AP.
- **Workaround (runtime only, not applied by this tool):** on each AP, as the device SSH user, for every radio present:
  ```sh
  iwpriv wifi0 sta_kickout 320   # 2.4 GHz
  iwpriv wifi1 sta_kickout 320   # 5 GHz
  iwpriv wifi2 sta_kickout 320   # 6 GHz, if the AP has it
  ```
  320 is the upstream ath11k "effectively off" value; hostapd's inactivity timer still removes dead clients. The value is write-only (there is no getter), so confirm it by watching the `kickout` counts fall. It is lost on AP reboot, firmware upgrade and reprovision (a `set-power` write reprovisions the AP). Reapply after any of those.
- **Source:** [Root cause of random client disconnects on U7/E7: Qualcomm firmware kickout, with fix](https://community.ui.com/questions/Root-cause-of-random-client-disconnects-on-U7-E7-Qualcomm-firmware-kickout-with-fix/e5ee377e-01ba-4495-8614-5cd6381cc7d0) (Ubiquiti Community).

A guarded `kickout --apply` may come later. This release only measures.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Answered (including previews, no-ops and empty results) |
| 1 | Could not answer, or the answer is partial (a source failed, a device was not read, a write failed) |
| 2 | Usage or configuration error (unknown flag, bad time, missing API key) |
| 3 | The device differs from the controller or the target (`verify` MISMATCH, `set-power` MISMATCH/DRIFT) |

## Tested hardware

- UniFi Network on a Cloud Gateway Fiber (UCG-Fiber), local API key.
- APs: U7 Pro, U7 Lite, U7 Pro Outdoor, firmware 8.8.14.

Other models with Qualcomm radios (U7 family, E7) probably work. Older APs with other chipsets will read fine through the controller, but the AP-log patterns, `verify` parsing and `kickout` are tied to this firmware's text.

## Limitations

- The local API is unofficial. `stat/*`, `rest/*`, `get/setting/mgmt` and `v2/.../system-log/all` are undocumented and can change with any UniFi Network release.
- AP log formats (hostapd, `qca_ol` kernel lines, `iwconfig`) are firmware-specific. A firmware upgrade can silently reduce what the AP side sees; the timeline then shows more `ctl`-only rows and `FT UNKNOWN`.
- The event log keeps a limited history. Long windows can hit the 20-page cap and report `INCOMPLETE`.
- AP SSH uses password authentication with host keys accepted on first use.
- One site per run (`UNIFI_SITE`).

## Agent skill

`skills/unifi-axi/SKILL.md` is a discovery stub in [Agent Skills](https://agentskills.io) format. It sends agents to `unifi-axi --help` for current usage, so it does not go stale.

## Development

```sh
uv run --with pytest pytest -q
uvx ruff check .
```

Tests use synthetic fixtures only. `tests/test_pii.py` also greps the tree for real identifiers listed in a local, gitignored `.pii-denylist` (one term per line), and skips when that file is absent.

## License

MIT. See [LICENSE](LICENSE).

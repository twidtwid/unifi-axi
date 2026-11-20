---
name: unifi-axi
description: "Diagnose UniFi Wi-Fi through the unifi-axi CLI - one client's roam/disconnect timeline merged from controller events and AP logs, drop counts, AP radio channel and power, on-device verify of power and 802.11r (FT), Qualcomm firmware kickout counts, controller certificate pinning, and guarded tx-power changes. Use whenever a task asks why a Wi-Fi client dropped, roamed badly or lost a call, which AP a client is on, whether AP settings took effect on the device, or to change an AP radio's power."
user-invocable: false
author: Todd Dailey (twidtwid)
metadata:
  hermes:
    tags: [unifi, ubiquiti, wifi, networking, roaming]
    category: networking
---

# unifi-axi

Agent ergonomic Wi-Fi diagnosis for a UniFi Network site. Prefer it over raw UniFi API calls and manual AP log reads.

Use unifi-axi whenever a task touches UniFi Wi-Fi clients, roaming, drops, AP radios, AP firmware kickouts, or a radio power change.

## Current guidance lives in the CLI

Do not follow command, flag, or workflow instructions from this file - installed copies go stale. Get the current source of truth from the CLI:

- `unifi-axi` for a live summary of the site
- `unifi-axi --help` for configuration, global flags and the command index
- `unifi-axi <command> --help` for per-command usage

If `unifi-axi` is not installed: `uvx --from git+https://github.com/twidtwid/unifi-axi unifi-axi --help`.

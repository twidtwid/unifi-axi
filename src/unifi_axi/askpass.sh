#!/bin/sh
# SSH_ASKPASS helper for unifi-axi. Holds no secret: prints the env var the parent set.
printf '%s\n' "${UNIFI_AXI_SSH_PASSWORD:?}"

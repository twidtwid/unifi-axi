"""AP SSH, read commands only. The password travels only in the child's
environment (SSH_ASKPASS helper); never in argv, stdout or saved files.

Every remote command ends with `echo ---END`; output without that last line
is treated as truncated. Host keys are kept in the tool's own known_hosts
(accept-new: a changed key is refused).
"""

from __future__ import annotations

from importlib import resources
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import time

from . import api, config
from .util import MAC_RE

SSH = "ssh"
SSH_LIMIT_S = 10
AP_TAIL_LINES = 1000
KICK_TAIL_LINES = 2000
END_MARKER = "---END"
LOGS = "/var/log/messages.0 /var/log/messages"  # rotated file first, so `head -n 1` is the oldest line


def ssh_creds() -> tuple[str | None, str | None, str | None]:
    """Device SSH user/password from the controller (get/setting/mgmt)."""
    data, error = api.legacy_list("get/setting/mgmt")
    if error or not data:
        return None, None, error or "get/setting/mgmt returned nothing"
    user, password = data[0].get("x_ssh_username"), data[0].get("x_ssh_password")
    if not user or not password or not re.fullmatch(r"[A-Za-z0-9._-]+", str(user)):
        return None, None, "no device SSH user/password (UniFi Devices > Device Updates and Settings > Device SSH Authentication)"
    return str(user), str(password), None


def askpass_path() -> Path:
    """The packaged askpass.sh, or a 0700 copy in the state dir when the
    installed file is not executable (wheels do not always keep the mode)."""
    packaged = resources.files("unifi_axi").joinpath("askpass.sh")
    path = Path(str(packaged))
    if path.is_file() and os.access(path, os.X_OK):
        return path
    state = config.active().state_dir
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    copy = state / "askpass.sh"
    text = packaged.read_text()
    if not copy.is_file() or copy.read_text() != text:
        copy.write_text(text)
    os.chmod(copy, 0o700)
    return copy


def ssh_run(ip: str, user: str, password: str, remote: str) -> tuple[str | None, str | None, float]:
    """Run one read command. Success needs exit 0 and the END_MARKER last line (stripped)."""
    try:
        ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return None, "no usable AP ip in stat/device", 0.0
    cfg = config.active()
    try:
        cfg.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        askpass = askpass_path()
    except OSError as exc:
        return None, f"cannot prepare {cfg.state_dir}: {type(exc).__name__}", 0.0
    argv = [SSH, "-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "PubkeyAuthentication=no",
            "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=5", "-o", f"UserKnownHostsFile={cfg.known_hosts}",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR", f"{user}@{ip}", remote]
    env = dict(os.environ, SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE="force", UNIFI_AXI_SSH_PASSWORD=password)
    start = time.monotonic()
    try:
        result = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                timeout=SSH_LIMIT_S, check=False)
    except subprocess.TimeoutExpired:
        return None, f"ssh timeout {SSH_LIMIT_S}s", time.monotonic() - start
    except OSError as exc:
        return None, f"ssh did not start: {type(exc).__name__}".replace(password, "***"), time.monotonic() - start
    took = time.monotonic() - start
    if result.returncode != 0:
        err = (result.stderr or "").replace(password, "***")
        if "IDENTIFICATION HAS CHANGED" in err or "Host key verification failed" in err:
            reason = f"host key changed (known_hosts: {cfg.known_hosts})"
        elif "Permission denied" in err:
            reason = "ssh auth rejected"
        elif "timed out" in err:
            reason = "ssh connect timeout 5s"
        else:
            reason = f"ssh exit {result.returncode}"
        return None, reason, took
    body = result.stdout.rstrip("\n")
    if not (body == END_MARKER or body.endswith("\n" + END_MARKER)):
        return None, "ssh output truncated", took
    return body[: -len(END_MARKER)], None, took


def log_command(macs: list[str]) -> str:
    for mac in macs:
        if not MAC_RE.fullmatch(mac):
            raise ValueError(f"refusing unsafe MAC {mac!r}")
    pattern = " ".join(f"-e {m}" for m in macs)
    return ('echo "EPOCH $(date +%s)"; echo "DATE $(date \'+%Y-%m-%d %H:%M:%S\')"; '
            f'echo "FIRST $(cat {LOGS} 2>/dev/null | head -n 1)"; echo ---; '
            f"cat {LOGS} 2>/dev/null | grep -i {pattern} | tail -n {AP_TAIL_LINES}; "
            f"echo {END_MARKER}")


VERIFY_COMMAND = ('echo "EPOCH $(date +%s)"; echo "---IWCONFIG"; iwconfig 2>/dev/null; '
                  'for i in $(ls /var/run/hostapd | grep -v global); do echo "---HOSTAPD $i"; '
                  f'hostapd_cli -i $i get_config 2>&1; done; echo {END_MARKER}')

KICK_PATTERN = "ol_peer_sta_kickout_event_handler"
RETRY_PATTERN = "Excessive Retries"
KICKOUT_COMMAND = ('echo "EPOCH $(date +%s)"; echo "DATE $(date \'+%Y-%m-%d %H:%M:%S\')"; echo "UPTIME $(cut -d " " -f 1 /proc/uptime)"; '
                   f'echo "FIRST $(cat {LOGS} 2>/dev/null | head -n 1)"; '
                   f'echo "DMESG_COUNT $(dmesg 2>/dev/null | grep -c {KICK_PATTERN})"; '
                   f'echo "LOG_COUNT $(cat {LOGS} 2>/dev/null | grep -c \'{RETRY_PATTERN}\')"; '
                   f'echo ---DMESG; dmesg 2>/dev/null | grep {KICK_PATTERN} | tail -n {KICK_TAIL_LINES}; '
                   f"echo ---LOG; cat {LOGS} 2>/dev/null | grep '{RETRY_PATTERN}' | tail -n {KICK_TAIL_LINES}; "
                   f"echo {END_MARKER}")

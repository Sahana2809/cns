"""Wi-Fi access-point discovery module (SHADOW Wi-Fi, Part 1).

Scans nearby Wi-Fi networks and normalizes OS-specific tool output into a
single AP record schema shared with detector.py:

    {"ssid": str, "bssid": str, "channel": int, "signal": int,
     "security": str, "ts": iso-8601 str}

Supported OSes: Windows (netsh), Linux (nmcli). A best-effort macOS parser
is included for local development, but note macOS hides real BSSIDs from
system_profiler without special location entitlements, so mac scans fall
back to a placeholder BSSID and are not suitable for the BSSID-based rogue
checks in detector.py.
"""

import platform
import re
import subprocess
from datetime import datetime, timezone


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _to_int(value):
    try:
        return int(re.sub(r"[^\d-]", "", value))
    except (TypeError, ValueError):
        return 0


def _normalize_security(raw):
    raw = (raw or "").upper()
    if "WPA3" in raw:
        return "WPA3"
    if "WPA2" in raw:
        return "WPA2"
    if "WPA" in raw:
        return "WPA"
    if "WEP" in raw:
        return "WEP"
    if not raw or raw in ("--", "NONE", "OPEN"):
        return "Open"
    return raw


def _run_command(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=15, check=False)
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _split_nmcli_line(line):
    # nmcli terse mode escapes literal ':' inside a field as '\:' and uses
    # unescaped ':' as the field separator.
    fields = re.split(r"(?<!\\):", line)
    return [f.replace("\\:", ":") for f in fields]


def parse_nmcli_output(output):
    """Parse `nmcli -t -f SSID,BSSID,CHAN,SIGNAL,SECURITY device wifi list` output."""
    aps = []
    for line in output.strip().splitlines():
        if not line:
            continue
        fields = _split_nmcli_line(line)
        if len(fields) < 5:
            continue
        ssid, bssid, channel, signal, security = fields[:5]
        if not ssid or not bssid:
            continue
        aps.append({
            "ssid": ssid,
            "bssid": bssid.upper(),
            "channel": _to_int(channel),
            "signal": _to_int(signal),
            "security": _normalize_security(security),
            "ts": _now_iso(),
        })
    return aps


_SSID_RE = re.compile(r"^SSID\s+\d+\s*:\s*(.*)$", re.MULTILINE)
_AUTH_RE = re.compile(r"^\s*Authentication\s*:\s*(.*)$", re.MULTILINE)
_BSSID_RE = re.compile(r"^\s*BSSID\s+\d+\s*:\s*(.*)$", re.MULTILINE)
_SIGNAL_RE = re.compile(r"^\s*Signal\s*:\s*(\d+)%", re.MULTILINE)
_CHANNEL_RE = re.compile(r"^\s*Channel\s*:\s*(\d+)", re.MULTILINE)


def parse_netsh_output(output):
    """Parse `netsh wlan show networks mode=bssid` output.

    Each SSID block can contain multiple BSSID sub-blocks (one AP name,
    several physical radios/APs) — one record is emitted per BSSID.
    """
    aps = []
    ssid_blocks = re.split(r"\n(?=SSID \d+\s*:)", output)
    for block in ssid_blocks:
        ssid_match = _SSID_RE.search(block)
        if not ssid_match:
            continue
        ssid = ssid_match.group(1).strip()
        if not ssid:
            continue
        auth_match = _AUTH_RE.search(block)
        security = _normalize_security(auth_match.group(1)) if auth_match else "Open"

        bssid_blocks = re.split(r"\n(?=\s*BSSID \d+\s*:)", block)
        for sub in bssid_blocks[1:]:
            bssid_match = _BSSID_RE.search(sub)
            if not bssid_match:
                continue
            bssid = bssid_match.group(1).strip()
            if not bssid:
                continue
            signal_match = _SIGNAL_RE.search(sub)
            channel_match = _CHANNEL_RE.search(sub)
            aps.append({
                "ssid": ssid,
                "bssid": bssid.upper(),
                "channel": int(channel_match.group(1)) if channel_match else 0,
                "signal": int(signal_match.group(1)) if signal_match else 0,
                "security": security,
                "ts": _now_iso(),
            })
    return aps


_MAC_NETWORK_NAME_RE = re.compile(r"^(\s*)([^\s].*):\s*$")
_MAC_SKIP_NAMES = {"other local wi-fi networks", "current network information", "interfaces", "spairport_wireless_card_type_wifi"}


def parse_macos_output(output):
    """Best-effort parse of `system_profiler SPAirPortDataType` text output.

    macOS does not expose real BSSIDs for nearby networks without location
    entitlements, so bssid is a synthetic placeholder here. Treat mac scans
    as useful only for SSID/channel/security/signal checks, not BSSID checks.

    Networks are listed as same-indent-level blocks under "Other Local
    Wi-Fi Networks:"; each block's own lines are indented one level deeper.
    """
    aps = []
    lines = output.splitlines()

    network_starts = []
    for i, line in enumerate(lines):
        match = _MAC_NETWORK_NAME_RE.match(line)
        if not match:
            continue
        name = match.group(2).strip()
        if name.lower() in _MAC_SKIP_NAMES:
            continue
        indent = len(match.group(1))
        network_starts.append((i, indent, name))

    # A network block's header has a deeper indent than section headers like
    # "Other Local Wi-Fi Networks:" — keep only the deepest, most common
    # indent level, which corresponds to individual network names.
    if not network_starts:
        return aps
    indents = [indent for _, indent, _ in network_starts]
    network_indent = max(indents)
    networks = [(i, name) for i, indent, name in network_starts if indent == network_indent]

    for idx, (start, ssid) in enumerate(networks):
        end = networks[idx + 1][0] if idx + 1 < len(networks) else len(lines)
        block = "\n".join(lines[start:end])
        channel_match = re.search(r"Channel:\s*(\d+)", block)
        security_match = re.search(r"Security:\s*([^\n]*)", block)
        signal_match = re.search(r"Signal\s*/\s*Noise:\s*(-?\d+)", block)
        aps.append({
            "ssid": ssid,
            "bssid": f"UNKNOWN-MAC-{idx}",
            "channel": _to_int(channel_match.group(1)) if channel_match else 0,
            "signal": _to_int(signal_match.group(1)) if signal_match else 0,
            "security": _normalize_security(security_match.group(1)) if security_match else "Open",
            "ts": _now_iso(),
        })
    return aps


def scan():
    """Scan nearby Wi-Fi APs on the current OS and return normalized records.

    Returns an empty list (and does not raise) if the platform's Wi-Fi
    command is unavailable or the scan otherwise fails — callers should log
    that condition rather than crash the pipeline.
    """
    system = platform.system()
    if system == "Windows":
        output = _run_command(["netsh", "wlan", "show", "networks", "mode=bssid"])
        return parse_netsh_output(output)
    if system == "Linux":
        output = _run_command(["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "device", "wifi", "list"])
        return parse_nmcli_output(output)
    if system == "Darwin":
        output = _run_command(["system_profiler", "SPAirPortDataType"])
        return parse_macos_output(output)
    return []

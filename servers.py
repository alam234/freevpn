"""Fetch and parse the free public server list published by VPN Gate.

VPN Gate (https://www.vpngate.net) is an academic project run by the
University of Tsukuba. Volunteers run the servers, and the project publishes
the list as CSV with each server's OpenVPN config embedded as base64.
"""

from __future__ import annotations

import base64
import csv
import io
import re
import urllib.request
from dataclasses import dataclass, field

API_URL = "https://www.vpngate.net/api/iphone/"
USER_AGENT = "FreeVPN-Desktop/1.0"

# Directives that run programs, load DLLs or write files. Configs come from
# volunteers, so these are stripped before handing the file to OpenVPN.
_BLOCKED_DIRECTIVES = {
    "up", "down", "route-up", "route-pre-down", "ipchange", "tls-verify",
    "client-connect", "client-disconnect", "learn-address",
    "auth-user-pass-verify", "script-security", "plugin", "setenv",
    "setenv-safe", "cd", "chroot", "log", "log-append", "status",
    "writepid", "management", "management-client", "daemon", "config",
    "tmp-dir", "dhcp-option",  # dhcp-option re-added deliberately below
}


@dataclass
class Server:
    hostname: str
    ip: str
    score: int
    ping: int
    speed_bps: int
    country: str
    country_code: str
    sessions: int
    uptime_ms: int
    total_users: int
    operator: str
    log_policy: str
    config_b64: str = field(repr=False)

    @property
    def speed_mbps(self) -> float:
        return self.speed_bps / 1_000_000

    @property
    def uptime_days(self) -> float:
        return self.uptime_ms / 86_400_000

    @property
    def protocol(self) -> str:
        m = re.search(r"^\s*proto\s+(\w+)", self.config_text, re.M)
        return m.group(1).upper() if m else "?"

    @property
    def port(self) -> str:
        m = re.search(r"^\s*remote\s+\S+\s+(\d+)", self.config_text, re.M)
        return m.group(1) if m else "?"

    @property
    def config_text(self) -> str:
        try:
            return base64.b64decode(self.config_b64).decode("utf-8", "replace")
        except (ValueError, TypeError):
            return ""


def _int(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def parse(raw: str) -> list[Server]:
    """Parse VPN Gate's CSV. Line 1 is '*vpn_servers', line 2 is the header
    (prefixed with '#'), and the list ends with a lone '*'."""
    lines = [ln for ln in raw.splitlines() if ln and not ln.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    servers: list[Server] = []
    for row in csv.DictReader(io.StringIO("\n".join(lines))):
        cfg = row.get("OpenVPN_ConfigData_Base64") or ""
        ip = row.get("IP") or ""
        if not cfg or not ip:
            continue
        servers.append(Server(
            hostname=row.get("HostName", ""),
            ip=ip,
            score=_int(row.get("Score")),
            ping=_int(row.get("Ping")),
            speed_bps=_int(row.get("Speed")),
            # e.g. "Croatia (LOCAL Name: Hrvatska)" -> "Croatia"
            country=re.sub(r"\s*\(LOCAL Name:.*", "", row.get("CountryLong", "")) or "Unknown",
            country_code=row.get("CountryShort", ""),
            sessions=_int(row.get("NumVpnSessions")),
            uptime_ms=_int(row.get("Uptime")),
            total_users=_int(row.get("TotalUsers")),
            operator=row.get("Operator", ""),
            log_policy=row.get("LogType", ""),
            config_b64=cfg,
        ))
    servers.sort(key=lambda s: s.score, reverse=True)
    return servers


def fetch_raw(timeout: float = 25.0) -> str:
    req = urllib.request.Request(API_URL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def fetch(timeout: float = 25.0) -> list[Server]:
    return parse(fetch_raw(timeout))


def sanitize_config(text: str, legacy_compat: bool = True) -> str:
    """Drop dangerous directives and append settings modern OpenVPN (2.5+/2.6)
    needs to talk to VPN Gate's mostly AES-128-CBC servers."""
    out: list[str] = []
    in_inline = None
    for line in text.splitlines():
        stripped = line.strip()
        if in_inline:
            out.append(line)
            if stripped.lower() == f"</{in_inline}>":
                in_inline = None
            continue
        m = re.match(r"<([\w-]+)>$", stripped)
        if m:
            in_inline = m.group(1).lower()
            out.append(line)
            continue
        if not stripped or stripped[0] in "#;":
            continue
        directive = stripped.split()[0].lower()
        if directive in _BLOCKED_DIRECTIVES:
            continue
        out.append(line)

    out += [
        "",
        "# --- added by FreeVPN ---",
        "script-security 1",
        "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC:AES-256-CBC",
        "data-ciphers-fallback AES-128-CBC",
        "block-outside-dns",
        # VPN Gate is IPv4-only; answer any IPv6 that reaches the tunnel with
        # "unreachable" so apps fall back to IPv4 at once instead of hanging.
        "block-ipv6",
        "dhcp-option DNS 1.1.1.1",
        "dhcp-option DNS 8.8.8.8",
        "connect-retry-max 5",
        # If the server drops us (e.g. Windows stalls during adapter setup
        # longer than the server's 10s keepalive) it may briefly refuse the
        # reconnect while the old session lingers; retry instead of quitting.
        "auth-retry nointeract",
        "verb 3",
    ]
    if legacy_compat:
        # Many volunteer servers still use 1024-bit RSA keys / SHA1 certs that
        # OpenSSL 3 rejects at its default security level.
        out.append("tls-cipher DEFAULT:@SECLEVEL=0")
    return "\n".join(out) + "\n"

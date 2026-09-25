"""Optional DHCP lease integration (authoritative client-reported hostnames).

A DHCP server records the hostname each client reports in its own DHCP request,
which is far more trustworthy than reverse DNS or NetBIOS. This reads that
lease data from a locally accessible ISC dhcpd leases file or a Windows DHCP
server CSV/JSON export, and can also query an HTTP JSON API when configured.

Everything here is optional and config-gated (`DHCP_LEASE_ENABLED`); when no
source is reachable the function simply returns no observations, and the
scanner keeps its existing behaviour.
"""
from __future__ import annotations

import csv
import io
import json
import re
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import settings

# ISC dhcpd.leases: "lease 192.168.1.20 { ... client-hostname "laptop-01"; ... }"
_ISC_LEASE_RE = re.compile(r"lease\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s*\{(?P<body>.*?)\}", re.DOTALL)
_ISC_HOSTNAME_RE = re.compile(r'client-hostname\s+"(?P<name>[^"]+)"')
_ISC_STARTS_RE = re.compile(r"starts\s+\d+\s+(?P<stamp>[0-9/]+\s+[0-9:]+)")
_ISC_ENDS_RE = re.compile(r"ends\s+\d+\s+(?P<stamp>[0-9/]+\s+[0-9:]+)")
_ISC_ABANDONED_RE = re.compile(r"binding\s+state\s+abandoned")


def _parse_isc_time(stamp: str | None) -> datetime | None:
    if not stamp:
        return None
    normalized = stamp.replace("/", "-", 2)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(normalized, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def parse_isc_leases(text: str) -> dict[str, dict]:
    """Return {ip: {hostname, active, ends}} from an ISC dhcpd.leases file."""
    leases: dict[str, dict] = {}
    for match in _ISC_LEASE_RE.finditer(text):
        ip = match.group("ip")
        body = match.group("body")
        hostname_match = _ISC_HOSTNAME_RE.search(body)
        if not hostname_match:
            continue
        ends = _parse_isc_time((_ISC_ENDS_RE.search(body) or [None, None])[1] if _ISC_ENDS_RE.search(body) else None)
        abandoned = bool(_ISC_ABANDONED_RE.search(body))
        leases[ip] = {
            "hostname": hostname_match.group("name").strip(),
            "active": not abandoned,
            "ends": ends,
        }
    return leases


def parse_windows_leases(text: str) -> dict[str, dict]:
    """Parse a Windows DHCP server export (CSV or JSON).

    Accepts a CSV with an IP/Address column and a Name/HostName column, or a
    JSON list of {"ip"/"address", "name"/"hostname"} objects.
    """
    stripped = text.lstrip()
    leases: dict[str, dict] = {}
    if stripped.startswith(("[", "{")):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return {}
        rows = payload if isinstance(payload, list) else payload.get("leases", []) or payload.get("data", [])
        for row in rows:
            if not isinstance(row, dict):
                continue
            lowered = {str(k).strip().lower(): v for k, v in row.items()}
            ip = str(lowered.get("ip") or lowered.get("address") or "").strip()
            name = str(lowered.get("name") or lowered.get("hostname") or "").strip()
            if ip and name and name != ip:
                leases[ip] = {"hostname": name, "active": True, "ends": None}
        return leases

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return {}
    header = {name.strip().lower(): name for name in reader.fieldnames}
    ip_key = next((header[key] for key in ("ip", "address", "ipaddress", "ip address") if key in header), None)
    name_key = next((header[key] for key in ("name", "hostname", "host name", "clientname") if key in header), None)
    if not ip_key or not name_key:
        return {}
    for row in reader:
        ip = (row.get(ip_key) or "").strip()
        name = (row.get(name_key) or "").strip()
        if ip and name and name != ip:
            leases[ip] = {"hostname": name, "active": True, "ends": None}
    return leases


def _read_lease_source() -> dict[str, dict]:
    path = settings.dhcp_lease_path
    if not path:
        return {}
    candidate = Path(path)
    if not candidate.exists():
        return {}
    try:
        text = candidate.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    if settings.dhcp_lease_format.lower() == "windows":
        return parse_windows_leases(text)
    return parse_isc_leases(text)


def _query_lease_api() -> dict[str, dict]:
    if not settings.dhcp_api_url:
        return {}
    headers = {"Accept": "application/json", "User-Agent": "SecureOps-Prototype/1.0"}
    if settings.dhcp_api_token:
        headers["Authorization"] = f"Bearer {settings.dhcp_api_token}"
    try:
        request = urllib.request.Request(settings.dhcp_api_url, headers=headers)
        with urllib.request.urlopen(request, timeout=settings.dhcp_request_timeout_seconds) as response:
            text = response.read().decode("utf-8", errors="replace")
    except Exception:
        return {}
    return parse_windows_leases(text)


def collect_leases() -> dict[str, dict]:
    """Return {ip: {hostname, active, ends}} from every configured DHCP source.

    Never raises - a missing or unreachable DHCP server just yields no data so
    the scan continues with its other sources.
    """
    if not settings.dhcp_lease_enabled:
        return {}
    leases = _read_lease_source()
    leases.update(_query_lease_api())
    return {ip: entry for ip, entry in leases.items() if entry.get("hostname")}
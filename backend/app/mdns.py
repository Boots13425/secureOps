"""mDNS (.local) hostname resolution (Layer 1 accuracy).

Apple devices, many IoT devices, and other non-Windows hosts advertise a
friendly name via multicast DNS but never appear in reverse DNS or NetBIOS.
This sends a minimal mDNS PTR query for the host's reverse address
(<reversed-ip>.in-addr.arpa) to the 224.0.0.251:5353 multicast group and reads
the first PTR answer. Stdlib only - no external dependency.

Config-gated by MDNS_ENABLED; a device that doesn't answer simply yields None
and the scanner falls back to its other sources.
"""
from __future__ import annotations

import ipaddress
import socket
import struct

from .config import settings

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
_PTR_TYPE = 12
_IN_CLASS = 1


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("utf-8")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def build_ptr_query(ip_address: str) -> bytes:
    """Build a minimal mDNS PTR query packet for a reverse-lookup name."""
    reversed_ip = ".".join(reversed(ip_address.split(".")))
    qname = f"{reversed_ip}.in-addr.arpa"
    # Header: id=0, flags=0 (query), qdcount=1, others 0.
    packet = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    packet += _encode_name(qname)
    packet += struct.pack(">HH", _PTR_TYPE, _IN_CLASS)
    return packet


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read a (possibly compressed) DNS name starting at offset."""
    labels: list[str] = []
    jumped = False
    end_offset = offset
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end_offset = offset
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length
        if not jumped:
            end_offset = offset
    return ".".join(labels), end_offset


def parse_ptr_answer(data: bytes) -> str | None:
    """Extract the first PTR target (a .local name) from an mDNS response."""
    try:
        _, _, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    except struct.error:
        return None
    offset = 12
    for _ in range(qdcount):
        _, offset = _read_name(data, offset)
        offset += 4  # qtype + qclass
    for _ in range(ancount):
        _, offset = _read_name(data, offset)
        rtype, _, _, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if rtype == _PTR_TYPE:
            name, _ = _read_name(data, offset)
            return name.rstrip(".")
        offset += rdlength
    return None


def resolve_hostname(ip_address: str, timeout: float | None = None) -> str | None:
    """Return the mDNS-advertised .local name for an IP, or None.

    Never raises - any socket/parse failure just means "no mDNS name".
    """
    if not settings.mdns_enabled:
        return None
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return None
    timeout = timeout if timeout is not None else settings.mdns_timeout_seconds
    query = build_ptr_query(ip_address)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        try:
            sock.bind(("", 0))
        except OSError:
            pass
        sock.sendto(query, (MDNS_GROUP, MDNS_PORT))
        # Read a few datagrams; the first PTR answer wins.
        for _ in range(4):
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                break
            name = parse_ptr_answer(data)
            if name:
                return name
        return None
    except OSError:
        return None
    finally:
        sock.close()
"""Minimal SNMP v2c client (Layer 1 accuracy) - stdlib only, no dependency.

SNMP is authoritative and vendor-supplied: sysDescr/sysName/sysObjectID come
straight from the agent, and router/switch ARP tables expose MAC-to-IP bindings
for cross-segment hosts the scanner has no direct Layer-2 presence on.

Config-gated by SNMP_ENABLED; failures yield {} so the scan continues.
"""
from __future__ import annotations

import socket

from .config import settings
from .identification import classify_device, enterprise_vendor, parse_sysdescr

SNMP_PORT = 161

SYS_DESCR = (1, 3, 6, 1, 2, 1, 1, 1, 0)
SYS_OBJECT_ID = (1, 3, 6, 1, 2, 1, 1, 2, 0)
SYS_NAME = (1, 3, 6, 1, 2, 1, 1, 5, 0)
# sysServices: which layers (physical/internet/datalink/internetworking/
# end-to-end) the device offers services at - routers and switches report
# distinct combinations, so it separates infrastructure from servers.
SYS_SERVICES = (1, 3, 6, 1, 2, 1, 1, 7, 0)
# ipNetToMediaPhysAddress: 1.3.6.1.2.1.4.22.1.2.<ifIndex>.<ip4>
IPNETTOMEDIA_PHYS = (1, 3, 6, 1, 2, 1, 4, 22, 1, 2)


# --- BER Encoding ---------------------------------------------------------
def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _len(len(val)) + val


def _enc_int(val: int) -> bytes:
    b = val.to_bytes((val.bit_length() + 8) // 8, "big") if val else b"\x00"
    return _tlv(0x02, b)


def _enc_oid(oid: tuple[int, ...]) -> bytes:
    body = bytearray([oid[0] * 40 + oid[1]])
    for sub in oid[2:]:
        if sub == 0:
            body.append(0)
            continue
        parts = []
        while sub:
            parts.append(sub & 0x7F)
            sub >>= 7
        for i, p in enumerate(reversed(parts)):
            body.append(p | (0x80 if i < len(parts) - 1 else 0))
    return _tlv(0x06, bytes(body))


def _enc_seq(val: bytes, tag: int = 0x30) -> bytes:
    return _tlv(tag, val)


def build_request(community: str, oids: list[tuple[int, ...]], pdu_tag: int = 0xA0) -> bytes:
    vbs = b"".join(_enc_seq(_enc_oid(o) + b"\x05\x00") for o in oids)
    pdu = _enc_seq(_enc_int(1) + _enc_int(0) + _enc_int(0) + _enc_seq(vbs), tag=pdu_tag)
    return _enc_seq(_enc_int(1) + _tlv(0x04, community.encode()) + pdu)


# --- BER Decoding ---------------------------------------------------------
def _read_tlv(data: bytes, off: int) -> tuple[int, bytes, int]:
    tag, length, off = data[off], data[off + 1], off + 2
    if length & 0x80:
        cnt = length & 0x7F
        length = int.from_bytes(data[off:off + cnt], "big")
        off += cnt
    return tag, data[off:off + length], off + length


def _dec_oid(val: bytes) -> tuple[int, ...]:
    if not val:
        return ()
    oid = [val[0] // 40, val[0] % 40]
    sub = 0
    for b in val[1:]:
        sub = (sub << 7) | (b & 0x7F)
        if not b & 0x80:
            oid.append(sub)
            sub = 0
    return tuple(oid)


def parse_response(data: bytes) -> dict[tuple[int, ...], tuple[int, bytes]]:
    result: dict[tuple[int, ...], tuple[int, bytes]] = {}
    try:
        _, msg, _ = _read_tlv(data, 0)
        _, _, off = _read_tlv(msg, 0)       # version
        _, _, off = _read_tlv(msg, off)     # community
        pdu_tag, pdu, _ = _read_tlv(msg, off)
        if pdu_tag not in (0xA2, 0xA0, 0xA1):
            return result
        _, _, off = _read_tlv(pdu, 0)       # req id
        _, _, off = _read_tlv(pdu, off)     # err status
        _, _, off = _read_tlv(pdu, off)     # err idx
        _, vbs, _ = _read_tlv(pdu, off)     # varbinds
        off = 0
        while off < len(vbs):
            _, vb, off = _read_tlv(vbs, off)
            _, oid_raw, voff = _read_tlv(vb, 0)
            vtag, vval, _ = _read_tlv(vb, voff)
            result[_dec_oid(oid_raw)] = (vtag, vval)
    except (IndexError, ValueError):
        pass
    return result


def _exchange(ip: str, packet: bytes, timeout: float) -> bytes | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, SNMP_PORT))
        data, _ = sock.recvfrom(65535)
        return data
    except OSError:
        return None
    finally:
        sock.close()


def collect_identity(ip: str, community: str | None = None, timeout: float | None = None) -> dict:
    """Query sysDescr, sysName, sysObjectID, sysServices and derive fields."""
    if not settings.snmp_enabled:
        return {}
    community = community or settings.snmp_community
    timeout = timeout if timeout is not None else settings.snmp_timeout_seconds
    pkt = build_request(community, [SYS_DESCR, SYS_OBJECT_ID, SYS_NAME, SYS_SERVICES])
    raw = _exchange(ip, pkt, timeout)
    if not raw:
        return {}
    res = parse_response(raw)
    sys_descr = res.get(SYS_DESCR, (None, b""))[1].decode("utf-8", errors="replace").strip() or None
    raw_oid = res.get(SYS_OBJECT_ID, (None, b""))[1]
    sys_oid = ".".join(map(str, _dec_oid(raw_oid))) if raw_oid else None
    sys_name = res.get(SYS_NAME, (None, b""))[1].decode("utf-8", errors="replace").strip() or None
    sys_services = None
    services_tag, services_bytes = res.get(SYS_SERVICES, (None, b""))
    if services_tag == 0x02 and services_bytes:
        sys_services = int.from_bytes(services_bytes, "big")

    vendor = enterprise_vendor(sys_oid)
    os_family = parse_sysdescr(sys_descr)
    # The SNMP agent's own OS string is authoritative, so it decides the device
    # type here; sysServices only breaks a router/switch tie.
    device_type = classify_device(
        os_family=os_family, sys_descr=sys_descr, sys_name=sys_name,
        vendor=vendor, sys_services=sys_services,
    ).device_type
    return {
        "sys_descr": sys_descr,
        "sys_object_id": sys_oid,
        "sys_name": sys_name,
        "sys_services": sys_services,
        "vendor": vendor,
        "os_family": os_family,
        "device_type": device_type,
    }


def collect_arp_table(router_ip: str, community: str | None = None, timeout: float | None = None, max_entries: int = 512) -> dict[str, str]:
    """Walk ipNetToMediaPhysAddress on a router/switch. Returns {ip: mac}."""
    if not settings.snmp_enabled or not settings.snmp_arp_table_enabled:
        return {}
    community = community or settings.snmp_community
    timeout = timeout if timeout is not None else settings.snmp_timeout_seconds
    base = IPNETTOMEDIA_PHYS
    current = base
    arp: dict[str, str] = {}
    for _ in range(max_entries):
        pkt = build_request(community, [current], pdu_tag=0xA1)
        raw = _exchange(router_ip, pkt, timeout)
        if not raw:
            break
        res = parse_response(raw)
        if not res:
            break
        oid, (tag, val) = next(iter(res.items()))
        if oid[:len(base)] != base:
            break
        # OID suffix: .<ifIndex>.<ip_b1>.<ip_b2>.<ip_b3>.<ip_b4>
        if len(oid) >= len(base) + 5 and len(val) == 6:
            ip = ".".join(map(str, oid[-4:]))
            mac = ":".join(f"{b:02X}" for b in val)
            arp[ip] = mac
        current = oid
    return arp
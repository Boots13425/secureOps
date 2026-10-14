"""Minimal SNMP v2c client (Layer 1 accuracy) - stdlib only, no dependency.

SNMP is authoritative and vendor-supplied: sysDescr/sysName/sysObjectID come
straight from the agent, and router/switch ARP tables expose MAC-to-IP bindings
for cross-segment hosts the scanner has no direct Layer-2 presence on.

Config-gated by SNMP_ENABLED; failures yield {} so the scan continues.

Every request here is a GET or a GETNEXT walk. The client has no SET path at
all, so read-only access is a structural property of this module rather than
something callers have to remember.
"""
from __future__ import annotations

import ipaddress
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

# --- Table roots used for cross-network discovery (read-only walks) ---------
# These are walked as full tables and grouped by index, not walked per column.
# Walking from a bare column OID is fragile: a typo lands you on an unrelated
# column (or outside the table entirely) and the walk silently returns nothing
# rather than erroring, which is how the previous IP-MIB OIDs below went
# unnoticed for so long.
#
# ipAddressTable 1.3.6.1.2.1.4.20.1.1 -> entry .1: ifIndex .2, reasmExpires .3,
# addr .4, netmask .5
IP_ADDRESS_TABLE = (1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 1)
COL_IPADDR_IF_INDEX = (2,)
COL_IPADDR_ADDR = (4,)
COL_IPADDR_NETMASK = (5,)
# The deprecated ipAddrTable is still the only one some older IOS images expose.
# ipAddrTable 1.3.6.1.2.1.4.7.1 -> entry .1: ifIndex .2, addr .3, mask .4
IP_ADDR_TABLE = (1, 3, 6, 1, 2, 1, 4, 7, 1, 1)
COL_IPADENT_IF_INDEX = (2,)
COL_IPADENT_ADDR = (3,)
COL_IPADENT_NETMASK = (4,)
# ipCidrRouteTable 1.3.6.1.2.1.4.24.7.1.7 -> entry .1: dest .3, mask .5,
# tos .6, nextHop .7, type .9
IP_CIDR_ROUTE_TABLE = (1, 3, 6, 1, 2, 1, 4, 24, 7, 1, 7, 1)
COL_ROUTE_DEST = (3,)
COL_ROUTE_MASK = (5,)
COL_ROUTE_NEXT_HOP = (7,)
COL_ROUTE_TYPE = (9,)
# Backwards-compatible aliases used elsewhere in the module.
IP_ADDRESS_IF_INDEX = IP_ADDRESS_TABLE
IP_ADDRESS_ADDR = COL_IPADDR_ADDR
IP_ADDRESS_NETMASK = COL_IPADDR_NETMASK
IP_AD_ENT_IF_INDEX = COL_IPADENT_IF_INDEX
IP_AD_ENT_ADDR = COL_IPADENT_ADDR
IP_AD_ENT_NETMASK = COL_IPADENT_NETMASK
IP_CIDR_ROUTE_DEST = COL_ROUTE_DEST
IP_CIDR_ROUTE_MASK = COL_ROUTE_MASK
IP_NET_TO_PHYSICAL_ADDRESS = (1, 3, 6, 1, 2, 1, 4, 35, 1, 4)
IP_NET_TO_PHYSICAL_LENGTH = (1, 3, 6, 1, 2, 1, 4, 35, 1, 6)
# Q-BRIDGE-MIB
DOT1Q_VLAN_CURRENT_NAME = (1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 2, 1, 5)
DOT1Q_TP_FDB_ADDRESS = (1, 3, 6, 1, 2, 1, 17, 4, 3, 2, 2, 1, 1)
DOT1Q_TP_FDB_PORT = (1, 3, 6, 1, 2, 1, 17, 4, 3, 2, 2, 1, 2)
# BRIDGE-MIB
DOT1D_TP_FDB_ADDRESS = (1, 3, 6, 1, 2, 1, 17, 2, 2, 2, 1, 2)
# LLDP-MIB and the Cisco CDP cache, for neighbour/topology context.
LLDP_REM_LOCAL_PORT = (1, 0, 8802, 1, 1, 2, 1, 3, 7, 1, 7)
LLDP_REM_CHASSIS_ID = (1, 0, 8802, 1, 1, 2, 1, 3, 7, 1, 4)
LLDP_REM_SYS_NAME = (1, 0, 8802, 1, 1, 2, 1, 3, 7, 1, 9)
CDP_CACHE_ADDRESS = (1, 3, 6, 1, 4, 1, 9, 9, 23, 1, 2, 2, 1, 3)
CDP_CACHE_DEVICE_ID = (1, 3, 6, 1, 4, 1, 9, 9, 23, 1, 2, 2, 1, 6)
CDP_CACHE_PLATFORM = (1, 3, 6, 1, 4, 1, 9, 9, 23, 1, 2, 2, 1, 8)

# SNMP application types (RFC 2578) as they appear in the BER tag of a varbind.
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_IP_ADDRESS = 0x40

# A walk is bounded so a device that keeps answering GETNEXT with a bogus OID
# (or a loop in its agent) cannot stall discovery.
DEFAULT_MAX_ENTRIES = 512


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


def walk_table(base: tuple[int, ...], ip: str, community: str, timeout: float,
               max_entries: int = DEFAULT_MAX_ENTRIES) -> list[tuple[tuple[int, ...], int, bytes]]:
    """GETNEXT-walk `base` on `ip` and return [(oid_suffix, tag, value)].

    The walk ends when the agent returns an OID outside the subtree, which is
    the normal end-of-MIB signal, or when `max_entries` is reached. Repeating
    an OID is also treated as the end: an agent that answers GETNEXT with the
    OID just asked for would otherwise loop forever.
    """
    current = base
    rows: list[tuple[tuple[int, ...], int, bytes]] = []
    for _ in range(max_entries):
        raw = _exchange(ip, build_request(community, [current], pdu_tag=0xA1), timeout)
        if not raw:
            break
        response = parse_response(raw)
        if not response:
            break
        oid, (tag, value) = next(iter(response.items()))
        if oid[:len(base)] != base:
            break
        if any(existing[0] == oid for existing in rows):
            break
        rows.append((oid[len(base):], tag, value))
        current = oid
    return rows


def walk_columns(entry_oid: tuple[int, ...], columns: dict[tuple[int, ...], str],
                 ip: str, community: str, timeout: float,
                 max_entries: int = DEFAULT_MAX_ENTRIES) -> list[dict]:
    """Walk one table and group every column onto its row index.

    `entry_oid` is the entry OID (not the table root), e.g. ipCidrRouteEntry.
    `columns` maps a column's sub-identifier tuple to a name. Walking the whole
    entry once and splitting on the leading column sub-id is what makes
    multi-column tables reliable here: the returned varbind OIDs are always
    `<entry_oid>.<column>.<index...>`, so grouping cannot drift the way a
    per-column walk does.

    Each row is `{name: (tag, value)}`, present only for columns the agent
    actually returned (agents legitimately omit columns).
    """
    rows: dict[tuple[int, ...], dict] = {}
    lookup = {tuple(col): name for col, name in columns.items()}
    for suffix, tag, value in walk_table(entry_oid, ip, community, timeout, max_entries):
        if not suffix:
            continue
        name = lookup.get(tuple(suffix[:1]))
        if name is None:
            continue
        index = suffix[1:]
        if not index:
            continue
        rows.setdefault(index, {})[name] = (tag, value)
    return list(rows.values())


def dec_int(tag: int, value: bytes) -> int | None:
    if tag != TAG_INTEGER or not value:
        return None
    return int.from_bytes(value, "big", signed=True)


def dec_string(tag: int, value: bytes) -> str | None:
    if tag not in (TAG_OCTET_STRING, TAG_IP_ADDRESS) or not value:
        return None
    return value.decode("utf-8", errors="replace").strip()


def dec_ipv4(tag: int, value: bytes) -> str | None:
    """An IpAddress varbind, or a 4-octet string used as one."""
    if tag == TAG_IP_ADDRESS and len(value) == 4:
        return ".".join(str(b) for b in value)
    if tag == TAG_OCTET_STRING and len(value) == 4:
        return ".".join(str(b) for b in value)
    return None


def dec_mac(value: bytes, length: int = 6) -> str | None:
    if not value:
        return None
    usable = value[:length] if 0 < length <= len(value) else value
    if len(usable) < 6:
        return None
    return ":".join(f"{b:02X}" for b in usable[:6])


def dec_oid(tag: int, value: bytes) -> str | None:
    if tag != TAG_OID or not value:
        return None
    return ".".join(map(str, _dec_oid(value)))


def reachable(ip: str, community: str | None = None, timeout: float | None = None) -> bool:
    """True when the agent answers at all, used to report per-device status."""
    if not settings.snmp_enabled:
        return False
    community = community or settings.snmp_community
    timeout = timeout if timeout is not None else settings.snmp_timeout_seconds
    return _exchange(ip, build_request(community, [SYS_DESCR]), timeout) is not None


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
    return collect_arp_entries(router_ip, community, timeout, max_entries)["legacy"]


def collect_arp_entries(router_ip: str, community: str | None = None, timeout: float | None = None,
                        max_entries: int = 512) -> dict[str, dict[str, str]]:
    """Every ARP view of a router, merged into {source_name: {ip: mac}}.

    Modern agents expose ipNetToPhysicalTable; older ones only
    ipNetToMediaPhysAddress. Both are read so a device is not silently
    reported as having an empty ARP table just because it is old.
    """
    empty = {"physical": {}, "legacy": {}}
    if not settings.snmp_enabled or not settings.snmp_arp_table_enabled:
        return empty
    community = community or settings.snmp_community
    timeout = timeout if timeout is not None else settings.snmp_timeout_seconds

    # ipNetToPhysicalPhysAddress is a fixed-width prefix of an octet string;
    # the real MAC length lives in a sibling column, so read both.
    lengths = {
        suffix: dec_int(tag, value)
        for suffix, tag, value in walk_table(IP_NET_TO_PHYSICAL_LENGTH, router_ip, community, timeout, max_entries)
    }
    physical: dict[str, str] = {}
    for suffix, tag, value in walk_table(IP_NET_TO_PHYSICAL_ADDRESS, router_ip, community, timeout, max_entries):
        # Index is <ifIndex>.<d1>.<d2>.<d3>.<d4>.<vlan>
        if len(suffix) < 5 or tag != TAG_OCTET_STRING:
            continue
        address = ".".join(map(str, suffix[-5:-1]))
        mac = dec_mac(value, lengths.get(suffix) or 6)
        if mac:
            physical.setdefault(address, mac)

    legacy: dict[str, str] = {}
    for suffix, tag, value in walk_table(IPNETTOMEDIA_PHYS, router_ip, community, timeout, max_entries):
        # Index is <ifIndex>.<d1>.<d2>.<d3>.<d4>
        if len(suffix) >= 5 and len(value) == 6:
            legacy.setdefault(".".join(map(str, suffix[-4:])), dec_mac(value) or "")

    return {"physical": physical, "legacy": legacy}


def collect_interface_addresses(device_ip: str, community: str | None = None, timeout: float | None = None) -> list[dict]:
    """Directly attached subnets from ipAddressTable, falling back to ipAddrTable.

    Each entry is {cidr, ip_address, if_index, source}. The netmask is applied
    to the address so the result is a real subnet rather than a host route.
    """
    if not settings.snmp_enabled:
        return []
    community = community or settings.snmp_community
    timeout = timeout if timeout is not None else settings.snmp_timeout_seconds

    specs = [
        (IP_ADDRESS_TABLE,
         {COL_IPADDR_IF_INDEX: "if_index", COL_IPADDR_ADDR: "addr", COL_IPADDR_NETMASK: "netmask"},
         "ipAddressTable"),
        (IP_ADDR_TABLE,
         {COL_IPADENT_IF_INDEX: "if_index", COL_IPADENT_ADDR: "addr", COL_IPADENT_NETMASK: "netmask"},
         "ipAddrTable"),
    ]
    results: list[dict] = []
    for entry_oid, columns, source in specs:
        for row in walk_columns(entry_oid, columns, device_ip, community, timeout):
            address_tag, address_bytes = row.get("addr", (None, b""))
            mask_tag, mask_bytes = row.get("netmask", (None, b""))
            address = dec_ipv4(address_tag, address_bytes)
            mask = dec_ipv4(mask_tag, mask_bytes)
            if not address or not mask:
                continue
            if_index = dec_int(*row["if_index"]) if "if_index" in row else None
            results.append({
                "cidr": _subnet_cidr(address, mask),
                "ip_address": address,
                "if_index": if_index,
                "source": source,
            })
        if results:
            break
    return results


def _subnet_cidr(address: str, mask: str) -> str:
    """Network address of address/mask, tolerating a host-style address."""
    try:
        return str(ipaddress.ip_network(f"{address}/{mask}", strict=False))
    except ValueError:
        return f"{address}/{mask}"


# ipCidrRouteType (IP-FORWARD-MIB): 3 is a directly attached network, 4 a
# static route, 1 "other" (typically learned from a routing protocol). 2/5/6
# are discard routes - a deliberate black hole, not a path to anything.
ROUTE_TYPE_DIRECT = 3
ROUTE_TYPE_UNUSABLE = frozenset({2, 5, 6})
ROUTE_TYPE_NAMES = {1: "other", 2: "reject", 3: "direct", 4: "static", 5: "nhs", 6: "dvrp"}

# INET-ADDRESS-MIB inetCidrRouteTable: newer agents carry IPv6 - and sometimes
# IPv4 - here instead of in ipCidrRouteTable. Dest and next hop are
# InetAddressType, a CHOICE of <2-byte tag><address>, not a bare IpAddress.
INET_CIDR_ROUTE_TABLE = (1, 3, 6, 1, 2, 1, 76, 4, 4, 1, 1, 1)
COL_INET_ROUTE_TYPE = (3,)
COL_INET_ROUTE_DEST = (4,)
COL_INET_ROUTE_PFX_LEN = (5,)
COL_INET_ROUTE_NEXT_HOP = (7,)
INET_ADDRESS_IPV4_TAG = 0x0002
INET_ADDRESS_IPV6_TAG = 0x0003


def dec_inet_address(tag: int, value: bytes) -> tuple[str, int] | None:
    """Decode an InetAddressType into (address, version), or None."""
    if tag != TAG_OCTET_STRING or len(value) < 3:
        return None
    choice = int.from_bytes(value[:2], "big")
    payload = value[2:]
    if choice == INET_ADDRESS_IPV4_TAG and len(payload) == 4:
        return ".".join(str(b) for b in payload), 4
    if choice == INET_ADDRESS_IPV6_TAG and len(payload) == 16:
        return str(ipaddress.IPv6Address(payload)), 6
    return None


def collect_routes(device_ip: str, community: str | None = None, timeout: float | None = None) -> list[dict]:
    """Every route in the device's tables, from both ipCidrRoute and inetCidrRoute.

    Each entry is {cidr, next_hop, route_type, route_kind, connected, learned,
    usable, source}. The distinction the multi-router traversal depends on:

      direct  - attached to this device's own interface (already the RoAS case)
      learned - reached via a next hop, i.e. the real path runs through another
                device. Static routes count as learned.
      unusable - a discard route (reject/nhs/dvrp); no path exists to build on.

    Both tables are read so a device is not reported as having no routes merely
    because it only populates the newer one.
    """
    if not settings.snmp_enabled:
        return []
    community = community or settings.snmp_community
    timeout = timeout if timeout is not None else settings.snmp_timeout_seconds

    results: list[dict] = []

    columns = {
        COL_ROUTE_DEST: "dest", COL_ROUTE_MASK: "mask",
        COL_ROUTE_NEXT_HOP: "next_hop", COL_ROUTE_TYPE: "route_type",
    }
    for row in walk_columns(IP_CIDR_ROUTE_TABLE, columns, device_ip, community, timeout):
        dest_tag, dest_bytes = row.get("dest", (None, b""))
        mask_tag, mask_bytes = row.get("mask", (None, b""))
        dest = dec_ipv4(dest_tag, dest_bytes)
        mask = dec_ipv4(mask_tag, mask_bytes)
        if not dest or not mask:
            continue
        next_hop_tag, next_hop_bytes = row.get("next_hop", (None, b""))
        next_hop = dec_ipv4(next_hop_tag, next_hop_bytes)
        route_type = dec_int(*row["route_type"]) if "route_type" in row else None
        results.append(_route_entry(_subnet_cidr(dest, mask), next_hop, route_type,
                                    "ipCidrRouteTable"))

    inet_columns = {
        COL_INET_ROUTE_TYPE: "route_type", COL_INET_ROUTE_DEST: "dest",
        COL_INET_ROUTE_PFX_LEN: "pfx_len", COL_INET_ROUTE_NEXT_HOP: "next_hop",
    }
    for row in walk_columns(INET_CIDR_ROUTE_TABLE, inet_columns, device_ip, community, timeout):
        dest = dec_inet_address(*row.get("dest", (None, b"")))
        if not dest or dest[1] != 4:
            # IPv6 routes are recorded but not traversed: the scan pipeline is
            # IPv4-only, so an IPv6 destination is not a scannable target.
            continue
        pfx_len = dec_int(*row["pfx_len"]) if "pfx_len" in row else None
        if pfx_len is None or not 0 <= pfx_len <= 32:
            continue
        next_hop = dec_inet_address(*row.get("next_hop", (None, b"")))
        route_type = dec_int(*row["route_type"]) if "route_type" in row else None
        results.append(_route_entry(f"{dest[0]}/{pfx_len}",
                                    next_hop[0] if next_hop else None,
                                    route_type, "inetCidrRouteTable"))

    return results


def _route_entry(cidr: str, next_hop: str | None, route_type: int | None, source: str) -> dict:
    connected = route_type == ROUTE_TYPE_DIRECT or next_hop in (None, "0.0.0.0", "::")
    usable = route_type is None or route_type not in ROUTE_TYPE_UNUSABLE
    return {
        "cidr": cidr,
        "next_hop": next_hop,
        "route_type": route_type,
        "route_kind": ROUTE_TYPE_NAMES.get(route_type, "unknown"),
        "connected": connected,
        # "Learned" means the path genuinely runs through another device, which
        # is what makes multi-router traversal worth doing.
        "learned": usable and not connected,
        "usable": usable,
        "source": source,
    }


def collect_vlans(device_ip: str, community: str | None = None, timeout: float | None = None) -> list[dict]:
    """dot1qVlanCurrentTable: [{vlan_id, name, source}]."""
    if not settings.snmp_enabled:
        return []
    community = community or settings.snmp_community
    timeout = timeout if timeout is not None else settings.snmp_timeout_seconds
    names = {
        dec_int(TAG_INTEGER, value) or (index[0] if index else None): value
        for index, tag, value in walk_table(DOT1Q_VLAN_CURRENT_NAME, device_ip, community, timeout)
    }
    vlans = []
    for vlan_id, value in names.items():
        if vlan_id is None:
            continue
        vlans.append({
            "vlan_id": vlan_id,
            "name": dec_string(TAG_OCTET_STRING, value) or None,
            "source": "dot1qVlanCurrentTable",
        })
    return vlans


def collect_fdb_ports(device_ip: str, community: str | None = None, timeout: float | None = None,
                      max_entries: int = DEFAULT_MAX_ENTRIES) -> dict[int, dict[str, int]]:
    """Forwarding-database MAC -> port ifIndex, per VLAN.

    This is the bridge between "VLAN 20 exists" and "VLAN 20 is 10.20.0.0/24":
    dot1qTpFdbPort gives the interface each learned MAC sits behind, and the
    interface's ipAddressTable entry gives that interface's subnet. Without the
    port column a VLAN can only be counted, never mapped to a subnet.
    """
    if not settings.snmp_enabled:
        return {}
    community = community or settings.snmp_community
    timeout = timeout if timeout is not None else settings.snmp_timeout_seconds

    addresses = {
        suffix: (tag, value) for suffix, tag, value in
        walk_table(DOT1Q_TP_FDB_ADDRESS, device_ip, community, timeout, max_entries)
    }
    ports = {
        suffix: (tag, value) for suffix, tag, value in
        walk_table(DOT1Q_TP_FDB_PORT, device_ip, community, timeout, max_entries)
    }
    by_vlan: dict[int, dict[str, int]] = {}
    for index, (tag, value) in addresses.items():
        # Index is <vlanId>.<mac 6 bytes>
        if len(index) < 7 or tag != TAG_OCTET_STRING:
            continue
        mac = dec_mac(value)
        if not mac:
            continue
        port_entry = ports.get(index)
        if not port_entry:
            continue
        if_index = dec_int(*port_entry)
        if if_index is None:
            continue
        by_vlan.setdefault(index[0], {})[mac] = if_index
    return by_vlan


def collect_fdb_entries(device_ip: str, community: str | None = None, timeout: float | None = None) -> dict[int, list[str]]:
    """Forwarding-database MACs per VLAN.

    Q-BRIDGE-MIB dot1qTpFdbTable indexes on <vlanId>.<mac> and is preferred;
    BRIDGE-MIB dot1dTpFdbTable is VLAN-agnostic and is used as a fallback (or
    per-VLAN via a "community@vlan" string, which `collect_fdb_entries_vlan`
    handles for the Cisco IOS agents that require it).
    """
    if not settings.snmp_enabled:
        return {}
    community = community or settings.snmp_community
    timeout = timeout if timeout is not None else settings.snmp_timeout_seconds

    by_vlan: dict[int, list[str]] = {}
    for index, tag, value in walk_table(DOT1Q_TP_FDB_ADDRESS, device_ip, community, timeout):
        # Index is <vlanId>.<mac 6 bytes>
        if len(index) < 7 or tag != TAG_OCTET_STRING:
            continue
        mac = dec_mac(value)
        if mac:
            by_vlan.setdefault(index[0], []).append(mac)

    if by_vlan:
        return {vlan: sorted(set(macs)) for vlan, macs in by_vlan.items()}

    for index, tag, value in walk_table(DOT1D_TP_FDB_ADDRESS, device_ip, community, timeout):
        if tag != TAG_OCTET_STRING:
            continue
        mac = dec_mac(value)
        if mac:
            # dot1dTpFdbAddress has no VLAN in the index; VLAN 1 is the only
            # honest bucket until a per-VLAN walk succeeds.
            by_vlan.setdefault(1, []).append(mac)
    return {vlan: sorted(set(macs)) for vlan, macs in by_vlan.items()}


def collect_fdb_entries_vlan(device_ip: str, vlan_id: int, community: str | None = None,
                             timeout: float | None = None) -> list[str]:
    """BRIDGE-MIB forwarding entries for one VLAN via "community@vlan".

    Some Cisco IOS agents only expose the per-VLAN view when the community
    string carries the VLAN id, so this is the only way to count those VLANs.
    """
    if not settings.snmp_enabled:
        return []
    base_community = community or settings.snmp_community
    timeout = timeout if timeout is not None else settings.snmp_timeout_seconds
    macs = []
    for index, tag, value in walk_table(DOT1D_TP_FDB_ADDRESS, device_ip, f"{base_community}@{vlan_id}", timeout):
        if tag == TAG_OCTET_STRING and (mac := dec_mac(value)):
            macs.append(mac)
    return sorted(set(macs))


def collect_neighbors(device_ip: str, community: str | None = None, timeout: float | None = None) -> list[dict]:
    """LLDP (and the Cisco CDP cache) neighbours, for topology context only."""
    if not settings.snmp_enabled:
        return []
    community = community or settings.snmp_community
    timeout = timeout if timeout is not None else settings.snmp_timeout_seconds
    neighbors = []

    chassis = {index: value for index, tag, value in walk_table(LLDP_REM_CHASSIS_ID, device_ip, community, timeout)}
    for index, tag, value in walk_table(LLDP_REM_SYS_NAME, device_ip, community, timeout):
        neighbors.append({
            "source": "lldpRemTable",
            "remote_name": dec_string(tag, value) or None,
            "remote_chassis_id": dec_string(*chassis.get(index, (TAG_OCTET_STRING, b""))),
            "local_port_index": index[0] if index else None,
        })

    cdp = {index: value for index, tag, value in walk_table(CDP_CACHE_ADDRESS, device_ip, community, timeout)}
    device_ids = {index: value for index, tag, value in walk_table(CDP_CACHE_DEVICE_ID, device_ip, community, timeout)}
    for index, tag, value in cdp.items():
        address = dec_ipv4(tag, value)
        if not address:
            continue
        neighbors.append({
            "source": "cdpCacheTable",
            "remote_name": dec_string(*device_ids.get(index, (TAG_OCTET_STRING, b""))),
            "remote_address": address,
            "local_port_index": index[0] if index else None,
        })
    return neighbors
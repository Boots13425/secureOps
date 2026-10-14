"""Per-VLAN cross-network detection (read-only SNMP).

A router/switch is asked, over read-only SNMP GET/GETNEXT, which VLANs it has.
Each VLAN is then resolved to a scannable subnet and to a reachability verdict,
so the UI can offer an independent scan for one VLAN at a time instead of one
undifferentiated "other network".

The resolution chain, and why each link is needed:

    VLAN id + name          dot1qVlanCurrentTable
    MAC count (est. size)   dot1qTpFdbTable / dot1dTpFdbTable
    VLAN -> interface       dot1qTpFdbPort (which port each MAC sits behind)
    interface -> subnet     ipAddressTable / ipAddrTable
    subnet -> routed?       ipCidrRouteTable, plus the SVI address itself

Nothing here probes a detected network. A scan only happens when a user
explicitly authorizes one through the API, and only for a VLAN that was proven
to have a routed path (see `network_is_scannable`).
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from . import snmp
from .config import settings
from .network import connected_ipv4_networks, current_default_network

# Why a VLAN cannot be scanned, shown verbatim in the UI as the disabled
# button's explanation. Deliberately says this is a network configuration
# change rather than a tool limitation, because that is the truth: no amount of
# retrying from this host can reach an unrouted L2-only VLAN.
L2_ONLY_REASON = (
    "This network has no routed path from this scanner. Scanning it requires a "
    "network connection (e.g. a trunk port) on this VLAN, which is a network "
    "configuration change, not something this tool can do remotely."
)
NO_SUBNET_REASON = (
    "This VLAN has no IP subnet reported by the device, so there is nothing to "
    "target. It may be a Layer 2-only or unused VLAN."
)
# A VLAN can be plainly visible on a switch's MAC table and still have no route
# to it anywhere. That is the signature of inter-router routing simply not
# being configured, so say that instead of implying the VLAN is broken.
NO_ROUTE_REASON = (
    "This network exists but there is no configured route to it from here - "
    "inter-router routing (static route or a routing protocol) would need to be "
    "set up for this to be reachable."
)
# The next-hop router is a real path, but only the already-configured community
# is ever used to read it, so a device needing different credentials cannot be
# described in detail. Reported per network rather than aborting the traversal.
HOP_CREDENTIALS_REASON = (
    "Reachable per the routing table, but this next-hop router's own device "
    "information could not be queried with the configured SNMP credentials. "
    "Different credentials may be needed for it."
)

# Fallback: infer subnets from ARP table gateway IPs when standard tables fail.
# Layer-3 switches often expose SVI gateways in ARP but not in ipAddressTable.
ARP_SUBNET_INFERENCE_REASON = (
    "Subnet inferred from ARP table gateway address (SVI) because the device "
    "did not expose it via ipAddressTable/ipAddrTable or VLAN tables."
)


def _normalize_cidr(value: str | None) -> str | None:
    """Canonicalize a CIDR so two spellings of one subnet compare equal."""
    if not value:
        return None
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None


def _classify_reachability(subnet: str | None, connected: set, learned: set,
                            known: set) -> tuple[bool, str]:
    """Decide (is_reachable, path) for a subnet seen on a device.

    "direct" means attached to this device's own interface. "routed" means the
    device has a route to it that goes out via another router - still reachable,
    but through a hop rather than the local segment. "none" means the device
    knows nothing about it at all, which for a VLAN that plainly exists means
    inter-router routing is not configured.

    A pure Layer 2 switch has no route table at all, so an empty `known` is not
    evidence of unreachability; the interface's own address is then trusted.
    """
    if not subnet:
        return False, "none"
    cidr = _normalize_cidr(subnet)
    if cidr in connected:
        return True, "direct"
    if not known:
        return True, "direct"
    if cidr in learned:
        return True, "routed"
    return False, "none"


def _infer_subnets_from_arp(arp_entries: dict[str, str]) -> list[dict]:
    """Infer subnets from ARP table by detecting gateway IPs (typically .1 or .254).

    Returns list of {cidr, gateway_ip, subnet_evidence} for each inferred subnet.
    """
    import ipaddress
    gateways = set()
    for ip_str in arp_entries.keys():
        try:
            ip = ipaddress.IPv4Address(ip_str)
            # Common gateway patterns: last octet 1 or 254
            if ip.packed[-1] in (1, 254):
                gateways.add(ip)
        except ValueError:
            continue

    inferred = []
    for gw in sorted(gateways):
        # Infer /24 subnet from gateway
        try:
            network = ipaddress.IPv4Network(f"{gw}/24", strict=False)
            inferred.append({
                "cidr": str(network),
                "gateway_ip": str(gw),
                "subnet_evidence": "arp_gateway_inference",
            })
        except ValueError:
            continue
    return inferred


def discover_networks(device_ip: str, community: str | None = None,
                     timeout: float | None = None) -> list[dict]:
    """Every VLAN on one router/switch, each with its own subnet and verdict.

    Read-only. Returns one record per VLAN, ordered by VLAN id.
    """
    if not settings.cross_network_discovery_enabled:
        return []
    community = community or settings.snmp_community
    timeout = timeout if timeout is not None else settings.cross_network_snmp_timeout_seconds

    vlans = snmp.collect_vlans(device_ip, community, timeout)
    macs_by_vlan = snmp.collect_fdb_entries(device_ip, community, timeout)
    fdb_ports = snmp.collect_fdb_ports(device_ip, community, timeout)
    interface_addresses = snmp.collect_interface_addresses(device_ip, community, timeout)
    routes = snmp.collect_routes(device_ip, community, timeout)
    # ARP table fallback: Layer-3 switches often expose SVI gateways here
    # when ipAddressTable/ipAddrTable and VLAN tables are empty.
    arp_entries = snmp.collect_arp_entries(device_ip, community, timeout)
    arp_legacy = arp_entries.get("legacy", {})
    arp_physical = arp_entries.get("physical", {})
    all_arp = {**arp_legacy, **arp_physical}
    identity = snmp.collect_identity(device_ip, community, timeout)

    # Pre-compute route-based subnet sets for reachability classification.
    # These are needed both for VLAN processing and for ARP-inference fallback.
    connected_subnets = {
        _normalize_cidr(route.get("cidr"))
        for route in routes if route.get("connected")
    }
    learned_subnets = {
        _normalize_cidr(route.get("cidr"))
        for route in routes if route.get("learned")
    }
    known_subnets = connected_subnets | learned_subnets
    known_subnets.discard(None)

    if not vlans:
        # Some agents expose the MAC table but no VLAN table. Report VLAN 1
        # rather than nothing, because those MACs are still a real signal.
        if not macs_by_vlan:
            # No VLANs, no MACs - try ARP table inference as last resort
            arp_inferred = _infer_subnets_from_arp(all_arp)
            results: list[dict] = []
            for inf in arp_inferred:
                cidr = inf["cidr"]
                routed, path = _classify_reachability(cidr, connected_subnets,
                                                      learned_subnets, known_subnets)
                record = {
                    "vlan_id": None,
                    "name": f"Inferred from ARP gateway {inf['gateway_ip']}",
                    "subnet": cidr,
                    "subnet_evidence": inf["subnet_evidence"],
                    "reachability_path": path,
                    "if_indexes": [],
                    "mac_count": 0,
                    "routed": routed,
                    "source_device": device_ip,
                    "source_device_name": identity.get("sys_name"),
                }
                record["scannable"], record["unscannable_reason"] = network_is_scannable(record)
                if not routed and path == "none":
                    record["unscannable_reason"] = NO_ROUTE_REASON
                results.append(record)
            return sorted(results, key=lambda item: (item["vlan_id"] is None, item["vlan_id"] or 0))
        vlans = [{"vlan_id": 1, "name": None, "source": "implicit"}]

    # interface -> subnet. An SVI/interface address is the subnet's own proof of
    # existence, so this is the primary mapping.
    subnet_by_interface: dict[int, list[str]] = {}
    for entry in interface_addresses:
        cidr = _normalize_cidr(entry.get("cidr"))
        if_index = entry.get("if_index")
        if cidr and if_index is not None:
            subnet_by_interface.setdefault(if_index, []).append(cidr)

    results: list[dict] = []
    for vlan in vlans:
        vlan_id = vlan.get("vlan_id")
        if vlan_id is None:
            continue
        vlan_id = int(vlan_id)
        macs = macs_by_vlan.get(vlan_id) or []
        ports = fdb_ports.get(vlan_id) or {}

        # VLAN -> subnet, via the ports its learned MACs sit behind.
        candidate_subnets: list[str] = []
        for if_index in sorted(set(ports.values())):
            candidate_subnets.extend(subnet_by_interface.get(if_index, []))
        subnets = sorted(set(candidate_subnets))

        # Fall back to matching the whole connected route set when no FDB port
        # mapped anywhere (many agents withhold dot1qTpFdbPort). Only
        # directly-attached subnets qualify, so this cannot invent a VLAN that
        # does not exist, but it also cannot attribute one to a specific VLAN.
        subnet = subnets[0] if subnets else None
        subnet_evidence = "fdb_port" if subnet else None

        if not subnet and vlan_id == 1 and len(connected_subnets) == 1:
            subnet = next(iter(connected_subnets))
            subnet_evidence = "default_vlan_single_connected_subnet"

        routed, path = _classify_reachability(subnet, connected_subnets,
                                              learned_subnets, known_subnets)
        record = {
            "vlan_id": vlan_id,
            "name": vlan.get("name"),
            "subnet": subnet,
            "subnet_evidence": subnet_evidence,
            "reachability_path": path,
            "if_indexes": sorted(set(ports.values())),
            "mac_count": len(macs),
            "routed": routed,
            "source_device": device_ip,
            "source_device_name": identity.get("sys_name"),
        }
        record["scannable"], record["unscannable_reason"] = network_is_scannable(record)
        if not routed and subnet and path == "none":
            # A VLAN with an address that appears in no route table at all is
            # the signature of inter-router routing not being configured, which
            # is a different problem from the VLAN being Layer 2 only.
            record["unscannable_reason"] = NO_ROUTE_REASON
        results.append(record)

    # Fallback: infer additional subnets from ARP table gateway IPs.
    # This catches Layer-3 switch SVIs that don't appear in VLAN/interface tables.
    standard_subnets = {_normalize_cidr(r.get("subnet")) for r in results if r.get("subnet")}
    standard_subnets.discard(None)
    arp_inferred = _infer_subnets_from_arp(all_arp)
    for inf in arp_inferred:
        cidr = inf["cidr"]
        if cidr in standard_subnets:
            continue
        # Create a synthetic record for this inferred subnet.
        # No VLAN ID available from ARP alone; use None.
        routed, path = _classify_reachability(cidr, connected_subnets,
                                              learned_subnets, known_subnets)
        record = {
            "vlan_id": None,
            "name": f"Inferred from ARP gateway {inf['gateway_ip']}",
            "subnet": cidr,
            "subnet_evidence": inf["subnet_evidence"],
            "reachability_path": path,
            "if_indexes": [],
            "mac_count": 0,
            "routed": routed,
            "source_device": device_ip,
            "source_device_name": identity.get("sys_name"),
        }
        record["scannable"], record["unscannable_reason"] = network_is_scannable(record)
        if not routed and path == "none":
            record["unscannable_reason"] = NO_ROUTE_REASON
        results.append(record)

    return sorted(results, key=lambda item: (item["vlan_id"] is None, item["vlan_id"] or 0))


def record_cidr(network: dict) -> str | None:
    """The subnet of a detection record or a stored `networks` row.

    Prefers the authoritative `cidr` column. `cidr_text` is only trusted when it
    actually carries a prefix length: a bare "10.0.0.0" would otherwise normalize
    to a /32, and a scan aimed at a /32 silently targets one host instead of the
    subnet the whole detection agreed on.
    """
    for key in ("subnet", "cidr"):
        cidr = _normalize_cidr(network.get(key))
        if cidr:
            return cidr
    text = network.get("cidr_text")
    if isinstance(text, str) and "/" in text:
        return _normalize_cidr(text)
    return None


def network_is_scannable(network: dict) -> tuple[bool, str | None]:
    """The single reachability rule, shared by detection and the scan endpoint.

    Accepts either a fresh detection record (which carries `routed`) or a stored
    `networks` row (which carries the verdict detection already made and
    persisted). Returns (scannable, reason_when_not). Kept in one place so a
    VLAN can never be listed as scannable by one part of the app and refused by
    another.
    """
    cidr = record_cidr(network)
    if not cidr:
        # A VLAN the device reports with no IP information cannot have a routed
        # path from here either, and the remedy is identical: physical access
        # to the VLAN. Saying so is more useful than "nothing to target", which
        # does not tell the user what would actually change the outcome.
        return False, L2_ONLY_REASON

    if "routed" in network:
        routed = bool(network["routed"])
        if not routed:
            return False, L2_ONLY_REASON
    else:
        # Stored row: `routed` was decided at detection time and persisted as
        # is_scannable/reachability_reason. Reuse that rather than re-deriving
        # a verdict from columns the table does not carry.
        if not network.get("is_scannable", False):
            return False, network.get("reachability_reason") or L2_ONLY_REASON

    try:
        target = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False, NO_SUBNET_REASON
    if target.version != 4:
        return False, "Only IPv4 subnets can be scanned."
    if target.prefixlen < settings.cross_network_max_scan_prefix and not settings.cross_network_allow_large_scans:
        return False, (
            f"This subnet is larger than /{settings.cross_network_max_scan_prefix}, which would "
            "generate an impractically large scan. An administrator can raise "
            "CROSS_NETWORK_MAX_SCAN_PREFIX or set CROSS_NETWORK_ALLOW_LARGE_SCANS to permit it."
        )
    return True, None


def is_internal_address(value: str | None) -> bool:
    """True only for RFC1918 private space and IPv6 ULA.

    Deliberately not `ipaddress.is_private`, which also admits loopback,
    link-local and the documentation/test ranges. Traversal is for mapping the
    internal estate; a default route's next hop usually points at an ISP or a
    public transit address, and following that would start probing outward.
    """
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if address.version == 4:
        return any(address in network for network in (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ))
    return address in ipaddress.ip_network("fc00::/7")


def _router_inventory() -> dict[str, dict]:
    """Classified routers/switches by IP, for deciding what may be traversed to.

    Traversal only ever steps to a device a scan has already identified as a
    router or switch. Hopping to an arbitrary address found in a routing table
    would mean probing hosts whose role is unknown.
    """
    from .database import connection

    with connection() as conn:
        rows = conn.execute(
            "SELECT host(ip_address) AS ip, hostname, device_type FROM assets "
            "WHERE device_type = ANY(%s)", (list(L3_DEVICE_TYPES),)
        ).fetchall()
    return {row["ip"]: row for row in rows if row.get("ip")}


def traverse_routers(seeds: list[str], community: str | None = None,
                     timeout: float | None = None) -> dict:
    """Walk the routing tables of every reachable router, breadth-first.

    Each router is a node. A learned route is an edge: "this router reaches
    subnet X via next hop Y". When Y is an internal address belonging to a
    device already classified as a router in the inventory, it becomes the next
    node, up to CROSS_NETWORK_MAX_HOPS.

    Only the already-configured community is ever used. A hop that does not
    answer it is recorded as unqueryable and the walk continues, because that
    says nothing about the other subnets already found.

    Read-only SNMP throughout; no detected network is probed.
    """
    inventory = _router_inventory()
    max_hops = max(0, int(settings.cross_network_max_hops))
    community = community or settings.snmp_community
    timeout = timeout if timeout is not None else settings.cross_network_snmp_timeout_seconds

    visited: set[str] = set()
    queue: list[tuple[str, int, list[dict]]] = [(ip, 0, []) for ip in seeds]
    routed_networks: dict[str, dict] = {}
    queried: list[dict] = []
    unqueryable: list[dict] = []

    while queue:
        device_ip, hop, path = queue.pop(0)
        if device_ip in visited:
            continue
        visited.add(device_ip)

        if not snmp.reachable(device_ip, community, timeout):
            entry = {"ip": device_ip, "hop": hop, "reason": HOP_CREDENTIALS_REASON}
            # A seed that cannot be reached is a real gap; a next hop that
            # cannot is only a limit on how much detail we can add.
            if hop == 0:
                queried.append({"ip": device_ip, "hop": hop, "routes": 0, "reachable": False})
            unqueryable.append(entry)
            for network in routed_networks.values():
                network.setdefault("notes", []).append(HOP_CREDENTIALS_REASON)
            continue

        routes = snmp.collect_routes(device_ip, community, timeout)
        queried.append({"ip": device_ip, "hop": hop, "routes": len(routes), "reachable": True})

        for route in routes:
            cidr = _normalize_cidr(route.get("cidr"))
            next_hop = route.get("next_hop")
            if not cidr or cidr == "0.0.0.0/0":
                # The default route describes the internet, not an internal
                # network worth listing or scanning.
                continue
            if not route.get("learned"):
                continue
            if not is_internal_address(next_hop):
                # Stop at the edge rather than following a path out of the org.
                continue

            hops = [*path, {
                "router_ip": device_ip,
                "next_hop": next_hop,
                "route_type": route.get("route_kind"),
                "route_source": route.get("source"),
            }]
            record = routed_networks.setdefault(cidr, {
                "subnet": cidr,
                "reachability_path": "routed",
                "reachability_hops": hops,
                "hop_count": len(hops),
                "via_router": device_ip,
                "via_device_type": (inventory.get(device_ip) or {}).get("device_type"),
                "notes": [],
            })
            # Prefer the shortest proven path so the reported route is the most
            # direct one, not whichever hop happened to be read first.
            if len(hops) < len(record["reachability_hops"]):
                record["reachability_hops"] = hops
                record["hop_count"] = len(hops)
                record["via_router"] = device_ip

            if hop + 1 >= max_hops:
                # max_hops counts routers in a chain, so the default of 2 means
                # "the seed router plus one hop beyond it". The route itself is
                # still recorded at this depth; only further traversal stops.
                continue
            target = inventory.get(next_hop)
            if target is None:
                record["notes"].append(
                    f"Next hop {next_hop} is not classified as a router in the asset "
                    "inventory, so traversal stopped there rather than probing an unknown host.")
                continue
            if next_hop not in visited:
                queue.append((next_hop, hop + 1, hops))

    for network in routed_networks.values():
        scannable, reason = network_is_scannable({
            "subnet": network["subnet"],
            "is_scannable": True,
        })
        network["scannable"] = scannable
        network["unscannable_reason"] = reason
        if network["notes"]:
            network["unscannable_reason"] = reason or " ".join(dict.fromkeys(network["notes"]))

    return {
        "routed_networks": list(routed_networks.values()),
        "queried": queried,
        "unqueryable": unqueryable,
        "max_hops": max_hops,
        "depth_reached": max((q["hop"] for q in queried), default=0),
    }


def summarize_networks(networks: list[dict]) -> dict:
    """Counts for the Networks page header. Counts only, never device detail."""
    return {
        "total": len(networks),
        "scannable": sum(1 for n in networks if n.get("scannable")),
        "layer2_only": sum(1 for n in networks if not n.get("scannable")),
    }


def detect_and_store(device_ip: str, community: str | None = None,
                     timeout: float | None = None) -> list[dict]:
    """Detect one device's VLANs and persist them as one row per VLAN.

    Safe to call repeatedly: the upsert merges evidence rather than replacing
    it, and last_seen advances. Never raises for an unreachable device - an
    absent answer simply yields no rows.
    """
    from . import repository  # imported here to keep detection importable standalone

    detected = discover_networks(device_ip, community, timeout)
    stored = []
    for record in detected:
        sources = [{
            "device_ip": record.get("source_device"),
            "device_name": record.get("source_device_name"),
            "vlan_source": record.get("vlan_source"),
            "mac_count": record.get("mac_count"),
        }]
        stored.append(repository.upsert_detected_network({
            "cidr": record.get("subnet"),
            "vlan_id": record.get("vlan_id"),
            "label": record.get("name") or (f"VLAN {record['vlan_id']}"),
            "is_local": False,
            "sources": sources,
            "estimated_device_count": record.get("mac_count"),
            "count_method": "mac_table" if record.get("mac_count") else None,
            "is_scannable": record.get("scannable"),
            "reachability_reason": record.get("unscannable_reason"),
            "subnet_evidence": record.get("subnet_evidence"),
            "if_indexes": record.get("if_indexes"),
            "reachability_path": record.get("reachability_path", "direct"),
            "reachability_hops": [],
        }))
    if stored:
        repository.attribute_assets_to_networks()
    return stored


NOT_CLASSIFIED_YET = (
    "No router, switch or firewall has been classified in the asset inventory "
    "yet, so there is nothing to ask for VLANs. Run a network scan first - any "
    "device classified as a router or switch becomes a detection target "
    "automatically, with no configuration needed."
)

# Devices that can actually answer a VLAN/routing question. These are the
# already-classified assets: the scan's OS/vendor signature pass is what puts a
# device in this list, so this function needs no router IP, no gateway and no
# other manual input.
L3_DEVICE_TYPES = ("router", "switch", "firewall", "network device")


def discover_candidates() -> list[dict]:
    """Infrastructure devices to ask for VLANs, derived from asset inventory.

    Reads the router/switch devices a previous scan already identified and
    classified, so correlation is automatic on every re-run: as soon as a scan
    classifies a device as a router or switch it becomes a target, with no
    per-run input of any kind. Every classified device is returned, not just the
    first, because different L3 devices commonly own different VLANs and their
    answers are merged.

    Freshness is bounded by CROSS_NETWORK_DEVICE_MAX_SCAN_AGE_HOURS so an IP that
    has since been reassigned is not asked to describe a network it no longer
    sits on. Skipped-by-age devices are reported rather than dropped silently.
    """
    from .database import connection

    if not settings.cross_network_discovery_enabled:
        return []

    max_age = max(1, int(settings.cross_network_device_max_age_hours))
    with connection() as conn:
        rows = conn.execute(
            """SELECT host(ip_address) AS ip, hostname, device_type, vendor, last_seen
               FROM assets WHERE device_type = ANY(%s)
               ORDER BY last_seen DESC LIMIT 16""",
            (list(L3_DEVICE_TYPES),),
        ).fetchall()

    candidates, stale = [], []
    for row in rows:
        if not row.get("ip"):
            continue
        entry = {
            "ip": row["ip"],
            "hostname": row.get("hostname"),
            "device_type": row.get("device_type"),
            "vendor": row.get("vendor"),
            "last_seen": row.get("last_seen"),
        }
        seen = row.get("last_seen")
        if seen is not None and (datetime.now(timezone.utc) - seen).total_seconds() > max_age * 3600:
            entry["skipped"] = (
                f"Last seen {seen:%Y-%m-%d %H:%M}, older than the "
                f"{max_age}-hour window (CROSS_NETWORK_DEVICE_MAX_AGE_HOURS). "
                "Re-scan the network to refresh it."
            )
            stale.append(entry)
        else:
            candidates.append(entry)
    return candidates + stale


def active_candidates() -> list[dict]:
    """Only the candidates fresh enough to actually be queried."""
    return [c for c in discover_candidates() if not c.get("skipped")]


def detect_all(community: str | None = None, timeout: float | None = None) -> dict:
    """Ask every classified L3 device, traverse its routing tables, merge, persist.

    Two detection layers, both read-only:

      direct  - VLANs on the queried switches/routers, subnet from the VLAN's
                own interface (the existing single-router case)
      routed  - subnets only reachable through one or more next-hop routers,
                discovered by traversing the routing tables

    Reports what it did, including the case where there was nothing to ask, so
    an empty result is never mistaken for a failure.
    """
    candidates = discover_candidates()
    active = [c for c in candidates if not c.get("skipped")]
    skipped = [c for c in candidates if c.get("skipped")]

    if not active:
        return {
            "networks": [],
            "routed_networks": [],
            "queried": [],
            "skipped": skipped,
            "report": NOT_CLASSIFIED_YET if not candidates else
                      "No classified router or switch is recent enough to query.",
        }

    queried, by_vlan = [], {}
    for candidate in active:
        stored = detect_and_store(candidate["ip"], community, timeout)
        queried.append({
            "ip": candidate["ip"],
            "hostname": candidate.get("hostname"),
            "device_type": candidate.get("device_type"),
            "vlans_found": len(stored),
        })
        for network in stored:
            # Merge by VLAN: the first device to report a VLAN supplies its
            # subnet/verdict, and any further evidence is merged into `sources`.
            vlan_id = network.get("vlan_id")
            if vlan_id is not None:
                by_vlan.setdefault(vlan_id, network)
            else:
                # ARP-inferred networks have no VLAN ID; key by CIDR instead.
                cidr = network.get("subnet") or network.get("cidr")
                if cidr:
                    by_vlan.setdefault(("arp", cidr), network)

    # Second layer: multi-router traversal over the same devices.
    graph = traverse_routers([c["ip"] for c in active], community, timeout)
    for record in graph["routed_networks"]:
        stored = repository_store_routed(record)
        by_vlan.setdefault(("routed", record["subnet"]), stored)

    direct_networks = sorted(
        (by_vlan[v] for v in by_vlan if not (isinstance(v, tuple) and v[0] == "routed")),
        key=lambda n: (n.get("vlan_id") is None, n.get("vlan_id")),
    )
    routed_networks = [by_vlan[v] for v in by_vlan if isinstance(v, tuple) and v[0] == "routed"]

    all_networks = direct_networks + routed_networks
    
    # Determine which network the scanner is actually on (local network)
    local_networks = connected_ipv4_networks()
    for network in all_networks:
        cidr = record_cidr(network)
        if cidr:
            target = ipaddress.ip_network(cidr, strict=False)
            for local_net in local_networks:
                if target == local_net:
                    network["is_local"] = True
                    # Persist the is_local flag to database
                    from . import repository
                    repository.update_network_is_local(network["network_id"], True)
                    break
    
    # Ensure the scanner's local networks are in the networks table
    # (in case no router/switch was queried for them)
    from . import repository
    for local_net in local_networks:
        # Check if this local network is already in the results
        found = False
        for network in all_networks:
            cidr = record_cidr(network)
            if cidr and ipaddress.ip_network(cidr, strict=False) == local_net:
                found = True
                break
        if not found:
            # Add local network to the list
            local_network_record = {
                "cidr": str(local_net),
                "vlan_id": None,
                "label": f"Local network ({local_net})",
                "is_local": True,
                "is_scannable": True,
                "reachability_path": "direct",
                "subnet_evidence": "local_interface",
                "if_indexes": [],
                "reachability_hops": [],
                "sources": [{"device_ip": "local", "device_name": "Scanner"}],
                "estimated_device_count": None,
                "count_method": None,
            }
            # Persist to database
            stored = repository.upsert_detected_network(local_network_record)
            all_networks.append(stored)

    result = {
        "networks": direct_networks,
        "routed_networks": routed_networks,
        "queried": queried,
        "traversal": graph,
        "skipped": skipped,
        "report": None,
    }
    if not all_networks:
        # Distinguish "nothing to ask" from "asked and got nothing back". The
        # latter is the case that otherwise looks like a silent failure: it is
        # nearly always an unreachable agent or a community mismatch, not an
        # absence of VLANs.
        result["report"] = (
            f"Queried {len(queried)} classified network device(s) and none returned a VLAN "
            "table. Either the device does not answer SNMP on UDP 161 from this host, or "
            "SNMP_COMMUNITY does not match it. Detection never probes anything to find out."
        )
    return result


def repository_store_routed(record: dict) -> dict:
    """Persist one traversal-discovered subnet as its own networks row.

    Routed subnets have no VLAN id, so they are keyed by CIDR alone and listed
    separately from the per-VLAN cards.
    """
    from . import repository

    hops = record.get("reachability_hops") or []
    stored = repository.upsert_detected_network({
        "cidr": record.get("subnet"),
        "vlan_id": None,
        "label": f"Via {record.get('via_router')} ({record.get('hop_count')} hop"
                 f"{'s' if record.get('hop_count') != 1 else ''})",
        "is_local": False,
        "sources": [{"device_ip": hop["router_ip"], "next_hop": hop["next_hop"],
                     "route_type": hop.get("route_type")} for hop in hops],
        "estimated_device_count": None,
        "count_method": None,
        "is_scannable": record.get("scannable"),
        "reachability_reason": record.get("unscannable_reason"),
        "subnet_evidence": "routing_table_next_hop",
        "if_indexes": [],
        "reachability_path": "routed",
        "reachability_hops": hops,
    })
    repository.attribute_assets_to_networks()
    return stored
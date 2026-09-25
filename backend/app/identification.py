"""Authoritative device identification and field merging (Layer 1 accuracy).

Nmap can only *infer* a device's name, vendor, type and OS from side signals
(MAC OUI, optional banners, top-100 ports). This module lets the scanner layer
additional, more trustworthy sources on top of Nmap - SNMP, mDNS, DHCP leases,
reverse DNS, NetBIOS - and merge them per field using an explicit priority
order, so an authoritative value is never silently overwritten by a guess.

Nothing here removes Nmap's data: Nmap's inference is simply the lowest-priority
("nmap_heuristic") candidate. Devices for which no source returns a value keep
an honest "unknown" rather than a fabricated confident answer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import NamedTuple

from .config import settings


# Confidence label per source. Authoritative sources are vendor/administrator
# supplied (SNMP agent, DHCP server); inferred sources are best-effort guesses.
SOURCE_CONFIDENCE = {
    "dhcp_lease": "high",
    "snmp": "high",
    "os_signature": "medium",
    "reverse_dns": "medium",
    "netbios": "medium",
    "mdns": "medium",
    "hostname_hint": "low",
    "device_text": "medium",
    "service_heuristic": "low",
    "nmap_heuristic": "low",
}

# Authoritative sources beat inferred ones even if the operator's priority list
# is misconfigured.
AUTHORITATIVE_SOURCES = frozenset({"dhcp_lease", "snmp"})

# Fields that participate in source-tagged merging.
MERGED_FIELDS = ("hostname", "vendor", "os_family", "device_type")

# IANA Private Enterprise Numbers (PEN) -> vendor, for sysObjectID
# (1.3.6.1.4.1.<PEN>). Authoritative and independent of MAC OUI, so it works
# for routed/randomized-MAC devices. Unknown PEN -> no vendor (never wrong).
ENTERPRISE_VENDORS = {
    9: "Cisco", 11: "Hewlett-Packard", 63: "Apple", 111: "Oracle", 124: "Epson",
    171: "D-Link", 253: "Xerox", 311: "Microsoft", 318: "APC", 674: "Dell",
    890: "Zyxel", 1416: "ASUSTeK", 1602: "Canon", 1716: "Brother",
    2435: "Brother", 2620: "Check Point", 2636: "Juniper Networks",
    3375: "F5 Networks", 4526: "NETGEAR", 5078: "Belkin", 6574: "Synology",
    6876: "VMware", 8072: "net-snmp (Linux/BSD)", 8741: "SonicWall",
    10642: "Zebra Technologies", 11863: "TP-Link", 12356: "Fortinet",
    14988: "MikroTik", 17163: "Riverbed", 17166: "DrayTek", 24681: "QNAP",
    25053: "Ruckus Networks", 25461: "Palo Alto Networks", 29671: "Cisco Meraki",
    41112: "Ubiquiti",
}

# sysDescr substrings -> normalized OS family (vendor-provided, far more
# reliable than inferring an OS from open ports).
_SYSDESCR_OS_PATTERNS = (
    ("cisco nx-os", "Cisco NX-OS"), ("cisco adaptive security", "Cisco ASA"),
    ("cisco ios", "Cisco IOS"), ("ios software", "Cisco IOS"), ("cisco", "Cisco"),
    ("junos kernel", "Juniper Junos"), ("junos", "Juniper Junos"),
    ("fortios", "FortiOS"), ("fortigate", "FortiOS"),
    ("palo alto", "PAN-OS"), ("pan-os", "PAN-OS"),
    ("mikrotik", "RouterOS"), ("routeros", "RouterOS"), ("vyos", "VyOS"),
    ("arubanetworks", "ArubaOS"), ("arubaos", "ArubaOS"),
    ("windows", "Windows"), ("microsoft", "Windows"),
    ("ubuntu", "Ubuntu Linux"), ("debian", "Debian Linux"),
    ("esxi", "VMware ESXi"), ("vmware", "VMware"),
    ("freebsd", "FreeBSD"), ("openbsd", "OpenBSD"), ("netbsd", "NetBSD"),
    ("darwin", "macOS"), ("mac os", "macOS"), ("macos", "macOS"),
    ("android", "Android"), ("linux", "Linux"),
    ("brother", "Brother printer firmware"), ("ricoh", "Ricoh printer firmware"),
    ("laserjet", "HP printer firmware"), ("hewlett-packard", "HP printer firmware"),
    ("xerox", "Xerox printer firmware"), ("epson", "Epson printer firmware"),
    ("canon", "Canon printer firmware"), ("lexmark", "Lexmark printer firmware"),
    ("zebra", "Zebra printer firmware"),
)

# Substrings that imply a device type, in priority order. Aligned with the
# schema's device_type CHECK values (PC/server/router/switch/printer/phone).
_TYPE_PATTERNS = (
    ("switch", ("switch", "catalyst", "nexus", "stack", "access point", "arubaos")),
    ("router", ("router", "gateway", "firewall", "routeros", "edgeos", "fortigate",
                "palo alto", "junos")),
    ("printer", ("printer", "laserjet", "deskjet", "print server", "officejet",
                  "ecosys", "imagistics", "imageclass", "workcentre")),
    ("phone", ("iphone", "ip phone", "voip", "sip phone", "android phone")),
    ("server", ("server", "esxi", "proliant", "poweredge", "synology", "diskstation",
                "qnap", "nas", "ubuntu server", "windows server")),
    ("PC", ("windows", "workstation", "desktop", "laptop", "macbook", "imac", "macos", "mac os")),
)

# --- Network-infrastructure OS signatures ---------------------------------
# A device that reports one of these is running network-equipment firmware, so
# no combination of open ports can make it a server. This is the highest
# confidence classification signal available: it comes from the vendor's own
# sysDescr (SNMP) or from Nmap's OS fingerprint, never from a port guess.
#
# A `None` role means the OS family itself cannot separate router from switch
# (Cisco IOS runs on both), so the caller's next-best signals decide and the
# device falls back to the honest "network device" when they disagree.
# Firewalls and gateways map to "router": the schema's infrastructure bucket.
NETWORK_OS_SIGNATURES = (
    # Firewalls / security appliances - unambiguous infrastructure.
    ("fortios", "router"), ("fortigate", "router"),
    ("pan-os", "router"), ("palo alto", "router"),
    ("cisco adaptive security", "router"), ("cisco asa", "router"),
    ("sonicwall", "router"), ("sonicos", "router"),
    # Switching platforms.
    ("cisco nx-os", "switch"), ("nx-os", "switch"),
    ("catalyst", "switch"),
    # Routing platforms.
    ("junos", "router"), ("juniper", "router"),
    ("routeros", "router"), ("mikrotik", "router"),
    ("vyos", "router"), ("edgeos", "router"),
    ("arubaos", "switch"), ("arubanetworks", "switch"),
    ("cumulus", "switch"),
    # Ambiguous families: same firmware family spans routers and switches.
    ("cisco ios-xe", None), ("ios-xe", None),
    ("cisco ios", None), ("ios software", None), ("cisco", None),
)

# Model names inside sysDescr. Same vendor-supplied string as the OS signature,
# but specific enough to separate router from switch (a C2960 cannot route;
# an ASR is not a bridge), so it is consulted before sysServices/hostname.
NETWORK_MODEL_SIGNATURES = (
    ("c2960", "switch"), ("c3560", "switch"), ("c3750", "switch"),
    ("c4500", "switch"), ("c6500", "switch"), ("c9200", "switch"),
    ("c9300", "switch"), ("ws-c", "switch"), ("ws-c6", "switch"),
    ("n3k-", "switch"), ("n5k-", "switch"), ("n7k-", "switch"), ("n9k-", "switch"),
    ("sg300", "switch"), ("sg350", "switch"), ("usw-", "switch"),
    ("aruba 2", "switch"), ("aruba 3", "switch"), ("aruba 5", "switch"),
    ("c800", "router"), ("c1800", "router"), ("c2800", "router"),
    ("c3800", "router"), ("c4000", "router"), ("asr", "router"),
    ("isr", "router"), ("mx240", "router"), ("srx", "router"),
    ("ex4200", "router"), ("acx", "router"),
)

# Common infrastructure naming conventions. A naming prefix is the weakest
# signal available: it raises confidence when nothing else is known, but never
# overrides a clear OS-based match (e.g. a Linux host named "SW-DEV-BOX").
HOSTNAME_PREFIX_HINTS = (
    ("sw-", "switch"), ("sw_", "switch"), ("swt-", "switch"),
    ("switch-", "switch"), ("switch_", "switch"),
    ("rtr-", "router"), ("rtr_", "router"), ("router-", "router"), ("rt-", "router"),
    ("gw-", "router"), ("fw-", "router"), ("fwl-", "router"),
    ("ap-", "network device"), ("wap-", "network device"),
)

# General-purpose operating systems. A sysServices bitmask on one of these says
# nothing about the device's role (any Linux host with ip_forward reports the
# same internetworking bit a router does), so it is never used to classify them.
GENERAL_PURPOSE_OS_MARKERS = (
    "windows", "linux", "ubuntu", "debian", "fedora", "centos", "red hat",
    "macos", "mac os", "darwin", "freebsd", "openbsd", "netbsd", "android",
    "vmware", "esxi", "proxmox",
)

# Once a general-purpose OS is known it decides the device family. A hypervisor
# or storage OS is a server no matter what the host was last named; a desktop
# OS is a PC. Everything else (plain Linux, BSD, Android) stays undecided here
# and falls through to the port heuristic rather than guessing from a name.
HOST_OS_MARKERS = (
    "esxi", "vmware", "proxmox", "synology", "diskstation", "qnap",
    "windows server", "server",
)
WORKSTATION_OS_MARKERS = ("windows", "macos", "mac os", "darwin", "ios")

# sysServices.0 bit positions (RFC 1213-MIB): the layers at which the device
# offers services.
_SYS_SERVICES_PHYSICAL = 0x02
_SYS_SERVICES_INTERNET = 0x04
_SYS_SERVICES_DATALINK = 0x08
_SYS_SERVICES_INTERNETWORKING = 0x40
_SYS_SERVICES_END_TO_END = 0x80



def confidence_for(source: str) -> str:
    return SOURCE_CONFIDENCE.get(source, "low")


def enterprise_vendor(sys_object_id: str | None) -> str | None:
    """Authoritative vendor from a sysObjectID enterprise OID, else None."""
    if not sys_object_id:
        return None
    parts = [p for p in str(sys_object_id).strip().lstrip(".").split(".") if p.isdigit()]
    if len(parts) >= 7 and parts[:6] == ["1", "3", "6", "1", "4", "1"]:
        return ENTERPRISE_VENDORS.get(int(parts[6]))
    return None


def parse_sysdescr(sys_descr: str | None) -> str | None:
    """Normalized OS family from a vendor-supplied sysDescr string, else None."""
    if not sys_descr:
        return None
    lowered = sys_descr.lower()
    for needle, family in _SYSDESCR_OS_PATTERNS:
        if needle in lowered:
            return family
    return None


def derive_device_type(*texts: str | None) -> str | None:
    """Device type from descriptive strings, else None (honest unknown)."""
    combined = " ".join(text.lower() for text in texts if text)
    if not combined:
        return None
    for device_type, needles in _TYPE_PATTERNS:
        if any(needle in combined for needle in needles):
            return device_type
    return None


class DeviceClassification(NamedTuple):
    """Classification result plus the signal that produced it."""
    device_type: str
    source: str
    detail: str


def _combined_lowercase(*texts: str | None) -> str:
    return " ".join(str(text).lower() for text in texts if text)


def is_general_purpose_os(*texts: str | None) -> bool:
    combined = _combined_lowercase(*texts)
    return bool(combined) and any(marker in combined for marker in GENERAL_PURPOSE_OS_MARKERS)


def network_os_role(*texts: str | None) -> tuple[str | None, bool]:
    """(device_type_or_None, matched) for network-infrastructure OS strings.

    A `None` type with matched=True means the OS family is network equipment
    but does not by itself say whether the device routes or bridges.
    """
    combined = _combined_lowercase(*texts)
    if not combined:
        return None, False
    for needle, role in NETWORK_OS_SIGNATURES:
        if needle in combined:
            return role, True
    return None, False


def network_model_role(*texts: str | None) -> str | None:
    combined = _combined_lowercase(*texts)
    for needle, role in NETWORK_MODEL_SIGNATURES:
        if needle in combined:
            return role
    return None


def hostname_role_hint(hostname: str | None) -> str | None:
    """Role implied by a common infrastructure naming prefix, else None."""
    if not hostname:
        return None
    label = str(hostname).split(".")[0].strip().lower()
    for prefix, role in HOSTNAME_PREFIX_HINTS:
        if label.startswith(prefix):
            return role
    return None


def sys_services_role(value) -> str | None:
    """Role implied by SNMP sysServices.0, else None (no opinion)."""
    try:
        layers = int(value)
    except (TypeError, ValueError):
        return None
    if layers <= 0 or not layers & _SYS_SERVICES_INTERNETWORKING:
        # No internetworking layer: whatever this device is, it is not a
        # router/switch, so the bitmask carries no role information.
        return None
    if layers & _SYS_SERVICES_END_TO_END:
        # Offers host-level services on top of routing: a gateway/router.
        return "router"
    if layers & _SYS_SERVICES_DATALINK:
        # Bridges without offering host services: a switch.
        return "switch"
    return "router"


def service_name_heuristic(service_names) -> str:
    """Last-resort classification from open port/service names only.

    Deliberately last: SSH/HTTPS/HTTP are management interfaces on switches,
    routers, firewalls and access points just as much as on servers, so this
    must never outrank OS or vendor evidence.
    """
    names = {str(name).lower() for name in service_names if name}
    if names & {"ipp", "printer", "jetdirect"}: return "printer"
    if names & {"router", "upnp"}: return "router"
    if names & {"microsoft-ds", "rdp"}: return "PC"
    if names & {"ssh", "http", "https", "mysql", "postgresql"}: return "server"
    return "unknown"


def classify_device(*, os_family: str | None = None, sys_descr: str | None = None,
                    sys_name: str | None = None, hostname: str | None = None,
                    vendor: str | None = None, sys_services=None,
                    service_names=()) -> DeviceClassification:
    """Classify a device from strongest to weakest available signal.

    Priority order (see scanner._classify):
      a. OS/platform signature - vendor sysDescr or Nmap OS detection.
      b. SNMP sysServices layer bitmask.
      c. Infrastructure naming convention in the hostname.
      d. Descriptive text (printers, phones, workstations, servers).
      e. Open port/service names - fallback only, never a tiebreaker.
    """
    general_os = is_general_purpose_os(os_family, sys_descr)

    # (a) OS/platform signature. Highest confidence: the vendor told us what
    # firmware this is.
    role, matched = network_os_role(os_family, sys_descr)
    if matched:
        if role:
            return DeviceClassification(role, "os_signature", f"network OS signature ({role})")
        # Ambiguous network OS (e.g. Cisco IOS): refine with the most specific
        # evidence still available, otherwise stay honestly generic.
        refined = network_model_role(sys_descr) or hostname_role_hint(hostname or sys_name)
        if not refined:
            refined = sys_services_role(sys_services)
        if refined in {"router", "switch"}:
            return DeviceClassification(refined, "os_signature", "network OS signature refined by model/hostname/sysServices")
        return DeviceClassification("network device", "os_signature", "network OS signature, router/switch ambiguous")

    # (b) SNMP sysServices - a standard field describing which layers the
    # device serves. Ignored for general-purpose hosts, where the same bits
    # appear on an ordinary server.
    if not general_os:
        snmp_role = sys_services_role(sys_services)
        if snmp_role:
            return DeviceClassification(snmp_role, "snmp_sys_services", f"sysServices={sys_services}")

    # (c) Hostname naming convention - raises confidence, never overrides.
    if not general_os:
        hint = hostname_role_hint(hostname or sys_name)
        if hint:
            return DeviceClassification(hint, "hostname_hint", f"hostname {hostname or sys_name}")

    # (d) Descriptive text for the remaining device families. A known
    # general-purpose OS decides its own family first, so a host that was
    # renamed to "DESKTOP-*" cannot demote a Proxmox hypervisor to a PC.
    os_text = _combined_lowercase(sys_descr, os_family)
    if os_text:
        if any(marker in os_text for marker in HOST_OS_MARKERS):
            return DeviceClassification("server", "device_text", "server OS in platform string")
        if any(marker in os_text for marker in WORKSTATION_OS_MARKERS):
            return DeviceClassification("PC", "device_text", "workstation OS in platform string")
        if "android" in os_text:
            return DeviceClassification("phone", "device_text", "mobile OS in platform string")
    derived = derive_device_type(sys_descr, os_family, sys_name, hostname) if not general_os else None
    if derived:
        return DeviceClassification(derived, "device_text", "descriptive text match")

    # (e) Port/service-name heuristic, used only when nothing else is known.
    return DeviceClassification(
        service_name_heuristic(service_names), "service_heuristic", "open port/service names"
    )


@dataclass
class FieldValue:
    value: str
    source: str
    confidence: str = field(init=False)

    def __post_init__(self):
        self.confidence = confidence_for(self.source)


def source_rank(source: str) -> int:
    """Lower = higher priority. Authoritative sources always rank ahead."""
    priority = list(settings.identification_source_priority)
    position = priority.index(source) if source in priority else len(priority)
    authoritative_bonus = 0 if source in AUTHORITATIVE_SOURCES else 100
    return authoritative_bonus * 1000 + position


def merge_field(candidates: list[FieldValue]) -> FieldValue | None:
    """Highest-priority (lowest-rank) value wins; None if nothing observed."""
    best: FieldValue | None = None
    best_rank: int | None = None
    for candidate in candidates:
        if not candidate.value:
            continue
        rank = source_rank(candidate.source)
        if best is None or rank < best_rank:
            best, best_rank = candidate, rank
    return best


def merge_candidates(old: dict | None, new: dict | None) -> dict | None:
    """Merge two stored field-provenance dicts without silently downgrading.

    Each candidate map is {source: value}. A new value wins only if it comes
    from an equally- or higher-priority source than the current best; otherwise
    the existing higher-confidence value is preserved. Returns the merged map.
    """
    merged = dict(old or {})
    for source, value in (new or {}).items():
        if value in (None, ""):
            continue
        merged[source] = value
    return merged or None


def best_from_candidates(candidates: dict | None) -> tuple[str | None, str | None]:
    """Return (winning value, winning source) for a stored {source: value} map."""
    if not candidates:
        return None, None
    ranked = sorted(((source_rank(source), source, value) for source, value in candidates.items() if value))
    if not ranked:
        return None, None
    _, source, value = ranked[0]
    return value, source


class IdentificationAccumulator:
    """Collects per-source observations for one host during a scan."""

    def __init__(self) -> None:
        self.candidates: dict[str, list[FieldValue]] = {name: [] for name in MERGED_FIELDS}
        self.sources: dict[str, dict[str, str]] = {}
        # Raw signals that are not merged fields but must survive into stored
        # provenance so a later reclassification can reuse them (sysServices).
        self.signals: dict[str, dict[str, object]] = {}

    def add_signal(self, name: str, value, source: str) -> None:
        if value in (None, ""):
            return
        self.signals[name] = {"value": value, "source": source,
                              "confidence": confidence_for(source)}

    def add(self, source: str, *, hostname=None, vendor=None, os_family=None, device_type=None) -> None:
        provided = {"hostname": hostname, "vendor": vendor, "os_family": os_family, "device_type": device_type}
        for name, value in provided.items():
            if value in (None, ""):
                continue
            text = str(value).strip()
            if not text:
                continue
            self.candidates[name].append(FieldValue(text, source))
            self.sources.setdefault(name, {})[source] = text

    def merged(self) -> dict[str, str | None]:
        return {name: (merge_field(self.candidates[name]).value if merge_field(self.candidates[name]) else None)
                for name in MERGED_FIELDS}

    def winning_source(self, field_name: str) -> str | None:
        winner = merge_field(self.candidates[field_name])
        return winner.source if winner else None

    def sources_for(self, field_name: str) -> dict[str, str]:
        return dict(self.sources.get(field_name, {}))

    def provenance(self) -> dict:
        merged = self.merged()
        result = {
            name: {
                "value": merged[name],
                "source": self.winning_source(name),
                "confidence": confidence_for(self.winning_source(name)) if self.winning_source(name) else None,
                "candidates": self.sources_for(name),
            }
            for name in MERGED_FIELDS
        }
        if self.signals:
            result["signals"] = self.signals
        return result
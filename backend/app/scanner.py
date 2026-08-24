import ipaddress
import shutil
import subprocess
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory

from .config import settings


@dataclass
class ServiceObservation:
    port: int
    protocol: str
    state: str
    name: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None


@dataclass
class HostObservation:
    ip_address: str
    mac_address: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    device_type: str = "unknown"
    os_family: str | None = None
    os_confidence: float | None = None
    discovery_sources: list[str] = field(default_factory=lambda: ["nmap"])
    services: list[ServiceObservation] = field(default_factory=list)


class ScanStopped(Exception):
    pass


def validate_authorized_subnet(value: str) -> str:
    requested = ipaddress.ip_network(value, strict=False)
    if requested.version != 4:
        raise ValueError("Layer 1 currently supports authorized IPv4 subnets only")
    allowed = [ipaddress.ip_network(item, strict=False) for item in settings.allowed_subnets]
    if not any(requested.subnet_of(scope) for scope in allowed):
        raise ValueError(f"Subnet {requested} is outside SCAN_ALLOWED_SUBNETS")
    return str(requested)


def ensure_nmap() -> str:
    resolved = shutil.which(settings.nmap_path)
    if not resolved:
        candidates = (
            Path("C:/Program Files (x86)/Nmap/nmap.exe"),
            Path("C:/Program Files/Nmap/nmap.exe"),
        )
        resolved = next((str(path) for path in candidates if path.exists()), None)
    if not resolved:
        raise RuntimeError("Nmap was not found. Install Nmap or set NMAP_PATH to nmap.exe")
    return resolved


def _run_nmap(arguments: list[str], output: Path, stop_event: threading.Event) -> None:
    command = [ensure_nmap(), *arguments, "-oX", str(output)]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        while process.poll() is None:
            if stop_event.wait(0.25):
                process.terminate()
                raise ScanStopped()
        stderr = process.stderr.read() if process.stderr else ""
        if process.returncode != 0:
            raise RuntimeError(stderr.strip() or f"Nmap exited with code {process.returncode}")
    finally:
        if process.poll() is None:
            process.kill()


def _host_identity(host: ET.Element) -> HostObservation | None:
    if host.find("status") is None or host.find("status").get("state") != "up":
        return None
    addresses = {node.get("addrtype"): node for node in host.findall("address")}
    ipv4 = addresses.get("ipv4")
    if ipv4 is None or not ipv4.get("addr"):
        return None
    mac = addresses.get("mac")
    hostname_node = host.find("hostnames/hostname")
    return HostObservation(
        ip_address=ipv4.get("addr"),
        mac_address=mac.get("addr") if mac is not None else None,
        vendor=mac.get("vendor") if mac is not None else None,
        hostname=hostname_node.get("name") if hostname_node is not None else None,
    )


def parse_discovery_xml(path: Path) -> list[HostObservation]:
    return [item for host in ET.parse(path).getroot().findall("host") if (item := _host_identity(host))]


def _classify(os_family: str | None, services: list[ServiceObservation]) -> str:
    names = {service.name for service in services}
    if names & {"ipp", "printer", "jetdirect"}: return "printer"
    if names & {"router", "upnp"} or (os_family and "router" in os_family.lower()): return "router"
    if names & {"microsoft-ds", "rdp"} or (os_family and "windows" in os_family.lower()): return "PC"
    if names & {"ssh", "http", "https", "mysql", "postgresql"}: return "server"
    return "unknown"


def enrich_from_fingerprint_xml(path: Path, hosts: list[HostObservation]) -> None:
    by_ip = {host.ip_address: host for host in hosts}
    for node in ET.parse(path).getroot().findall("host"):
        parsed = _host_identity(node)
        if not parsed or parsed.ip_address not in by_ip: continue
        target = by_ip[parsed.ip_address]
        target.hostname = parsed.hostname or target.hostname
        for port_node in node.findall("ports/port"):
            state = port_node.find("state")
            if state is None or state.get("state") != "open": continue
            service = port_node.find("service")
            cpe = service.findtext("cpe") if service is not None else None
            target.services.append(ServiceObservation(
                port=int(port_node.get("portid")), protocol=port_node.get("protocol", "tcp"), state="open",
                name=service.get("name") if service is not None else None,
                product=service.get("product") if service is not None else None,
                version=service.get("version") if service is not None else None, cpe=cpe,
            ))
        osmatch = node.find("os/osmatch")
        if osmatch is not None:
            osclass = osmatch.find("osclass")
            target.os_family = (osclass.get("osfamily") if osclass is not None else None) or osmatch.get("name")
            target.os_confidence = int(osmatch.get("accuracy", "0")) / 100
        target.device_type = _classify(target.os_family, target.services)


def scan_two_pass(subnet: str, stop_event: threading.Event) -> list[HostObservation]:
    with TemporaryDirectory(prefix="secureops-scan-") as directory:
        discovery_xml = Path(directory) / "discovery.xml"
        fingerprint_xml = Path(directory) / "fingerprint.xml"
        _run_nmap(["-sn", "-n", subnet], discovery_xml, stop_event)
        hosts = parse_discovery_xml(discovery_xml)
        if not hosts: return []
        targets = [host.ip_address for host in hosts]
        arguments = ["-sV", "--version-light", "-T4", "--host-timeout", "90s"]
        if settings.enable_os_detection: arguments.append("-O")
        _run_nmap([*arguments, *targets], fingerprint_xml, stop_event)
        enrich_from_fingerprint_xml(fingerprint_xml, hosts)
        return hosts

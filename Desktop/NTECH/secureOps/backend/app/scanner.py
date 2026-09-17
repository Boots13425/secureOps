import ipaddress
import re
import shutil
import socket
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from concurrent.futures import ThreadPoolExecutor

from .config import settings
from .network import connected_ipv4_networks, current_default_network


@dataclass
class ServiceObservation:
    port: int
    protocol: str
    state: str
    name: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None
    detection_source: str = "nmap_service_probe"
    confidence: str = "low"
    confidence_score: float | None = None
    enrichment_status: str = "not_enriched"
    service_id: str | None = None
    is_new: bool = False


@dataclass
class ExposureCheckObservation:
    check_id: str
    port: int | None
    protocol: str | None
    status: str
    output: str | None = None
    structured_output: dict = field(default_factory=dict)
    check_run_id: str | None = None


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
    exposure_checks: list[ExposureCheckObservation] = field(default_factory=list)
    asset_id: str | None = None
    is_new_asset: bool = False


class ScanStopped(Exception):
    pass


def validate_authorized_subnet(value: str | None = None) -> str:
    configured_default = settings.default_subnet.strip().lower()
    if not value or value.strip().lower() == "auto":
        requested = current_default_network()
    else:
        requested = ipaddress.ip_network(value, strict=False)
    if requested.version != 4:
        raise ValueError("Layer 1 currently supports authorized IPv4 subnets only")
    auto_allowed = any(item.lower() == "auto" for item in settings.allowed_subnets)
    allowed = [ipaddress.ip_network(item, strict=False) for item in settings.allowed_subnets if item.lower() != "auto"]
    if configured_default != "auto":
        allowed.append(ipaddress.ip_network(configured_default, strict=False))
    if auto_allowed:
        allowed.extend(connected_ipv4_networks())
    if not any(requested.subnet_of(scope) for scope in allowed):
        raise ValueError(f"Subnet {requested} is not a currently connected or explicitly allowed private network")
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
        started = time.monotonic()
        while process.poll() is None:
            if stop_event.wait(0.25):
                process.terminate()
                raise ScanStopped()
            if time.monotonic() - started > settings.scan_timeout_seconds:
                process.terminate()
                raise RuntimeError(f"Nmap exceeded the {settings.scan_timeout_seconds}-second scan timeout")
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


def _service_os_evidence(services: list[ServiceObservation]) -> tuple[str | None, float | None]:
    """Use only explicit product/CPE evidence; never turn a generic open port into an OS claim."""
    evidence = " ".join(
        filter(None, (value for service in services for value in (service.product, service.cpe)))
    ).lower()
    if "microsoft" in evidence or "windows" in evidence:
        return "Windows", 0.65
    if "linux" in evidence:
        return "Linux", 0.60
    if "android" in evidence:
        return "Android", 0.60
    if "apple" in evidence or "mac os" in evidence or "macos" in evidence:
        return "Apple", 0.60
    return None, None


def _resolve_device_name(ip_address: str) -> str | None:
    """Layered best-effort resolution; absence remains unknown."""
    try:
        local_name = socket.gethostname()
        local_addresses = {
            item[4][0] for item in socket.getaddrinfo(local_name, None, family=socket.AF_INET)
        }
        if ip_address in local_addresses:
            return local_name
    except OSError:
        pass
    try:
        name = socket.gethostbyaddr(ip_address)[0].rstrip(".")
        if name and name != ip_address:
            return name
    except OSError:
        pass
    if shutil.which("nbtstat"):
        try:
            result = subprocess.run(
                ["nbtstat", "-A", ip_address], capture_output=True, text=True,
                timeout=2, check=False, encoding="utf-8", errors="replace",
            )
            for line in result.stdout.splitlines():
                match = re.match(r"\s*(\S.*?)\s+<00>\s+UNIQUE", line, re.IGNORECASE)
                if match:
                    return match.group(1).strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
    return None


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
            confidence_value = int(service.get("conf", "0")) if service is not None else 0
            confidence = "high" if confidence_value >= 8 else "medium" if confidence_value >= 5 else "low"
            method = service.get("method") if service is not None else None
            target.services.append(ServiceObservation(
                port=int(port_node.get("portid")), protocol=port_node.get("protocol", "tcp"), state="open",
                name=service.get("name") if service is not None else None,
                product=service.get("product") if service is not None else None,
                version=service.get("version") if service is not None else None, cpe=cpe,
                detection_source="nmap_service_probe" if method == "probed" else "nmap_service_table",
                confidence=confidence, confidence_score=confidence_value / 10,
                enrichment_status="cpe_ready" if cpe and confidence != "low" else "not_enriched",
            ))
        osmatch = node.find("os/osmatch")
        if osmatch is not None:
            osclass = osmatch.find("osclass")
            target.os_family = (osclass.get("osfamily") if osclass is not None else None) or osmatch.get("name")
            target.os_confidence = int(osmatch.get("accuracy", "0")) / 100
        if not target.os_family:
            target.os_family, target.os_confidence = _service_os_evidence(target.services)
        target.device_type = _classify(target.os_family, target.services)


def discover_hosts(subnet: str, stop_event: threading.Event) -> list[HostObservation]:
    with TemporaryDirectory(prefix="secureops-scan-") as directory:
        discovery_xml = Path(directory) / "discovery.xml"
        # ARP is both the fastest and most reliable discovery mechanism for
        # devices on the same local broadcast segment. Name resolution runs
        # separately and in parallel with fingerprinting below.
        _run_nmap(["-sn", "-PR", "-n", "--max-retries", "1", "-T4", subnet], discovery_xml, stop_event)
        return parse_discovery_xml(discovery_xml)


def fingerprint_hosts(hosts: list[HostObservation], stop_event: threading.Event) -> list[HostObservation]:
    if not hosts:
        return hosts
    with TemporaryDirectory(prefix="secureops-fingerprint-") as directory:
        targets = [host.ip_address for host in hosts]
        # Name lookup runs while Nmap fingerprints ports, so it adds no normal
        # wall-clock delay to the scan.
        resolver_pool = ThreadPoolExecutor(max_workers=min(16, len(hosts)))
        name_futures = {host.ip_address: resolver_pool.submit(_resolve_device_name, host.ip_address) for host in hosts}
        base_arguments = [
            "-sV", "--version-light", "--top-ports", str(settings.fingerprint_top_ports),
            "-T4", "--max-retries", "0", "--host-timeout", f"{settings.host_timeout_seconds}s",
        ]
        if settings.enable_os_detection:
            base_arguments.extend(["-O", "--osscan-limit", "--osscan-guess"])
        try:
            def fingerprint(target: str) -> Path:
                output = Path(directory) / f"fingerprint-{target.replace('.', '-')}.xml"
                _run_nmap([*base_arguments, target], output, stop_event)
                return output

            with ThreadPoolExecutor(max_workers=min(settings.parallel_fingerprint_hosts, len(targets))) as fingerprint_pool:
                for output in fingerprint_pool.map(fingerprint, targets):
                    enrich_from_fingerprint_xml(output, hosts)
            for host in hosts:
                if host.hostname:
                    continue
                try:
                    host.hostname = name_futures[host.ip_address].result(timeout=0.1)
                except TimeoutError:
                    pass
        finally:
            resolver_pool.shutdown(wait=False, cancel_futures=True)
        return hosts


def scan_two_pass(subnet: str, stop_event: threading.Event) -> list[HostObservation]:
    hosts = discover_hosts(subnet, stop_event)
    return fingerprint_hosts(hosts, stop_event)


APPROVED_EXPOSURE_SCRIPTS = frozenset({"smb-protocols", "ftp-anon", "ssl-cert", "rdp-enum-encryption"})
TLS_PORTS = {443, 465, 636, 853, 989, 990, 992, 993, 995, 8443, 9443}


def _approved_checks_for(host: HostObservation) -> dict[str, set[int]]:
    selected: dict[str, set[int]] = {}
    for service in host.services:
        name = (service.name or "").lower()
        if service.port in {139, 445}:
            selected.setdefault("smb-protocols", set()).add(service.port)
        if service.port == 21 or name == "ftp":
            selected.setdefault("ftp-anon", set()).add(service.port)
        if service.port in TLS_PORTS or name in {"https", "ssl", "ssl/http", "https-alt"}:
            selected.setdefault("ssl-cert", set()).add(service.port)
        if service.port == 3389 or name in {"ms-wbt-server", "rdp"}:
            selected.setdefault("rdp-enum-encryption", set()).add(service.port)
    return selected


def _xml_element_data(element: ET.Element):
    children = list(element)
    if not children:
        return element.text or ""
    result = {}
    for child in children:
        key = child.get("key") or child.tag
        value = _xml_element_data(child)
        if key in result:
            result[key] = result[key] if isinstance(result[key], list) else [result[key]]
            result[key].append(value)
        else:
            result[key] = value
    return result


def parse_exposure_check_xml(path: Path, host: HostObservation) -> None:
    root = ET.parse(path).getroot()
    returned = set()
    for port_node in root.findall("host/ports/port"):
        port = int(port_node.get("portid"))
        protocol = port_node.get("protocol", "tcp")
        for script in port_node.findall("script"):
            check_id = script.get("id")
            if check_id not in APPROVED_EXPOSURE_SCRIPTS:
                continue
            returned.add((check_id, port))
            host.exposure_checks.append(ExposureCheckObservation(
                check_id=check_id, port=port, protocol=protocol, status="completed",
                output=script.get("output"), structured_output=_xml_element_data(script),
            ))
    # smb-protocols is a hostrule script — Nmap attaches its output under
    # <hostscript>, not any <port>, because SMB dialect negotiation isn't tied
    # to one port. Without this, the check always falls through to "no_result"
    # below and findings.py never evaluates its output (it skips non-completed
    # checks), so SMBv1 would silently never be detected on a live scan.
    expected = _approved_checks_for(host)
    for script in root.findall("host/hostscript/script"):
        check_id = script.get("id")
        if check_id not in APPROVED_EXPOSURE_SCRIPTS:
            continue
        for port in expected.get(check_id, set()):
            returned.add((check_id, port))
            host.exposure_checks.append(ExposureCheckObservation(
                check_id=check_id, port=port, protocol="tcp", status="completed",
                output=script.get("output"), structured_output=_xml_element_data(script),
            ))
    for check_id, ports in expected.items():
        for port in ports:
            if (check_id, port) not in returned:
                host.exposure_checks.append(ExposureCheckObservation(
                    check_id=check_id, port=port, protocol="tcp", status="no_result",
                    output="Approved check completed without script output.",
                ))


def run_exposure_checks(hosts: list[HostObservation], stop_event: threading.Event) -> list[HostObservation]:
    if not settings.exposure_checks_enabled:
        return hosts
    eligible = [(host, _approved_checks_for(host)) for host in hosts]
    eligible = [(host, checks) for host, checks in eligible if checks]
    if not eligible:
        return hosts
    with TemporaryDirectory(prefix="secureops-exposure-") as directory:
        def check_host(item):
            host, checks = item
            scripts = sorted(checks)
            if not set(scripts).issubset(APPROVED_EXPOSURE_SCRIPTS):
                raise RuntimeError("An unapproved Nmap exposure script was requested")
            ports = sorted({port for selected in checks.values() for port in selected})
            output = Path(directory) / f"exposure-{host.ip_address.replace('.', '-')}.xml"
            arguments = [
                "-Pn", "-n", "-sT", "--script", ",".join(scripts), "-p", ",".join(map(str, ports)),
                "--script-timeout", "15s", "--host-timeout", f"{settings.exposure_check_timeout_seconds}s",
                "--max-retries", "0", "-T4", host.ip_address,
            ]
            _run_nmap(arguments, output, stop_event)
            parse_exposure_check_xml(output, host)

        with ThreadPoolExecutor(max_workers=min(settings.parallel_exposure_hosts, len(eligible))) as pool:
            list(pool.map(check_host, eligible))
    return hosts

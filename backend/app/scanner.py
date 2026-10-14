import ipaddress
import logging
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
from .identification import classify_device
from .network import connected_ipv4_networks, current_default_network, interface_for_target, local_subnet_contains

log = logging.getLogger("secureops.scanner")


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
    # Layer 1 accuracy: tag each field with the source that supplied it
    # ("snmp", "dhcp_lease", "reverse_dns", "netbios", "mdns", "nmap_heuristic")
    # plus a full provenance map so admins can inspect all competing values.
    hostname_source: str | None = None
    vendor_source: str | None = None
    os_source: str | None = None
    device_type_source: str | None = None
    identification_provenance: dict = field(default_factory=dict)
    discovery_sources: list[str] = field(default_factory=lambda: ["nmap"])
    services: list[ServiceObservation] = field(default_factory=list)
    exposure_checks: list[ExposureCheckObservation] = field(default_factory=list)
    asset_id: str | None = None
    is_new_asset: bool = False
    # Set when no hostname could be established, so the UI can explain *why*
    # instead of just showing "Unknown". None when a name was resolved or when
    # the device is local and every applicable method was simply tried.
    hostname_unresolved_reason: str | None = None


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
    log.info("nmap command: %s", " ".join(command))
    # Check if running with admin/raw-socket privileges (required for -PR ARP scan)
    import os
    has_admin = False
    try:
        has_admin = os.getuid() == 0  # Unix/Linux
    except AttributeError:
        # Windows: check if running as admin
        try:
            import ctypes
            has_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            has_admin = False
    log.info("nmap running with admin/raw-socket privileges: %s", has_admin)
    
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        started = time.monotonic()
        while process.poll() is None:
            if stop_event.wait(0.25):
                process.terminate()
                raise ScanStopped()
            if time.monotonic() - started > settings.scan_timeout_seconds:
                process.terminate()
                raise RuntimeError(f"Nmap exceeded the {settings.scan_timeout_seconds}-second scan timeout")
        stdout, stderr = process.communicate()
        elapsed = time.monotonic() - started
        log.info("nmap completed in %.2fs, returncode=%d", elapsed, process.returncode)
        if stderr:
            log.info("nmap stderr: %s", stderr.strip())
        if stdout:
            log.debug("nmap stdout (first 500 chars): %s", stdout[:500])
        if process.returncode != 0:
            raise RuntimeError(stderr.strip() or f"Nmap exited with code {process.returncode}")
    finally:
        if process.poll() is None:
            process.kill()
        # Fully reap the process before returning. terminate()/kill() are
        # asynchronous on Windows, and the caller's TemporaryDirectory cleanup
        # deletes nmap's -oX file. If nmap still holds that handle the rmtree
        # raises WinError 32, which masks the real scan error (e.g. the scan
        # timeout) and reports a confusing file-lock failure instead.
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


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


def _classify(host: HostObservation) -> str:
    """Device type from OS/vendor evidence first, open ports only as a fallback.

    SSH/HTTPS/HTTP are management interfaces on switches, routers and firewalls
    just as much as on servers, so the port heuristic can no longer decide a
    device that has already told us it runs network-infrastructure firmware.
    """
    return classify_device(
        os_family=host.os_family,
        hostname=host.hostname,
        vendor=host.vendor,
        service_names=[service.name for service in host.services],
    ).device_type


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


def _local_networks() -> list:
    """Networks the scanner itself is attached to, from its own interfaces.

    Used to decide which name-resolution methods are even worth attempting:
    NetBIOS and mDNS are both confined to the local broadcast domain, so on a
    remote segment they cannot answer and only cost the full timeout.
    """
    networks = []
    try:
        import psutil
        for addresses in psutil.net_if_addrs().values():
            for entry in addresses:
                if entry.family != socket.AF_INET or not entry.netmask:
                    continue
                try:
                    networks.append(ipaddress.ip_network(
                        f"{entry.address}/{entry.netmask}", strict=False))
                except ValueError:
                    continue
    except Exception:
        pass
    if not networks:
        # Fall back to a /24 assumption per local address rather than treating
        # every host as remote and silently disabling name resolution.
        try:
            for item in socket.getaddrinfo(socket.gethostname(), None, family=socket.AF_INET):
                networks.append(ipaddress.ip_network(f"{item[4][0]}/24", strict=False))
        except OSError:
            pass
    return networks


_LOCAL_NETWORKS = None

# Extra wall-clock allowed for a killed nbtstat process to be reaped on
# Windows. The subprocess timeout is the intended budget; this is only the
# slack before the result is abandoned, so a wedged child cannot stall a scan.
NETBIOS_REAP_GRACE_SECONDS = 1.0


def is_local_target(ip_address: str) -> bool:
    """True when the address shares a subnet with one of our interfaces."""
    global _LOCAL_NETWORKS
    if _LOCAL_NETWORKS is None:
        _LOCAL_NETWORKS = _local_networks()
    try:
        address = ipaddress.ip_address(ip_address)
    except ValueError:
        return False
    return any(address in network for network in _LOCAL_NETWORKS)


def _resolve_device_name(ip_address: str) -> tuple[str | None, str | None]:
    """Layered best-effort resolution; absence remains unknown.
    
    Returns (hostname, source) where source is 'reverse_dns', 'netbios', or None.
    """
    # First check if this is one of our own local addresses - if so, return our hostname
    try:
        local_name = socket.gethostname()
        local_addresses = {
            item[4][0] for item in socket.getaddrinfo(local_name, None, family=socket.AF_INET)
        }
        if ip_address in local_addresses:
            return local_name, "local"
    except OSError:
        pass
    # Reverse DNS is unicast and works across subnets, so it is always tried.
    # BUT: do not return our own hostname for remote addresses. If reverse DNS
    # returns our hostname for a remote IP, treat it as unresolved (likely DNS
    # misconfiguration or PTR record pointing to us).
    try:
        name = socket.gethostbyaddr(ip_address)[0].rstrip(".")
        if name and name != ip_address:
            # If the reverse DNS name matches our own hostname, discard it for remote IPs
            try:
                if name == socket.gethostname():
                    return None, None
            except OSError:
                pass
            return name, "reverse_dns"
    except OSError:
        pass
    # NetBIOS is opt-in: see settings.netbios_name_resolution_enabled. It is
    # also local-broadcast only, so it is never attempted for a remote device.
    if not settings.netbios_name_resolution_enabled or not is_local_target(ip_address):
        return None, None
    name = _netbios_name(ip_address)
    if name:
        return name, "netbios"
    return None, None


def _netbios_name(ip_address: str) -> str | None:
    """NetBIOS name lookup, bounded by an explicit wall-clock budget.

    subprocess.run(timeout=...) is not sufficient here on Windows. Measured on
    this host, TerminateProcess returned at the 2s timeout but the process
    handle was not signalled until ~9s, because the child was blocked in the
    NetBIOS/BROWSER kernel call. The reap is therefore done on a helper thread
    with its own deadline, so a wedged lookup can never hold up the caller for
    more than the configured budget.
    """
    if not shutil.which("nbtstat"):
        return None
    budget = settings.netbios_timeout_seconds
    box: dict = {}

    def _run():
        try:
            result = subprocess.run(
                ["nbtstat", "-A", ip_address], capture_output=True, text=True,
                timeout=budget, check=False, encoding="utf-8", errors="replace",
            )
            box["stdout"] = result.stdout
        except (OSError, subprocess.TimeoutExpired):
            pass

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    worker.join(timeout=budget + NETBIOS_REAP_GRACE_SECONDS)
    if worker.is_alive():
        # Give up on the result rather than block the scan; the lookup almost
        # always yields nothing, so losing it costs nothing measurable.
        return None
    for line in (box.get("stdout") or "").splitlines():
        match = re.match(r"\s*(\S.*?)\s+<00>\s+UNIQUE", line, re.IGNORECASE)
        if match:
            return match.group(1).strip()
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
        target.device_type = _classify(target)


def discover_hosts(subnet: str, stop_event: threading.Event, remote: bool | None = None, include_infrastructure: list[str] | None = None) -> list[HostObservation]:
    """Host discovery for one subnet.

    `remote` swaps ARP for ICMP + TCP ping probes. ARP only works on the local
    broadcast segment, so asking a router for a VLAN on another subnet with -PR
    would return nothing at all and be indistinguishable from an empty network.
    The same parser, fingerprinting and enrichment run either way, so this is
    the only place that differs between a local and a cross-network scan.
    """
    if remote is None:
        # Default to the subnet being local, so existing callers are unchanged.
        try:
            remote = not any(ipaddress.ip_address(host).version == 4 and
                             ipaddress.ip_address(host) in ipaddress.ip_network(subnet, strict=False)
                             for host in _local_networks_addresses())
        except ValueError:
            remote = False

    # Determine which interface routes to the target subnet
    iface_info = interface_for_target(subnet)
    if iface_info:
        iface_name, source_ip = iface_info
        log.info("discover_hosts: subnet=%s, remote=%s, using interface=%s source_ip=%s", subnet, remote, iface_name, source_ip)
    else:
        log.warning("discover_hosts: subnet=%s, remote=%s, no route found", subnet, remote)
        iface_name, source_ip = None, None

    log.info("discover_hosts: subnet=%s, remote=%s", subnet, remote)
    with TemporaryDirectory(prefix="secureops-scan-") as directory:
        discovery_xml = Path(directory) / "discovery.xml"
        
        # Build nmap arguments with interface binding for remote scans
        if remote:
            # -PE: ICMP echo. -PS: TCP SYN to common ports, which finds hosts
            # that drop or rate-limit ICMP (a lot of appliances and firewalls).
            # -T4 with aggressive parallelism for remote sweeps - the default
            # parallelism is too slow for a full /24. --min-hostgroup and
            # --max-parallelism ensure we probe many hosts concurrently instead
            # of waiting for timeouts sequentially.
            arguments = ["-sn", "-n", "-PE", "-PS22,80,443,445,3389",
                         "--max-retries", "1", "--host-timeout",
                         f"{settings.host_timeout_seconds}s",
                         "--min-hostgroup", "64",
                         "--max-parallelism", "64",
                         "-T4"]
        else:
            # ARP is both the fastest and most reliable discovery mechanism for
            # devices on the same local broadcast segment. Name resolution runs
            # separately and in parallel with fingerprinting below.
            arguments = ["-sn", "-PR", "-n", "--max-retries", "1", "-T4"]
        
        # Add interface binding if available
        if iface_name:
            arguments.extend(["-e", iface_name])
            # Also set source IP to be explicit
            arguments.extend(["-S", source_ip])
        
        arguments.append(subnet)
        
        _run_nmap(arguments, discovery_xml, stop_event)
        hosts = parse_discovery_xml(discovery_xml)
        log.info("discover_hosts: found %d hosts up in %s", len(hosts), subnet)
        for h in hosts:
            log.info("  host: ip=%s, mac=%s, hostname=%s", h.ip_address, h.mac_address, h.hostname)
        
        # Add infrastructure hosts if they weren't discovered
        if include_infrastructure:
            existing_ips = {h.ip_address for h in hosts}
            for ip in include_infrastructure:
                if ip not in existing_ips:
                    log.info("discover_hosts: adding infrastructure host %s", ip)
                    hosts.append(HostObservation(
                        ip_address=ip,
                        mac_address=None,
                        vendor=None,
                        hostname=None,
                        device_type="unknown",
                        discovery_sources=["infrastructure"],
                    ))
        return hosts


def _local_networks_addresses() -> list[str]:
    """Network addresses of the scanner's own attached networks."""
    return [str(network.network_address) for network in _local_networks()]


def _port_counts_from_xml(path: Path) -> dict[str, tuple[int, int]]:
    """Return {ip: (open_count, closed_count)} from a fingerprint XML."""
    counts: dict[str, tuple[int, int]] = {}
    try:
        for node in ET.parse(path).getroot().findall("host"):
            ident = _host_identity(node)
            if not ident:
                continue
            open_ports = 0
            closed_ports = 0
            for port_node in node.findall("ports/port"):
                state = port_node.find("state")
                st = state.get("state") if state is not None else None
                if st == "open":
                    open_ports += 1
                elif st == "closed":
                    closed_ports += 1
            counts[ident.ip_address] = (open_ports, closed_ports)
    except Exception:
        pass
    return counts


def _enrich_os_from_xml(path: Path, hosts: list[HostObservation]) -> None:
    by_ip = {host.ip_address: host for host in hosts}
    try:
        for node in ET.parse(path).getroot().findall("host"):
            ident = _host_identity(node)
            if not ident or ident.ip_address not in by_ip:
                continue
            target = by_ip[ident.ip_address]
            osmatch = node.find("os/osmatch")
            if osmatch is not None:
                osclass = osmatch.find("osclass")
                target.os_family = (osclass.get("osfamily") if osclass is not None else None) or osmatch.get("name")
                target.os_confidence = int(osmatch.get("accuracy", "0")) / 100
                # OS detection can reveal network-infrastructure firmware the
                # service probe missed, so the type is re-derived from it.
                target.device_type = _classify(target)
    except Exception:
        pass


def fingerprint_hosts(hosts: list[HostObservation], stop_event: threading.Event) -> list[HostObservation]:
    if not hosts:
        return hosts
    with TemporaryDirectory(prefix="secureops-fingerprint-") as directory:
        targets = [host.ip_address for host in hosts]
        resolver_pool = ThreadPoolExecutor(max_workers=min(16, len(hosts)))
        name_futures = {host.ip_address: resolver_pool.submit(_resolve_device_name, host.ip_address) for host in hosts}
        base_arguments = [
            "-sV", "--version-light", "--top-ports", str(settings.fingerprint_top_ports),
            "-T4", "--max-retries", "0", "--host-timeout", f"{settings.host_timeout_seconds}s",
        ]
        port_stats: dict[str, tuple[int, int]] = {}
        try:
            def fingerprint(target: str) -> Path:
                output = Path(directory) / f"fingerprint-{target.replace('.', '-')}.xml"
                
                # Determine interface for this specific target
                iface_info = interface_for_target(target)
                fp_args = list(base_arguments)
                if iface_info:
                    iface_name, source_ip = iface_info
                    fp_args.extend(["-e", iface_name, "-S", source_ip])
                
                fp_args.append(target)
                _run_nmap(fp_args, output, stop_event)
                return output

            with ThreadPoolExecutor(max_workers=min(settings.parallel_fingerprint_hosts, len(targets))) as fingerprint_pool:
                _fp_started = time.monotonic()
                for output in fingerprint_pool.map(fingerprint, targets):
                    enrich_from_fingerprint_xml(output, hosts)
                    port_stats.update(_port_counts_from_xml(output))
                logging.getLogger("secureops.scan").info(
                    "    nmap -sV: %d host(s), %d workers, %.2fs",
                    len(targets), min(settings.parallel_fingerprint_hosts, len(targets)), time.monotonic() - _fp_started)

            for host in hosts:
                if host.hostname:
                    continue
                try:
                    name, source = name_futures[host.ip_address].result(timeout=0.1)
                    if name:
                        host.hostname = name
                        host.hostname_source = source
                except TimeoutError:
                    pass
                # A resolved hostname can carry an infrastructure naming prefix
                # that the port heuristic never would have seen.
                host.device_type = _classify(host)

            # Requirement 3: Selective, targeted Nmap OS detection.
            # Instead of running -O broadly with --osscan-guess (noisy/low confidence),
            # only run -O against hosts that meet Nmap's own documented precondition:
            # at least one open AND one closed TCP port. Skip all others.
            if settings.enable_os_detection:
                if settings.selective_os_detection:
                    qualified = [
                        ip for ip, (open_c, closed_c) in port_stats.items()
                        if open_c >= 1 and closed_c >= 1
                    ]
                    os_args = ["-O", "--osscan-limit"]  # No --osscan-guess: reliable matches only
                else:
                    qualified = targets
                    os_args = ["-O", "--osscan-limit", "--osscan-guess"]

                if qualified:
                    def os_scan(target: str) -> Path:
                        out = Path(directory) / f"os-{target.replace('.', '-')}.xml"
                        os_scan_args = list(os_args)
                        iface_info = interface_for_target(target)
                        if iface_info:
                            iface_name, source_ip = iface_info
                            os_scan_args.extend(["-e", iface_name, "-S", source_ip])
                        os_scan_args.extend(["-T4", "--max-retries", "0",
                                           "--host-timeout", f"{settings.host_timeout_seconds}s", target])
                        _run_nmap(os_scan_args, out, stop_event)
                        return out

                    with ThreadPoolExecutor(max_workers=min(settings.parallel_fingerprint_hosts, len(qualified))) as os_pool:
                        _os_started = time.monotonic()
                        for out in os_pool.map(os_scan, qualified):
                            _enrich_os_from_xml(out, hosts)
                        logging.getLogger("secureops.scan").info(
                            "    nmap -O: %d of %d host(s) qualified, %.2fs",
                            len(qualified), len(targets), time.monotonic() - _os_started)

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
            
            # Determine interface for this target
            iface_info = interface_for_target(host.ip_address)
            arguments = [
                "-Pn", "-n", "-sT", "--script", ",".join(scripts), "-p", ",".join(map(str, ports)),
                "--script-timeout", "15s", "--host-timeout", f"{settings.exposure_check_timeout_seconds}s",
                "--max-retries", "0", "-T4",
            ]
            if iface_info:
                iface_name, source_ip = iface_info
                arguments.extend(["-e", iface_name, "-S", source_ip])
            arguments.append(host.ip_address)
            
            try:
                _run_nmap(arguments, output, stop_event)
                parse_exposure_check_xml(output, host)
            except ScanStopped:
                raise
            except Exception as exc:
                for check_id, ports in checks.items():
                    for port in ports:
                        host.exposure_checks.append(ExposureCheckObservation(
                            check_id=check_id, port=port, protocol="tcp", status="failed",
                            output=f"Approved exposure check failed: {str(exc)[:1000]}",
                        ))

        with ThreadPoolExecutor(max_workers=min(settings.parallel_exposure_hosts, len(eligible))) as pool:
            list(pool.map(check_host, eligible))
    return hosts

import ipaddress
import re
import socket
import subprocess

import psutil


class NetworkDetectionError(ValueError):
    pass


def _nmap_interface_map() -> dict[str, str]:
    """Return mapping of source_ip -> nmap_interface_short_name (e.g., 'eth0').

    Parses `nmap --iflist` output to find which nmap interface (eth0, eth1, etc.)
    has which IP address.
    """
    try:
        result = subprocess.run(["nmap", "--iflist"], capture_output=True, text=True, timeout=10)
        output = result.stdout
    except Exception:
        return {}

    ip_to_iface = {}
    current_iface = None
    for line in output.splitlines():
        line = line.strip()
        # Match nmap interface lines like: eth0 (eth0)  172.16.1.2/24  ethernet down 1500  4C:D7:17:08:BC:D7
        m = re.match(r'^(eth\d+)\s+\(eth\d+\)\s+(\S+/\d+)\s+\w+', line)
        if m:
            iface = m.group(1)
            ip_cidr = m.group(2)
            ip = ip_cidr.split('/')[0]
            ip_to_iface[ip] = iface
    return ip_to_iface


def _default_route_address() -> str | None:
    """Ask the OS which local address it would use for a normal outbound route."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # UDP connect selects a route without sending application data.
        sock.connect(("1.1.1.1", 53))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def connected_ipv4_networks() -> list[ipaddress.IPv4Network]:
    """Return active, directly connected private IPv4 networks, default first."""
    default_address = _default_route_address()
    candidates: list[tuple[bool, ipaddress.IPv4Network]] = []
    stats = psutil.net_if_stats()
    for interface, addresses in psutil.net_if_addrs().items():
        if interface in stats and not stats[interface].isup:
            continue
        for address in addresses:
            if address.family != socket.AF_INET or not address.netmask:
                continue
            ip = ipaddress.ip_address(address.address)
            network = ipaddress.ip_interface(f"{address.address}/{address.netmask}").network
            if ip.is_loopback or ip.is_link_local or not ip.is_private or network.prefixlen >= 31:
                continue
            candidates.append((address.address == default_address, network))
    ordered = sorted(candidates, key=lambda item: (not item[0], -item[1].prefixlen, str(item[1])))
    return list(dict.fromkeys(network for _, network in ordered))


def current_default_network() -> ipaddress.IPv4Network:
    networks = connected_ipv4_networks()
    if not networks:
        raise NetworkDetectionError("No active private IPv4 network with a usable subnet was detected")
    return networks[0]


def interface_for_target(target_subnet: str | ipaddress.IPv4Network) -> tuple[str, str] | None:
    """Return (nmap_interface_name, source_ip) for the adapter that routes to target_subnet.

    Uses the system routing table to determine which interface would be used to reach
    the target subnet, then maps it to nmap's short interface name (eth0, eth1, etc.).
    Returns None if no route found.
    """
    if isinstance(target_subnet, str):
        target_subnet = ipaddress.ip_network(target_subnet, strict=False)
    target_ip = target_subnet.network_address

    # Use UDP connect trick to let OS select the route
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((str(target_ip), 53))
        source_ip = sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()

    # Map source IP to nmap interface name
    nmap_iface_map = _nmap_interface_map()
    iface_name = nmap_iface_map.get(source_ip)
    if iface_name:
        return iface_name, source_ip

    # Fallback: try psutil interface name (works on Linux)
    for interface, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family == socket.AF_INET and address.address == source_ip:
                return interface, source_ip
    return None


def local_subnet_contains(target_subnet: str | ipaddress.IPv4Network) -> bool:
    """Check if target_subnet is one of our directly connected networks."""
    if isinstance(target_subnet, str):
        target_subnet = ipaddress.ip_network(target_subnet, strict=False)
    for network in connected_ipv4_networks():
        if target_subnet.subnet_of(network) or network.subnet_of(target_subnet):
            if target_subnet.network_address == network.network_address:
                return True
    return False

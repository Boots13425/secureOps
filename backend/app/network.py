import ipaddress
import socket

import psutil


class NetworkDetectionError(ValueError):
    pass


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

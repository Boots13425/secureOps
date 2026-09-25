import unittest
import ipaddress
import threading
from pathlib import Path
from unittest.mock import patch

from app.scanner import HostObservation, ServiceObservation, _classify, enrich_from_fingerprint_xml, parse_discovery_xml, run_exposure_checks, validate_authorized_subnet


FIXTURES = Path(__file__).parent / "fixtures"


class ScannerXmlTests(unittest.TestCase):
    def test_two_pass_xml_is_structured_without_terminal_scraping(self):
        hosts = parse_discovery_xml(FIXTURES / "discovery.xml")
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].mac_address, "00:11:22:33:44:55")
        enrich_from_fingerprint_xml(FIXTURES / "fingerprint.xml", hosts)
        self.assertEqual(hosts[0].hostname, "lab-pc.local")
        self.assertEqual(hosts[0].device_type, "PC")
        self.assertEqual(hosts[0].os_family, "Windows")
        self.assertEqual(hosts[0].os_confidence, 0.92)
        self.assertEqual(hosts[0].services[0].port, 445)
        self.assertEqual(hosts[0].services[0].cpe, "cpe:/o:microsoft:windows_10")
        self.assertEqual(hosts[0].services[0].confidence, "high")
        self.assertEqual(hosts[0].services[0].confidence_score, 1.0)
        self.assertEqual(hosts[0].services[0].detection_source, "nmap_service_probe")
        self.assertEqual(hosts[0].services[0].enrichment_status, "cpe_ready")

    def test_subnet_scope_rejects_unauthorized_targets(self):
        connected = [ipaddress.ip_network("192.168.1.0/24")]
        with patch("app.scanner.connected_ipv4_networks", return_value=connected), patch("app.scanner.current_default_network", return_value=connected[0]):
            self.assertEqual(validate_authorized_subnet(), "192.168.1.0/24")
            self.assertEqual(validate_authorized_subnet("192.168.1.23/24"), "192.168.1.0/24")
            with self.assertRaises(ValueError): validate_authorized_subnet("8.8.8.0/24")

    def test_exposure_check_failure_is_attached_to_host(self):
        host = HostObservation(
            ip_address="192.168.1.10",
            services=[ServiceObservation(port=445, protocol="tcp", state="open", name="microsoft-ds")],
        )
        with patch("app.scanner._run_nmap", side_effect=RuntimeError("nmap script failed")):
            run_exposure_checks([host], threading.Event())
        self.assertEqual(len(host.exposure_checks), 1)
        self.assertEqual(host.exposure_checks[0].status, "failed")
        self.assertIn("nmap script failed", host.exposure_checks[0].output)


class DeviceClassificationTests(unittest.TestCase):
    def _host(self, **kwargs) -> HostObservation:
        return HostObservation(ip_address=kwargs.pop("ip_address", "172.16.1.10"), **kwargs)

    def test_cisco_ios_switch_behind_ssh_and_https_is_not_a_server(self):
        host = self._host(
            hostname="SW-NTECHCENTRAL", vendor="Cisco", os_family="Cisco IOS",
            services=[
                ServiceObservation(port=22, protocol="tcp", state="open", name="ssh"),
                ServiceObservation(port=443, protocol="tcp", state="open", name="https"),
            ],
        )
        self.assertEqual(_classify(host), "switch")

    def test_ambiguous_network_os_without_naming_falls_back_to_network_device(self):
        host = self._host(
            vendor="Cisco", os_family="Cisco IOS",
            services=[ServiceObservation(port=22, protocol="tcp", state="open", name="ssh")],
        )
        self.assertEqual(_classify(host), "network device")

    def test_plain_host_still_uses_the_port_heuristic(self):
        host = self._host(
            services=[ServiceObservation(port=22, protocol="tcp", state="open", name="ssh")],
        )
        self.assertEqual(_classify(host), "server")


if __name__ == "__main__": unittest.main()

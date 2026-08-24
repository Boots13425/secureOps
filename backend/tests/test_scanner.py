import unittest
import ipaddress
from pathlib import Path
from unittest.mock import patch

from app.scanner import enrich_from_fingerprint_xml, parse_discovery_xml, validate_authorized_subnet


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


if __name__ == "__main__": unittest.main()

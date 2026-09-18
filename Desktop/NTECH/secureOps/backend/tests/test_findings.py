import unittest
from datetime import datetime, timezone
from pathlib import Path

from app.findings import evaluate_host
from app.scanner import (
    APPROVED_EXPOSURE_SCRIPTS,
    ExposureCheckObservation,
    HostObservation,
    ServiceObservation,
    parse_exposure_check_xml,
)


FIXTURES = Path(__file__).parent / "fixtures"


class ExposureFindingTests(unittest.TestCase):
    def test_default_script_allowlist_is_small_and_non_intrusive(self):
        self.assertEqual(APPROVED_EXPOSURE_SCRIPTS, {"smb-protocols", "ftp-anon", "ssl-cert", "rdp-enum-encryption"})
        self.assertNotIn("ssl-enum-ciphers", APPROVED_EXPOSURE_SCRIPTS)

    def test_smbv1_xml_creates_evidence_backed_high_finding(self):
        service = ServiceObservation(port=445, protocol="tcp", state="open", name="microsoft-ds", service_id="service-1")
        host = HostObservation(ip_address="192.168.1.10", asset_id="asset-1", services=[service])
        parse_exposure_check_xml(FIXTURES / "exposure.xml", host)
        findings = evaluate_host(host, datetime(2026, 8, 25, tzinfo=timezone.utc))
        legacy = next(finding for finding in findings if finding.check_id == "smb-protocols")
        self.assertEqual(legacy.title, "Legacy SMB protocol detected")
        self.assertEqual(legacy.severity, "high")
        self.assertEqual(legacy.confidence, "high")
        self.assertIn("SMBv1 dialect", legacy.evidence)

    def test_observation_rules_do_not_invent_vulnerabilities(self):
        http = ServiceObservation(port=80, protocol="tcp", state="open", name="http", service_id="service-http")
        telnet = ServiceObservation(port=23, protocol="tcp", state="open", name="telnet", service_id="service-telnet")
        rdp = ServiceObservation(port=3389, protocol="tcp", state="open", name="ms-wbt-server", service_id="service-rdp")
        host = HostObservation(ip_address="192.168.1.20", asset_id="asset-2", services=[http, telnet, rdp])
        titles = {finding.title for finding in evaluate_host(host)}
        self.assertIn("Clear-text Telnet administration exposed", titles)
        self.assertIn("HTTP service exposed without observed HTTPS", titles)
        self.assertIn("Remote Desktop service exposed", titles)

    def test_valid_certificate_check_does_not_create_expiry_finding(self):
        tls = ServiceObservation(port=443, protocol="tcp", state="open", name="https", service_id="service-tls")
        check = ExposureCheckObservation(check_id="ssl-cert", port=443, protocol="tcp", status="completed", output="Not valid after: 2030-01-01T00:00:00")
        host = HostObservation(ip_address="192.168.1.30", asset_id="asset-3", services=[tls], exposure_checks=[check])
        self.assertEqual(evaluate_host(host, datetime(2026, 8, 25, tzinfo=timezone.utc)), [])


if __name__ == "__main__": unittest.main()

import unittest
from datetime import datetime, timezone

from app.nvd import cpe_query_profile, normalize_cpe, parse_nvd_cve, select_cvss


class NvdEnrichmentTests(unittest.TestCase):
    def test_nmap_cpe_uri_is_normalized_for_nvd_api_2(self):
        normalized = normalize_cpe("cpe:/a:apache:http_server:2.4.49")
        self.assertEqual(normalized, "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        query_cpe, query_type, confidence, _ = cpe_query_profile("cpe:/a:apache:http_server:2.4.49")
        self.assertEqual(query_cpe, normalized)
        self.assertEqual((query_type, confidence), ("cpeName", "high"))

    def test_partial_product_is_medium_but_generic_platform_is_skipped(self):
        self.assertEqual(cpe_query_profile("cpe:/a:apache:http_server")[1:3], ("virtualMatchString", "medium"))
        query = cpe_query_profile("cpe:/o:microsoft:windows")
        self.assertEqual(query[1], "skip")
        self.assertEqual(query[2], "low")

    def test_cvss_selection_is_consistent(self):
        metrics = {
            "cvssMetricV31": [{"type":"Primary","cvssData":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N"}}],
            "cvssMetricV2": [{"cvssData":{"version":"2.0","baseScore":7.5,"vectorString":"AV:N"},"baseSeverity":"HIGH"}],
        }
        selected = select_cvss(metrics)
        self.assertEqual(selected["version"], "3.1")
        self.assertEqual(selected["score"], 9.8)
        self.assertEqual(selected["severity"], "CRITICAL")

    def test_nvd_record_retains_applicability_and_raw_data(self):
        item = {"cve":{"id":"CVE-2021-41773","sourceIdentifier":"security@apache.org","published":"2021-10-05T09:15:00.000","lastModified":"2025-01-01T00:00:00.000","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"Example description"}],"metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"version":"3.1","baseScore":7.5,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N"}}]},"configurations":[{"nodes":[]}]}}
        parsed = parse_nvd_cve(item, datetime.now(timezone.utc))
        self.assertEqual(parsed["cve_id"], "CVE-2021-41773")
        self.assertEqual(parsed["applicability_data"], [{"nodes":[]}])
        self.assertEqual(parsed["raw"]["id"], "CVE-2021-41773")


if __name__ == "__main__": unittest.main()

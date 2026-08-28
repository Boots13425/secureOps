import gzip
import unittest
from datetime import date

from app.epss import organization_risk_score, parse_epss_csv, parse_schedule_time


def sample_csv(score_date="2026-08-27"):
    text = f"#model_version:v2025.03.14,score_date:{score_date}\ncve,epss,percentile\nCVE-2024-12345,0.7200000,0.9700000\n"
    return gzip.compress(text.encode("utf-8"))


class EpssTests(unittest.TestCase):
    def test_parse_daily_gzip_csv(self):
        score_date, records = parse_epss_csv(sample_csv())
        self.assertEqual(score_date, date(2026, 8, 27))
        self.assertEqual(records[0].cve_id, "CVE-2024-12345")
        self.assertEqual(float(records[0].score), 0.72)
        self.assertEqual(float(records[0].percentile), 0.97)

    def test_rejects_out_of_range_score(self):
        payload = b"#score_date:2026-08-27\ncve,epss,percentile\nCVE-2024-12345,1.2,0.9\n"
        with self.assertRaisesRegex(ValueError, "between 0 and 1"):
            parse_epss_csv(payload)

    def test_rejects_missing_score_date(self):
        payload = b"cve,epss,percentile\nCVE-2024-12345,0.2,0.9\n"
        with self.assertRaisesRegex(ValueError, "score_date"):
            parse_epss_csv(payload)

    def test_schedule_uses_24_hour_time(self):
        parsed = parse_schedule_time("14:45")
        self.assertEqual((parsed.hour, parsed.minute), (14, 45))

    def test_organization_risk_combines_probability_and_context(self):
        high_score, high_band = organization_risk_score(9.8, 0.72, "high", "server", "unknown")
        low_score, low_band = organization_risk_score(4.0, 0.01, "low", "phone", "approved")
        self.assertGreater(high_score, low_score)
        self.assertEqual(high_band, "critical")
        self.assertEqual(low_band, "low")

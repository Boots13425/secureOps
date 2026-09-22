import unittest
from ipaddress import ip_network

from app.risk_engine import policy_criticality, policy_exposure, score_asset, score_label


class RiskEngineTests(unittest.TestCase):
    def test_score_uses_specified_weights(self):
        score, label = score_asset(100, 50, 0, 80, 70)
        self.assertEqual(score, 62.5)
        self.assertEqual(label, "Elevated")

    def test_labels_follow_specified_ranges(self):
        self.assertEqual(score_label(29), "Low")
        self.assertEqual(score_label(30), "Moderate")
        self.assertEqual(score_label(50), "Elevated")
        self.assertEqual(score_label(70), "High")
        self.assertEqual(score_label(85), "Critical")

    def test_kev_floors_score_at_80(self):
        score, label = score_asset(0, 0, 100, 0, 20)
        self.assertEqual(score, 80)
        self.assertEqual(label, "High")

    def test_policy_criticality_normalizes_mac_delimiters(self):
        values = {"00:11:22:33:44:55": "critical", "10.0.0.5": "low"}
        self.assertEqual(policy_criticality(values, ["00-11-22-33-44-55", "10-0-0-5"]), (100, "critical"))

    def test_policy_defaults(self):
        self.assertEqual(policy_criticality({}, ("host", "10.0.0.1", None)), (50, "normal"))
        exposure, unmapped, context = policy_exposure("10.1.2.3", [{"network": ip_network("10.0.0.0/8"), "context_label": "Internet-facing/reachable"}])
        self.assertEqual((exposure, unmapped, context), (100, False, "Internet-facing/reachable"))
        self.assertEqual(policy_exposure("192.168.1.1", []), (50, True, None))


if __name__ == "__main__":
    unittest.main()

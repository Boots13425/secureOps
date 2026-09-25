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
        self.assertEqual(policy_criticality(values, ["00-11-22-33-44-55", "10-0-0-5"]), (100, "critical_service"))

    def test_policy_criticality_matches_dashed_ipv4_identifier(self):
        values = {"10.0.0.5": "high"}
        self.assertEqual(policy_criticality(values, ["10-0-0-5"]), (70, "privileged_workstation"))

    def test_policy_exposure_prefers_most_specific_subnet(self):
        policies = [
            {"network": ip_network("10.0.0.0/8"), "context_label": "General staff/user network"},
            {"network": ip_network("10.1.0.0/16"), "context_label": "Internet-facing/reachable"},
        ]
        self.assertEqual(policy_exposure("10.1.2.3", policies), (100, False, "Internet-facing/reachable"))

    def test_policy_defaults(self):
        self.assertEqual(policy_criticality({}, ("host", "10.0.0.1", None)), (50, "standard_workstation"))
        exposure, unmapped, context = policy_exposure("10.1.2.3", [{"network": ip_network("10.0.0.0/8"), "context_label": "Internet-facing/reachable"}])
        self.assertEqual((exposure, unmapped, context), (100, False, "Internet-facing/reachable"))
        self.assertEqual(policy_exposure("192.168.1.1", []), (50, True, None))

    def test_score_matches_manual_weighted_recomputation(self):
        score, label = score_asset(72.0, 18.0, 0, 65, 85)
        expected = round((72.0 * 0.30) + (18.0 * 0.20) + (0 * 0.20) + (65 * 0.15) + (85 * 0.15), 1)
        self.assertEqual((score, label), (expected, "Moderate"))

    def test_score_uses_all_five_inputs_for_each_criticality(self):
        expected = {
            "test_temporary": (59.9, "Elevated"),
            "peripheral": (61.4, "Elevated"),
            "standard_workstation": (64.4, "Elevated"),
            "privileged_workstation": (67.4, "Elevated"),
            "business_server": (69.7, "Elevated"),
            "critical_service": (71.9, "High"),
        }
        values = {"test_temporary": 20, "peripheral": 30, "standard_workstation": 50,
                  "privileged_workstation": 70, "business_server": 85, "critical_service": 100}
        for category, criticality in values.items():
            self.assertEqual(score_asset(98, 100, 0, 50, criticality), expected[category])


if __name__ == "__main__":
    unittest.main()

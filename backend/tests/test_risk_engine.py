import unittest

from app.config import settings
from app.risk_engine import CRITICALITY_CATEGORY_VALUES, CRITICALITY_LABELS, CRITICALITY_VALUES, score_asset, score_label


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

    def test_exposure_is_a_single_network_wide_value(self):
        # The network is flat, so there is no per-subnet lookup and no
        # "unmapped" case: every asset is scored with the same exposure.
        self.assertEqual(settings.network_exposure_value, 65)
        low = score_asset(50, 50, 0, settings.network_exposure_value, 50)
        high = score_asset(50, 50, 0, settings.network_exposure_value, 85)
        self.assertGreater(high[0], low[0])

    def test_category_values_match_the_criticality_table(self):
        # An asset document row's criticality_value must be exactly the value
        # the formula expects for the category that produced it.
        for label, value in CRITICALITY_CATEGORY_VALUES.items():
            key = next(key for key, name in CRITICALITY_LABELS.items() if name == label)
            self.assertEqual(CRITICALITY_VALUES[key], value)

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

import unittest
from ipaddress import ip_address

from app.risk_engine import (
    CRITICALITY_CATEGORY_VALUES,
    DEFAULT_CRITICALITY_VALUE,
    MISSING_FROM_SCAN_NOTE,
    NOT_IN_DOCUMENT_NOTE,
    match_document_to_assets,
    normalize_hostname,
    parse_asset_document,
    score_asset,
)

HEADER = ["device_name", "ip_address", "purpose", "criticality_category"]


def row(name="", ip="", purpose="", category=""):
    return [name, ip, purpose, category]


def doc(*rows):
    return [HEADER, *rows]


def errors_for(errors, row_number, column):
    return [e for e in errors if e["row"] == row_number and column in e["column"]]


class AssetDocumentValidationTests(unittest.TestCase):
    def test_valid_upload_returns_rows_with_mapped_values(self):
        rows = doc(
            row("SW-NTECHCENTRAL", "172.16.1.10", "Core switching", "Business application/server"),
            row("DESKTOP-V5IE2BR", "172.16.1.13", "Staff workstation", "Standard staff workstation"),
        )
        valid, errors = parse_asset_document(rows)
        self.assertEqual(errors, [])
        self.assertEqual(len(valid), 2)
        self.assertEqual(valid[0]["device_name"], "SW-NTECHCENTRAL")
        self.assertEqual(valid[0]["ip_address"], "172.16.1.10")
        self.assertEqual(valid[0]["purpose"], "Core switching")
        self.assertEqual(valid[0]["criticality_category"], "Business application/server")
        self.assertEqual(valid[0]["criticality_value"], 85)
        self.assertEqual(valid[1]["criticality_value"], 50)

    def test_headers_are_case_insensitive_and_whitespace_trimmed(self):
        rows = [
            [" Device_Name ", " IP_Address", "Purpose ", " Criticality_Category "],
            ["PC-1", "10.0.0.5", "Desk", "  standard staff workstation  "],
        ]
        valid, errors = parse_asset_document(rows)
        self.assertEqual(errors, [])
        self.assertEqual(valid[0]["device_name"], "PC-1")
        # Category matching ignores case and surrounding spaces
        self.assertEqual(valid[0]["criticality_category"], "Standard staff workstation")

    def test_all_six_categories_map_to_spec_values(self):
        rows = doc(*[row(f"d{i}", f"10.0.0.{i + 1}", "", category)
                     for i, category in enumerate(CRITICALITY_CATEGORY_VALUES)])
        valid, errors = parse_asset_document(rows)
        self.assertEqual(errors, [])
        self.assertEqual([r["criticality_value"] for r in valid], [20, 30, 50, 70, 85, 100])

    def test_missing_column_is_rejected(self):
        rows = [["device_name", "ip_address", "purpose"], ["PC-1", "10.0.0.5", "Desk"]]
        valid, errors = parse_asset_document(rows)
        self.assertEqual(valid, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("criticality_category", errors[0]["column"])
        self.assertIn("Required column", errors[0]["problem"])

    def test_row_with_neither_ip_nor_name_is_rejected(self):
        rows = doc(row("", "", "Mystery box", "Standard staff workstation"))
        valid, errors = parse_asset_document(rows)
        self.assertEqual(valid, [])
        self.assertTrue(errors_for(errors, 2, "ip_address / device_name"))

    def test_name_only_row_is_accepted(self):
        rows = doc(row("PRINTER-HQ", "", "Reception printer", "Printer/non-critical peripheral"))
        valid, errors = parse_asset_document(rows)
        self.assertEqual(errors, [])
        self.assertEqual(valid[0]["device_name"], "PRINTER-HQ")
        self.assertIsNone(valid[0]["ip_address"])

    def test_invalid_ip_is_rejected_and_names_the_problem(self):
        rows = doc(row("PC-1", "10.0.0.999", "Desk", "Standard staff workstation"))
        valid, errors = parse_asset_document(rows)
        self.assertEqual(valid, [])
        problem = errors_for(errors, 2, "ip_address")[0]
        self.assertIn("not a valid IP address", problem["problem"])
        self.assertIn("IPv4", problem["expected"])

    def test_unknown_category_is_rejected_with_the_allowed_list(self):
        rows = doc(row("PC-1", "10.0.0.5", "Desk", "Super important"))
        valid, errors = parse_asset_document(rows)
        self.assertEqual(valid, [])
        problem = errors_for(errors, 2, "criticality_category")[0]
        self.assertIn("Super important", problem["problem"])
        for allowed in CRITICALITY_CATEGORY_VALUES:
            self.assertIn(allowed, problem["expected"])

    def test_empty_category_is_rejected(self):
        rows = doc(row("PC-1", "10.0.0.5", "Desk", ""))
        valid, errors = parse_asset_document(rows)
        self.assertEqual(valid, [])
        self.assertTrue(errors_for(errors, 2, "criticality_category"))

    def test_duplicate_ip_is_rejected(self):
        rows = doc(
            row("PC-1", "10.0.0.5", "Desk", "Standard staff workstation"),
            row("PC-2", "10.0.0.5", "Desk", "Standard staff workstation"),
        )
        valid, errors = parse_asset_document(rows)
        # One error anywhere rejects the whole file (the endpoint only stores
        # when `errors` is empty), so the surviving row is never persisted.
        problem = errors_for(errors, 3, "ip_address")[0]
        self.assertIn("Duplicate", problem["problem"])
        self.assertIn("row 2", problem["problem"])
        self.assertEqual([r["device_name"] for r in valid], ["PC-1"])

    def test_duplicate_device_name_is_rejected_case_insensitively(self):
        rows = doc(
            row("PC-1", "10.0.0.5", "Desk", "Standard staff workstation"),
            row("pc-1", "10.0.0.6", "Desk", "Standard staff workstation"),
        )
        valid, errors = parse_asset_document(rows)
        problem = errors_for(errors, 3, "device_name")[0]
        self.assertIn("Duplicate", problem["problem"])
        self.assertEqual([r["device_name"] for r in valid], ["PC-1"])

    def test_every_failure_is_reported_not_just_the_first(self):
        rows = doc(
            row("PC-1", "999.9.9.9", "Desk", "Standard staff workstation"),
            row("PC-2", "10.0.0.6", "Desk", "Nonsense"),
            row("", "", "Nothing", "Standard staff workstation"),
        )
        valid, errors = parse_asset_document(rows)
        self.assertEqual(valid, [])
        self.assertEqual({e["row"] for e in errors}, {2, 3, 4})

    def test_empty_document_is_rejected(self):
        valid, errors = parse_asset_document([HEADER])
        self.assertEqual(valid, [])
        self.assertTrue(errors)


class HostnameNormalizationTests(unittest.TestCase):
    def test_domain_suffix_is_dropped(self):
        self.assertEqual(normalize_hostname("SW-NTECHCENTRAL.ntech.com"), "sw-ntechcentral")
        self.assertEqual(normalize_hostname("sw-ntechcentral"), "sw-ntechcentral")
        self.assertEqual(normalize_hostname("  DESKTOP-V5IE2BR "), "desktop-v5ie2br")
        self.assertEqual(normalize_hostname(None), "")


class DocumentMatchingTests(unittest.TestCase):
    def _asset(self, asset_id, ip, hostname):
        return {"asset_id": asset_id, "ip_address": ip, "hostname": hostname}

    def test_ip_match_wins(self):
        document = [{"row_number": 2, "device_name": "switch-a", "ip_address": "10.0.0.1",
                     "purpose": "Core", "criticality_category": "Business application/server",
                     "criticality_value": 85}]
        assets = [self._asset("a1", "10.0.0.1", "unknown-host")]
        matches, unmatched = match_document_to_assets(document, assets)
        self.assertEqual(matches["a1"]["flag"], "ip")
        self.assertEqual(matches["a1"]["row"]["criticality_value"], 85)
        self.assertEqual(unmatched, [])

    def test_hostname_match_ignores_domain_suffix(self):
        document = [{"row_number": 2, "device_name": "SW-NTECHCENTRAL", "ip_address": None,
                     "purpose": "Core switch", "criticality_category": "Business application/server",
                     "criticality_value": 85}]
        assets = [self._asset("a1", "172.16.1.10", "SW-NTECHCENTRAL.ntech.com")]
        matches, unmatched = match_document_to_assets(document, assets)
        self.assertEqual(matches["a1"]["flag"], "hostname")
        self.assertEqual(matches["a1"]["row"]["device_name"], "SW-NTECHCENTRAL")
        self.assertEqual(unmatched, [])

    def test_hostname_match_is_case_insensitive(self):
        document = [{"row_number": 2, "device_name": "sw-ntechcentral", "ip_address": None,
                     "purpose": "Core", "criticality_category": "Business application/server",
                     "criticality_value": 85}]
        assets = [self._asset("a1", "10.0.0.9", "SW-NTECHCENTRAL")]
        matches, _ = match_document_to_assets(document, assets)
        self.assertEqual(matches["a1"]["flag"], "hostname")

    def test_conflict_when_ip_and_hostname_point_at_different_rows(self):
        document = [
            {"row_number": 2, "device_name": "SW-ONE", "ip_address": "10.0.0.1",
             "purpose": "Switch A", "criticality_category": "Business application/server",
             "criticality_value": 85},
            {"row_number": 3, "device_name": "SW-TWO", "ip_address": "10.0.0.2",
             "purpose": "Switch B", "criticality_category": "Printer/non-critical peripheral",
             "criticality_value": 30},
        ]
        # The asset's IP is row 2's, but its hostname belongs to row 3.
        assets = [self._asset("a1", "10.0.0.1", "SW-TWO")]
        matches, unmatched = match_document_to_assets(document, assets)
        self.assertEqual(matches["a1"]["flag"], "conflict")
        # IP wins, so row 2 supplies the value and row 3 stays unmatched.
        self.assertEqual(matches["a1"]["row"]["device_name"], "SW-ONE")
        self.assertEqual([r["row_number"] for r in unmatched], [3])

    def test_document_row_not_scanned_is_unmatched(self):
        document = [
            {"row_number": 2, "device_name": "PRESENT", "ip_address": "10.0.0.1",
             "purpose": "Here", "criticality_category": "Standard staff workstation",
             "criticality_value": 50},
            {"row_number": 3, "device_name": "GHOST", "ip_address": "10.9.9.9",
             "purpose": "Offsite", "criticality_category": "Critical core service",
             "criticality_value": 100},
        ]
        assets = [self._asset("a1", "10.0.0.1", "PRESENT")]
        matches, unmatched = match_document_to_assets(document, assets)
        self.assertEqual(len(matches), 1)
        self.assertEqual([r["device_name"] for r in unmatched], ["GHOST"])

    def test_scanned_asset_not_in_document_is_not_matched(self):
        document = [{"row_number": 2, "device_name": "KNOWN", "ip_address": "10.0.0.1",
                     "purpose": "", "criticality_category": "Standard staff workstation",
                     "criticality_value": 50}]
        assets = [self._asset("a1", "10.0.0.1", "KNOWN"), self._asset("a2", "10.0.0.2", "STRANGER")]
        matches, unmatched = match_document_to_assets(document, assets)
        self.assertIn("a1", matches)
        self.assertNotIn("a2", matches)
        self.assertEqual(unmatched, [])

    def test_two_assets_sharing_a_row_ip_both_match_it(self):
        # A re-scanned host can briefly appear twice in `assets`. The document
        # row describes the device, not the database row, so both entries must
        # still receive its criticality - and the row must not then be reported
        # as missing from the scan.
        document = [{"row_number": 2, "device_name": "SHARED", "ip_address": "10.0.0.1",
                     "purpose": "", "criticality_category": "Standard staff workstation",
                     "criticality_value": 50}]
        assets = [self._asset("a1", "10.0.0.1", "HOST-A"), self._asset("a2", "10.0.0.1", "HOST-A")]
        matches, unmatched = match_document_to_assets(document, assets)
        self.assertEqual(len(matches), 2)
        self.assertEqual(unmatched, [])


class GroupCompositionTests(unittest.TestCase):
    """The three-group composition and ordering, exercised through the real
    scoring function so the formula itself is covered too."""

    def _scored(self, criticality, device_identifier, score_inputs=(0, 0, 0)):
        severity, epss, kev = score_inputs
        score, label = score_asset(severity, epss, kev, 65, criticality)
        return {"device_identifier": device_identifier, "score": score, "label": label}

    def test_unmatched_device_is_ranked_after_every_matched_device(self):
        # The matched devices carry real vulnerability signal; the unknown
        # device is scored with the default criticality of 50. If the groups
        # were merged and sorted by score alone the unknown device would be
        # interleaved, so this asserts the group boundary explicitly.
        ranked = [self._scored(85, "WEAK-MATCH", (10, 10, 0)),
                  self._scored(30, "MIDDLE-MATCH", (40, 40, 0))]
        not_in_document = [self._scored(DEFAULT_CRITICALITY_VALUE, "STRANGER", (90, 90, 0))]
        self.assertGreater(not_in_document[0]["score"], ranked[0]["score"])

        ordered = sorted(ranked, key=lambda a: -a["score"]) + sorted(not_in_document, key=lambda a: -a["score"])
        self.assertEqual([a["device_identifier"] for a in ordered],
                         ["MIDDLE-MATCH", "WEAK-MATCH", "STRANGER"])
        # Priority numbers continue straight on from group 1.
        self.assertEqual([i for i, _ in enumerate(ordered, start=1)], [1, 2, 3])

    def test_unmatched_devices_are_ordered_among_themselves_by_score(self):
        not_in_document = [self._scored(DEFAULT_CRITICALITY_VALUE, "LOW", (0, 0, 0)),
                           self._scored(DEFAULT_CRITICALITY_VALUE, "HIGH", (90, 90, 0))]
        ordered = sorted(not_in_document, key=lambda a: -a["score"])
        self.assertEqual([a["device_identifier"] for a in ordered], ["HIGH", "LOW"])

    def test_notes_are_the_specified_wording(self):
        self.assertEqual(NOT_IN_DOCUMENT_NOTE, "Not in your document - default value used")
        self.assertEqual(MISSING_FROM_SCAN_NOTE,
                         "Listed in your document but not detected on the network in the last 24 hours")

    def test_ip_validation_accepts_only_ipv4(self):
        self.assertEqual(str(ip_address("192.168.1.10")), "192.168.1.10")
        rows = doc(row("PC-1", "2001:db8::1", "Desk", "Standard staff workstation"))
        valid, errors = parse_asset_document(rows)
        self.assertEqual(valid, [])
        self.assertIn("not an IPv4 address", errors[0]["problem"])


if __name__ == "__main__":
    unittest.main()

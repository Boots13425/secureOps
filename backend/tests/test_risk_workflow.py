"""Layer 8 integration tests against the real database.

Two kinds of test live here:

* Storage/transport tests hit the database and the endpoint for real - a
  document upload replaces the previous one, an xlsx sheet is read, a 409 is
  returned when no document exists.
* Group composition and ordering are driven through a controlled asset list,
  because this database holds the real network's devices. Assertions about
  "the ranked group contains exactly these devices" would otherwise be at the
  mercy of whatever the last real scan found.

setUp/tearDown snapshot and restore the asset document, the stored ranking and
the ranking state, so a run leaves the live database exactly as it found it.
"""
import io
import unittest
from unittest import mock
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb

from app import repository
from app.database import connection
from app.risk_engine import parse_asset_document

HEADER = ["device_name", "ip_address", "purpose", "criticality_category"]

# A subnet reserved for documentation by RFC 5737, used so fixture assets are
# never confused with the real network.
FIXTURE_PREFIX = "198.18.0."


def build_document(*rows):
    valid, errors = parse_asset_document([HEADER, *rows])
    assert not errors, errors
    return valid


def insert_asset(ip_address, hostname, device_type="PC"):
    asset_id = uuid4()
    # macaddr is uniquely indexed; derive one from a random uuid so a re-run can
    # never collide with a row an interrupted earlier run left behind.
    tail = uuid4().bytes[:2]
    mac = ":".join(["02", "00", "00", f"{tail[0]:02x}", f"{tail[1]:02x}", f"{uuid4().bytes[2]:02x}"])
    with connection() as conn:
        conn.execute("""
            INSERT INTO assets(asset_id, ip_address, hostname, mac_address, device_type, status, first_seen, last_seen)
            VALUES (%s, %s, %s, %s, %s, 'known', now(), now())
        """, (asset_id, ip_address, hostname, mac, device_type))
    return str(asset_id)


def make_vulnerable(asset_id, cvss, epss=0.0, kev=False):
    """Attach one active CVE so the device gets a real score."""
    cve_id = f"TEST-{uuid4().hex[:12]}"
    with connection() as conn:
        # EPSS rows must reference a real download run (FK).
        run_id = conn.execute("""
            INSERT INTO epss_download_runs(target_date, trigger_source, status, source_url, records_received, finished_at)
            VALUES (current_date, 'manual', 'completed', 'test://layer8', 1, now())
            RETURNING epss_run_id
        """).fetchone()["epss_run_id"]
        service = conn.execute("""
            INSERT INTO services(asset_id, port, protocol, service_name, state, first_seen, last_seen)
            VALUES (%s, 443, 'tcp', 'https', 'open', now(), now()) RETURNING service_id
        """, (asset_id,)).fetchone()["service_id"]
        conn.execute("""
            INSERT INTO vulnerabilities(cve_id, description, cvss_base_score, cvss_version,
                                        cvss_base_severity, published_at, kev_flag,
                                        nvd_last_refreshed_at, raw_nvd_data)
            VALUES (%s, 'Test finding for the Layer 8 ranking tests', %s, '3.1', 'HIGH', now(), %s, now(), '{}'::jsonb)
        """, (cve_id, cvss, kev))
        conn.execute("""
            INSERT INTO epss_current_scores(cve_id, epss_score, epss_percentile, epss_date, source_run_id)
            VALUES (%s, %s, %s, current_date, %s)
        """, (cve_id, epss, epss, run_id))
        conn.execute("""
            INSERT INTO service_vulnerabilities(service_id, cve_id, matched_cpe, match_confidence,
                                                match_wording, match_reason, status,
                                                first_seen, last_seen, last_checked_at)
            VALUES (%s, %s, 'cpe:/a:layer8:https:1', 'high', 'test fixture',
                    'test fixture for the Layer 8 ranking', 'active', now(), now(), now())
        """, (service, cve_id))
    return cve_id, run_id


def scored_asset(asset_id, ip_address, hostname, cvss=None, epss=0.0, kev=False, device_type="PC"):
    """An asset row shaped exactly like _score_rows_for_calculation returns."""
    vulnerabilities = []
    if cvss is not None:
        vulnerabilities = [{"cve_id": f"TEST-{asset_id}", "cvss": cvss, "epss": epss, "kev": kev}]
    return {
        "asset_id": UUID(asset_id), "ip_address": ip_address, "hostname": hostname,
        "mac_address": None, "device_type": device_type, "status": "known",
        "services": [], "findings": [], "vulnerabilities": vulnerabilities,
    }


class DatabaseSnapshotMixin:
    """Restores the document, the stored ranking and the ranking state."""

    def setUp(self):
        with connection() as conn:
            self.saved_uploads = [dict(r) for r in conn.execute(
                "SELECT upload_id, uploaded_at, row_count FROM asset_document_uploads").fetchall()]
            self.saved_rows = [dict(r) for r in conn.execute(
                "SELECT * FROM asset_document_rows ORDER BY row_number").fetchall()]
            self.saved_state = [dict(r) for r in conn.execute("SELECT * FROM risk_ranking_state").fetchall()]
            self.saved_results = [dict(r) for r in conn.execute(
                "SELECT asset_id, priority_rank, match_group, risk_score, risk_band, payload, ranked_at"
                " FROM risk_ranking_results ORDER BY priority_rank").fetchall()]
            self.saved_missing = [dict(r) for r in conn.execute(
                "SELECT device_name, ip_address, purpose, criticality_category, criticality_value, note, ranked_at"
                " FROM risk_ranking_missing").fetchall()]
        self.created_assets = []
        self.created_cves = []

    def tearDown(self):
        with connection() as conn:
            for cve_id, run_id in self.created_cves:
                # EPSS rows hold no FK to the CVE, so clear them before the run.
                conn.execute("DELETE FROM epss_current_scores WHERE cve_id=%s", (cve_id,))
                conn.execute("DELETE FROM vulnerabilities WHERE cve_id=%s", (cve_id,))
                conn.execute("DELETE FROM epss_download_runs WHERE epss_run_id=%s", (run_id,))
            for asset_id in self.created_assets:
                conn.execute("DELETE FROM epss_current_scores WHERE cve_id IN ("
                             "SELECT cve_id FROM service_vulnerabilities "
                             "WHERE service_id IN (SELECT service_id FROM services WHERE asset_id=%s))", (asset_id,))
                conn.execute("DELETE FROM assets WHERE asset_id=%s", (asset_id,))
            # Ranking first, then the document (rows reference upload_id).
            conn.execute("DELETE FROM risk_ranking_state")
            conn.execute("DELETE FROM risk_ranking_results")
            conn.execute("DELETE FROM risk_ranking_missing")
            for row in self.saved_state:
                conn.execute("INSERT INTO risk_ranking_state(state_id, ranked_at, ranking) VALUES (%s,%s,%s)",
                             (row["state_id"], row["ranked_at"], Jsonb(row["ranking"])))
            for row in self.saved_results:
                conn.execute("""
                    INSERT INTO risk_ranking_results(asset_id, priority_rank, match_group, risk_score,
                                                     risk_band, payload, ranked_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                """, (row["asset_id"], row["priority_rank"], row["match_group"], row["risk_score"],
                      row["risk_band"], Jsonb(row["payload"]), row["ranked_at"]))
            for row in self.saved_missing:
                conn.execute("""
                    INSERT INTO risk_ranking_missing(device_name, ip_address, purpose, criticality_category,
                                                     criticality_value, note, ranked_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                """, (row["device_name"], row["ip_address"], row["purpose"], row["criticality_category"],
                      row["criticality_value"], row["note"], row["ranked_at"]))
            conn.execute("DELETE FROM asset_document_uploads")
            for row in self.saved_uploads:
                conn.execute("INSERT INTO asset_document_uploads(upload_id, uploaded_at, row_count) VALUES (%s,%s,%s)",
                             (row["upload_id"], row["uploaded_at"], row["row_count"]))
            for row in self.saved_rows:
                conn.execute("""
                    INSERT INTO asset_document_rows(upload_id, row_number, device_name, ip_address,
                                                   purpose, criticality_category, criticality_value)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                """, (row["upload_id"], row["row_number"], row["device_name"], row["ip_address"],
                      row["purpose"], row["criticality_category"], row["criticality_value"]))

    def add_asset(self, last_octet, hostname, device_type="PC"):
        ip_address = f"{FIXTURE_PREFIX}{last_octet}"
        asset_id = insert_asset(ip_address, hostname, device_type)
        self.created_assets.append(UUID(asset_id))
        return asset_id, ip_address

    def add_vulnerability(self, asset_id, cvss, **kwargs):
        cve_id, run_id = make_vulnerable(asset_id, cvss, **kwargs)
        self.created_cves.append((cve_id, run_id))
        return cve_id

    def calculate_with(self, assets):
        """Run the real calculation over a controlled asset list."""
        with mock.patch.object(repository, "_score_rows_for_calculation", return_value=assets):
            return repository.calculate_and_store_ranking()


class ReadinessTests(DatabaseSnapshotMixin, unittest.TestCase):
    def test_readiness_reports_only_the_document(self):
        with connection() as conn:
            conn.execute("DELETE FROM asset_document_uploads")
        readiness = repository.risk_readiness()
        self.assertEqual(set(readiness), {"asset_document_uploaded", "uploaded_at", "ready_to_rank"})
        self.assertFalse(readiness["asset_document_uploaded"])
        self.assertIsNone(readiness["uploaded_at"])
        self.assertFalse(readiness["ready_to_rank"])

    def test_readiness_is_true_once_a_document_exists(self):
        repository.save_asset_document(build_document(
            ["PC-1", f"{FIXTURE_PREFIX}1", "Desk", "Standard staff workstation"]))
        readiness = repository.risk_readiness()
        self.assertTrue(readiness["asset_document_uploaded"])
        self.assertIsNotNone(readiness["uploaded_at"])
        self.assertTrue(readiness["ready_to_rank"])

    def test_calculate_without_a_document_raises_for_409(self):
        with connection() as conn:
            conn.execute("DELETE FROM asset_document_uploads")
        with self.assertRaises(repository.AssetDocumentMissing) as caught:
            repository.calculate_and_store_ranking()
        self.assertFalse(caught.exception.readiness["ready_to_rank"])


class AssetDocumentStorageTests(DatabaseSnapshotMixin, unittest.TestCase):
    def test_upload_returns_row_count_and_timestamp(self):
        result = repository.save_asset_document(build_document(
            ["PC-1", f"{FIXTURE_PREFIX}1", "Desk", "Standard staff workstation"],
            ["SRV-1", f"{FIXTURE_PREFIX}2", "File server", "Business application/server"]))
        self.assertEqual(result["row_count"], 2)
        self.assertIsNotNone(result["uploaded_at"])

    def test_re_upload_replaces_the_previous_document_entirely(self):
        repository.save_asset_document(build_document(
            ["OLD-PC", f"{FIXTURE_PREFIX}1", "Old desk", "Test/temporary device"],
            ["OLD-PRINTER", f"{FIXTURE_PREFIX}2", "Old printer", "Printer/non-critical peripheral"]))
        self.assertEqual(repository.asset_document_state()["row_count"], 2)

        result = repository.save_asset_document(build_document(
            ["NEW-PC", f"{FIXTURE_PREFIX}3", "New desk", "Business application/server"]))
        self.assertEqual(result["row_count"], 1)

        # The old rows are gone, not merged with the new ones.
        self.assertEqual([r["device_name"] for r in repository.load_asset_document()], ["NEW-PC"])
        with connection() as conn:
            uploads = conn.execute("SELECT count(*) AS n FROM asset_document_uploads").fetchone()["n"]
            rows = conn.execute("SELECT count(*) AS n FROM asset_document_rows").fetchone()["n"]
        self.assertEqual(uploads, 1)
        self.assertEqual(rows, 1)


class GroupCompositionTests(DatabaseSnapshotMixin, unittest.TestCase):
    def test_three_groups_are_produced_and_ordered(self):
        matched_high, ip_high = self.add_asset(1, "MATCHED-HIGH")
        matched_low, ip_low = self.add_asset(2, "MATCHED-LOW")
        stranger, ip_stranger = self.add_asset(3, "STRANGER")
        assets = [
            scored_asset(matched_high, ip_high, "MATCHED-HIGH", cvss=6.0),
            scored_asset(matched_low, ip_low, "MATCHED-LOW", cvss=1.0),
            # Highest vulnerability signal on the network, yet not in the
            # document: it must still sort after every matched device.
            scored_asset(stranger, ip_stranger, "STRANGER", cvss=10.0, epss=1.0),
        ]
        repository.save_asset_document(build_document(
            ["MATCHED-HIGH", ip_high, "Core switching", "Business application/server"],
            ["MATCHED-LOW", "", "Reception printer", "Printer/non-critical peripheral"],
            ["GHOST-HOST", f"{FIXTURE_PREFIX}99", "Offsite laptop",
             "Identity, finance, student/medical records, critical core service"]))

        result = self.calculate_with(assets)

        self.assertEqual([r["hostname"] for r in result["ranked"]], ["MATCHED-HIGH", "MATCHED-LOW"])
        self.assertEqual([r["hostname"] for r in result["not_in_document"]], ["STRANGER"])
        self.assertEqual([r["device_name"] for r in result["missing_from_scan"]], ["GHOST-HOST"])

        # Group 3 ranks continue after group 1 in one strict sequence.
        self.assertEqual([r["priority_rank"] for r in result["ranked"] + result["not_in_document"]], [1, 2, 3])

        stranger_row = result["not_in_document"][0]
        self.assertGreater(stranger_row["score"], result["ranked"][0]["score"])
        self.assertEqual(stranger_row["asset_criticality"], 50)
        self.assertEqual(stranger_row["document_note"], "Not in your document - default value used")
        self.assertIsNone(stranger_row["purpose"])

    def test_every_asset_uses_the_one_network_wide_exposure(self):
        a, ip_a = self.add_asset(11, "EXPOSURE-A")
        b, ip_b = self.add_asset(12, "EXPOSURE-B")
        repository.save_asset_document(build_document(
            ["EXPOSURE-A", ip_a, "", "Test/temporary device"],
            ["EXPOSURE-B", ip_b, "", "Standard staff workstation"]))
        result = self.calculate_with([
            scored_asset(a, ip_a, "EXPOSURE-A", cvss=1.0),
            scored_asset(b, ip_b, "EXPOSURE-B", cvss=1.0),
        ])
        for row in result["ranked"]:
            self.assertEqual(row["exposure"], 65)
            self.assertNotIn("exposure_unmapped", row)

    def test_missing_from_scan_carries_the_specified_message(self):
        repository.save_asset_document(build_document(
            ["GHOST-HOST", f"{FIXTURE_PREFIX}99", "Offsite laptop",
             "Identity, finance, student/medical records, critical core service"]))
        result = self.calculate_with([])
        self.assertEqual(len(result["missing_from_scan"]), 1)
        entry = result["missing_from_scan"][0]
        self.assertEqual(entry["note"],
                         "Listed in your document but not detected on the network in the last 24 hours")
        self.assertEqual(entry["device_name"], "GHOST-HOST")
        self.assertEqual(entry["ip_address"], f"{FIXTURE_PREFIX}99")
        self.assertEqual(entry["purpose"], "Offsite laptop")

    def test_match_flags_are_reported(self):
        a, ip_a = self.add_asset(21, "SOMETHING")
        b, ip_b = self.add_asset(22, "SW-NTECHCENTRAL.ntech.com")
        repository.save_asset_document(build_document(
            ["ROW-A", ip_a, "", "Standard staff workstation"],
            ["SW-NTECHCENTRAL", "", "Core switch", "Business application/server"]))
        result = self.calculate_with([
            scored_asset(a, ip_a, "SOMETHING"),
            scored_asset(b, ip_b, "SW-NTECHCENTRAL.ntech.com"),
        ])
        flags = {r["hostname"]: r["match_flag"] for r in result["ranked"]}
        self.assertEqual(flags["SOMETHING"], "ip")
        # The document lists the short name; the scan reports the FQDN.
        self.assertEqual(flags["SW-NTECHCENTRAL.ntech.com"], "hostname")
        by_hostname = {r["hostname"]: r["matched_device_name"] for r in result["ranked"]}
        self.assertEqual(by_hostname["SW-NTECHCENTRAL.ntech.com"], "SW-NTECHCENTRAL")
        self.assertEqual(by_hostname["SOMETHING"], "ROW-A")

    def test_conflict_is_flagged_when_ip_and_hostname_disagree(self):
        a, ip_a = self.add_asset(31, "ROW-B-HOST")
        repository.save_asset_document(build_document(
            ["ROW-A", ip_a, "Claimed by IP", "Business application/server"],
            ["ROW-B-HOST", f"{FIXTURE_PREFIX}32", "Claimed by name", "Printer/non-critical peripheral"]))
        result = self.calculate_with([scored_asset(a, ip_a, "ROW-B-HOST")])
        entry = result["ranked"][0]
        # The IP match wins and supplies the criticality...
        self.assertEqual(entry["match_flag"], "conflict")
        self.assertEqual(entry["matched_device_name"], "ROW-A")
        self.assertEqual(entry["asset_criticality"], 85)
        # ...so the row the hostname pointed at is reported as not seen.
        self.assertEqual([r["device_name"] for r in result["missing_from_scan"]], ["ROW-B-HOST"])

    def test_criticality_and_purpose_come_from_the_document_row(self):
        a, ip_a = self.add_asset(41, "DOC-MATCH")
        repository.save_asset_document(build_document(
            ["DOC-MATCH", ip_a, "Payroll processing server",
             "Identity, finance, student/medical records, critical core service"]))
        entry = self.calculate_with([scored_asset(a, ip_a, "DOC-MATCH")])["ranked"][0]
        self.assertEqual(entry["asset_criticality"], 100)
        self.assertEqual(entry["purpose"], "Payroll processing server")
        self.assertEqual(entry["criticality_category"],
                         "Identity, finance, student/medical records, critical core service")
        self.assertEqual(entry["criticality_source"], "asset_document")


class StoredResultTests(DatabaseSnapshotMixin, unittest.TestCase):
    def test_get_current_ranking_returns_the_three_groups_in_priority_order(self):
        a, ip_a = self.add_asset(51, "A-LOW")
        b, ip_b = self.add_asset(52, "B-HIGH")
        repository.save_asset_document(build_document(
            ["A-LOW", ip_a, "", "Standard staff workstation"],
            ["B-HIGH", ip_b, "", "Standard staff workstation"]))
        self.calculate_with([scored_asset(a, ip_a, "A-LOW", cvss=1.0),
                             scored_asset(b, ip_b, "B-HIGH", cvss=9.5)])

        stored = repository.get_current_ranking()
        self.assertEqual(set(stored),
                         {"last_ranked_at", "ranking_stale", "ranked", "not_in_document", "missing_from_scan"})
        self.assertIsNotNone(stored["last_ranked_at"])
        self.assertEqual([r["hostname"] for r in stored["ranked"]], ["B-HIGH", "A-LOW"])
        self.assertEqual([r["priority_rank"] for r in stored["ranked"]], [1, 2])
        # The stored order must survive a re-read rather than depend on the
        # order rows happen to come back from the database in.
        self.assertEqual([r["hostname"] for r in repository.get_current_ranking()["ranked"]],
                         ["B-HIGH", "A-LOW"])

    def test_group_three_is_stored_after_group_one(self):
        a, ip_a = self.add_asset(61, "MATCHED")
        b, ip_b = self.add_asset(62, "UNMATCHED")
        repository.save_asset_document(build_document(["MATCHED", ip_a, "", "Printer/non-critical peripheral"]))
        self.calculate_with([scored_asset(a, ip_a, "MATCHED", cvss=0.5),
                             scored_asset(b, ip_b, "UNMATCHED", cvss=10.0, epss=1.0)])
        stored = repository.get_current_ranking()
        self.assertEqual([r["priority_rank"] for r in stored["ranked"]], [1])
        self.assertEqual([r["priority_rank"] for r in stored["not_in_document"]], [2])
        self.assertGreater(stored["not_in_document"][0]["score"], stored["ranked"][0]["score"])

    def test_summary_counts_match_the_devices_shown(self):
        a, ip_a = self.add_asset(71, "KEV-HOST")
        b, ip_b = self.add_asset(72, "CLEAN-HOST")
        repository.save_asset_document(build_document(
            ["KEV-HOST", ip_a, "", "Standard staff workstation"],
            ["CLEAN-HOST", ip_b, "", "Printer/non-critical peripheral"]))
        self.calculate_with([scored_asset(a, ip_a, "KEV-HOST", cvss=9.9, kev=True),
                             scored_asset(b, ip_b, "CLEAN-HOST")])

        summary = repository.risk_summary()
        current = repository.get_current_ranking()
        shown = len(current["ranked"]) + len(current["not_in_document"])
        self.assertEqual(summary["assets_scored"], shown)
        self.assertEqual(summary["kev_matches"], 1)
        # The KEV floor forces >= 80, which is "High", never "Critical".
        self.assertEqual(summary["high"], 1)
        self.assertEqual(summary["critical"], 0)
        self.assertEqual(
            summary["assets_scored"],
            summary["critical"] + summary["high"] + summary["elevated"]
            + summary["moderate"] + summary["low"])


class StalenessTests(DatabaseSnapshotMixin, unittest.TestCase):
    def test_ranking_is_stale_after_a_new_document_upload(self):
        a, ip_a = self.add_asset(81, "STALE-HOST")
        repository.save_asset_document(build_document(
            ["STALE-HOST", ip_a, "", "Standard staff workstation"]))
        self.calculate_with([scored_asset(a, ip_a, "STALE-HOST", cvss=5.0)])
        self.assertFalse(repository.get_current_ranking()["ranking_stale"])

        # Re-uploading must not recalculate, only flag the ranking as stale.
        repository.save_asset_document(build_document(
            ["STALE-HOST", ip_a, "Repurposed", "Business application/server"]))
        current = repository.get_current_ranking()
        self.assertTrue(current["ranking_stale"])
        self.assertEqual(current["ranked"][0]["purpose"], "")
        self.assertEqual(current["ranked"][0]["asset_criticality"], 50)

    def test_ranking_is_stale_when_a_new_device_appears(self):
        repository.save_asset_document(build_document(
            ["ONLY-PC", f"{FIXTURE_PREFIX}91", "", "Standard staff workstation"]))
        self.calculate_with([])
        self.assertFalse(repository.get_current_ranking()["ranking_stale"])

        # A real asset row, so the staleness query sees a new last_seen.
        self.add_asset(92, "BRAND-NEW")
        self.assertTrue(repository.get_current_ranking()["ranking_stale"])

    def test_devices_older_than_24_hours_are_excluded(self):
        old, ip_old = self.add_asset(93, "OLD-DEVICE")
        with connection() as conn:
            conn.execute("UPDATE assets SET last_seen = now() - interval '48 hours' WHERE asset_id=%s", (old,))
        repository.save_asset_document(build_document(
            ["OLD-DEVICE", ip_old, "", "Standard staff workstation"]))
        # No mocking here: this exercises the real 24-hour filter in SQL.
        result = repository.calculate_and_store_ranking()
        self.assertEqual([r["hostname"] for r in result["ranked"] if r["hostname"] == "OLD-DEVICE"], [])
        self.assertIn("OLD-DEVICE", [r["device_name"] for r in result["missing_from_scan"]])


class AssetDocumentEndpointTests(DatabaseSnapshotMixin, unittest.TestCase):
    def _post(self, filename, content):
        from fastapi.testclient import TestClient
        from app.main import app
        return TestClient(app).post("/api/v1/risk/policy/asset-document",
                                    files={"file": (filename, content)})

    def _csv(self, *rows):
        lines = [",".join(HEADER)] + [",".join(str(c) for c in row) for row in rows]
        return ("\n".join(lines) + "\n").encode("utf-8")

    def test_valid_csv_upload_returns_row_count_and_timestamp(self):
        response = self._post("assets.csv", self._csv(
            ["PC-1", f"{FIXTURE_PREFIX}1", "Staff desk", "Standard staff workstation"],
            ["SRV-1", f"{FIXTURE_PREFIX}2", "File server", "Business application/server"]))
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["rows_uploaded"], 2)
        self.assertTrue(body["uploaded_at"])

    def test_every_failure_is_returned_with_row_column_problem_and_expected(self):
        response = self._post("bad.csv", self._csv(
            ["PC-1", f"{FIXTURE_PREFIX}1", "Desk", "Standard staff workstation"],
            ["PC-2", "not-an-ip", "Desk", "Standard staff workstation"],
            ["", "", "Nothing", "Standard staff workstation"],
            ["PC-3", f"{FIXTURE_PREFIX}3", "Desk", "Wrong category"]))
        self.assertEqual(response.status_code, 400)
        errors = response.json()["detail"]["errors"]
        self.assertEqual({e["row"] for e in errors}, {3, 4, 5})
        for error in errors:
            self.assertEqual(set(error), {"row", "column", "problem", "expected"})
        columns = {e["column"] for e in errors}
        self.assertIn("ip_address", columns)
        self.assertIn("criticality_category", columns)
        self.assertIn("ip_address / device_name", columns)

    def test_rejected_upload_does_not_replace_the_existing_document(self):
        ok = self._post("good.csv", self._csv(
            ["PC-1", f"{FIXTURE_PREFIX}1", "Desk", "Standard staff workstation"]))
        self.assertEqual(ok.status_code, 200)
        rejected = self._post("bad.csv", self._csv(
            ["PC-2", f"{FIXTURE_PREFIX}2", "Desk", "Nope"]))
        self.assertEqual(rejected.status_code, 400)
        # The document in force is still the first, valid one.
        self.assertEqual([r["device_name"] for r in repository.load_asset_document()], ["PC-1"])

    def test_xlsx_upload_uses_the_named_sheet(self):
        from openpyxl import Workbook
        workbook = Workbook()
        cover = workbook.active
        cover.title = "Read me"
        cover.append(["this sheet must be ignored"])
        sheet = workbook.create_sheet("Device Criticality")
        sheet.append(HEADER)
        sheet.append(["XLSX-PC", f"{FIXTURE_PREFIX}1", "From a spreadsheet",
                      "Administration/privileged workstation"])
        buffer = io.BytesIO()
        workbook.save(buffer)

        response = self._post("assets.xlsx", buffer.getvalue())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["rows_uploaded"], 1)
        self.assertEqual(repository.load_asset_document()[0]["device_name"], "XLSX-PC")

    def test_xlsx_falls_back_to_the_first_sheet(self):
        from openpyxl import Workbook
        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "Sheet1"
        sheet.append(HEADER)
        sheet.append(["FIRST-SHEET-PC", f"{FIXTURE_PREFIX}1", "Fallback",
                      "Printer/non-critical peripheral"])
        buffer = io.BytesIO()
        workbook.save(buffer)

        response = self._post("assets.xlsx", buffer.getvalue())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(repository.load_asset_document()[0]["device_name"], "FIRST-SHEET-PC")

    def test_calculate_returns_409_with_readiness_detail(self):
        from fastapi.testclient import TestClient
        from app.main import app
        with connection() as conn:
            conn.execute("DELETE FROM asset_document_uploads")
        response = TestClient(app).post("/api/v1/risk/calculate")
        self.assertEqual(response.status_code, 409)
        detail = response.json()["detail"]
        self.assertFalse(detail["ready_to_rank"])
        self.assertFalse(detail["asset_document_uploaded"])
        self.assertEqual(detail["message"],
                         "Upload the asset document first. Ranking runs only after it is uploaded.")


if __name__ == "__main__":
    unittest.main()

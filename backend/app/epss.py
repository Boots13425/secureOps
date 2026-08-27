import csv
import gzip
import io
import re
import threading
import urllib.request
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal, InvalidOperation
from zoneinfo import ZoneInfo

from .config import settings
from .database import connection


@dataclass(frozen=True)
class EpssRecord:
    cve_id: str
    score: Decimal
    percentile: Decimal


def parse_schedule_time(value: str) -> time:
    try:
        hour, minute = (int(part) for part in value.split(":"))
        return time(hour=hour, minute=minute)
    except (TypeError, ValueError) as exc:
        raise ValueError("EPSS_SCHEDULE_TIME must use 24-hour HH:MM format") from exc


def parse_epss_csv(payload: bytes) -> tuple[date, list[EpssRecord]]:
    """Validate and parse FIRST's gzip or plain-text daily EPSS CSV."""
    try:
        raw = gzip.decompress(payload) if payload[:2] == b"\x1f\x8b" else payload
        text = raw.decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("EPSS download is not a readable CSV or gzip CSV") from exc

    lines = text.splitlines()
    if not lines:
        raise ValueError("EPSS CSV is empty")
    metadata = next((line for line in lines if line.startswith("#")), "")
    match = re.search(r"score_date\s*:\s*(\d{4}-\d{2}-\d{2})", metadata, re.IGNORECASE)
    if not match:
        raise ValueError("EPSS CSV metadata does not contain score_date")
    score_date = date.fromisoformat(match.group(1))
    csv_text = "\n".join(line for line in lines if not line.startswith("#"))
    reader = csv.DictReader(io.StringIO(csv_text))
    if not reader.fieldnames or not {"cve", "epss", "percentile"}.issubset({name.strip().lower() for name in reader.fieldnames}):
        raise ValueError("EPSS CSV must contain cve, epss, and percentile columns")

    records = []
    for row_number, row in enumerate(reader, start=2):
        normalized = {str(key).strip().lower(): value for key, value in row.items()}
        cve_id = (normalized.get("cve") or "").strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
            raise ValueError(f"Invalid CVE identifier on CSV row {row_number}")
        try:
            score = Decimal((normalized.get("epss") or "").strip())
            percentile = Decimal((normalized.get("percentile") or "").strip())
        except InvalidOperation as exc:
            raise ValueError(f"Invalid EPSS number on CSV row {row_number}") from exc
        if not (Decimal("0") <= score <= Decimal("1")) or not (Decimal("0") <= percentile <= Decimal("1")):
            raise ValueError(f"EPSS values must be between 0 and 1 on CSV row {row_number}")
        records.append(EpssRecord(cve_id, score, percentile))
    if not records:
        raise ValueError("EPSS CSV contains no score records")
    return score_date, records


def organization_risk_score(cvss_score, epss_score, confidence: str, device_type: str, asset_status: str) -> tuple[float, str]:
    """Prototype 0-100 risk: CVSS 50%, EPSS 35%, evidence 10%, asset context 5%."""
    cvss = min(max(float(cvss_score or 0) / 10, 0), 1)
    epss = min(max(float(epss_score or 0), 0), 1)
    confidence_factor = {"confirmed": 1, "high": 0.9, "medium": 0.65, "low": 0.35}.get(confidence, 0.35)
    type_factor = {"server": 1, "router": 1, "network device": 0.95, "printer": 0.8, "pc": 0.75, "phone": 0.6, "unknown": 0.7}.get((device_type or "unknown").lower(), 0.7)
    status_factor = {"unknown": 1, "approved": 0.9, "known": 0.85, "missing": 0.6, "offline": 0.5}.get((asset_status or "unknown").lower(), 0.8)
    asset_context = (type_factor + status_factor) / 2
    score = round((cvss * 50) + (epss * 35) + (confidence_factor * 10) + (asset_context * 5), 2)
    band = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"
    return score, band


def recalculate_organization_risk() -> int:
    with connection() as conn:
        rows = conn.execute("""SELECT sv.service_vulnerability_id,v.cvss_base_score,e.epss_score,
          sv.match_confidence,a.device_type,a.status AS asset_status
          FROM service_vulnerabilities sv
          JOIN vulnerabilities v ON v.cve_id=sv.cve_id
          JOIN services s ON s.service_id=sv.service_id
          JOIN assets a ON a.asset_id=s.asset_id
          LEFT JOIN epss_current_scores e ON e.cve_id=sv.cve_id""").fetchall()
        for row in rows:
            if row["epss_score"] is None:
                conn.execute("UPDATE service_vulnerabilities SET organization_risk_score=NULL,organization_risk_band=NULL,risk_calculated_at=NULL WHERE service_vulnerability_id=%s", (row["service_vulnerability_id"],))
                continue
            score, band = organization_risk_score(row["cvss_base_score"], row["epss_score"], row["match_confidence"], row["device_type"], row["asset_status"])
            conn.execute("UPDATE service_vulnerabilities SET organization_risk_score=%s,organization_risk_band=%s,risk_calculated_at=now() WHERE service_vulnerability_id=%s", (score, band, row["service_vulnerability_id"]))
    return len(rows)


class EpssCoordinator:
    def __init__(self):
        self._worker_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._scheduler_thread = None
        self._publish = None

    @property
    def local_timezone(self):
        return ZoneInfo(settings.epss_timezone)

    def start(self, publish=None):
        self._publish = publish
        if self._scheduler_thread and self._scheduler_thread.is_alive():
            return
        now_utc = datetime.now(timezone.utc)
        with connection() as conn:
            conn.execute("""UPDATE epss_download_runs SET status='failed',finished_at=now(),
              error_message=COALESCE(error_message,'Backend restarted before the EPSS download completed'),next_retry_at=%s
              WHERE status IN ('queued','running')""", (now_utc,))
        self._stop_event.clear()
        self._scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True, name="epss-daily-scheduler")
        self._scheduler_thread.start()

    def stop(self):
        self._stop_event.set()
        if self._scheduler_thread:
            self._scheduler_thread.join(timeout=2)

    def schedule(self, target_date: date | None = None, trigger_source="manual", force=False):
        target = target_date or datetime.now(self.local_timezone).date()
        with connection() as conn:
            active = conn.execute("SELECT epss_run_id FROM epss_download_runs WHERE target_date=%s AND status IN ('queued','running') ORDER BY queued_at DESC LIMIT 1", (target,)).fetchone()
            if active:
                return str(active["epss_run_id"])
            if not force:
                complete = conn.execute("SELECT epss_run_id FROM epss_download_runs WHERE target_date=%s AND status='completed' ORDER BY queued_at DESC LIMIT 1", (target,)).fetchone()
                if complete:
                    return str(complete["epss_run_id"])
            run = conn.execute("""INSERT INTO epss_download_runs(target_date,trigger_source,status,source_url)
              VALUES (%s,%s,'queued',%s) RETURNING epss_run_id""", (target, trigger_source, settings.epss_csv_url)).fetchone()
        run_id = str(run["epss_run_id"])
        threading.Thread(target=self._run, args=(run_id, target), daemon=True, name=f"epss-{run_id}").start()
        return run_id

    def _download(self) -> bytes:
        request = urllib.request.Request(settings.epss_csv_url, headers={"User-Agent": "SecureOps-Prototype/1.0", "Accept": "text/csv,application/gzip"})
        maximum = settings.epss_max_download_mb * 1024 * 1024
        with urllib.request.urlopen(request, timeout=settings.epss_request_timeout_seconds) as response:
            payload = response.read(maximum + 1)
        if len(payload) > maximum:
            raise ValueError(f"EPSS download exceeds configured {settings.epss_max_download_mb} MB limit")
        return payload

    def _store_snapshot(self, run_id: str, score_date: date, records: list[EpssRecord]):
        with connection() as conn:
            conn.execute("CREATE TEMP TABLE epss_import(cve_id varchar(24),epss_score numeric(8,7),epss_percentile numeric(8,7)) ON COMMIT DROP")
            with conn.cursor().copy("COPY epss_import (cve_id,epss_score,epss_percentile) FROM STDIN") as copy:
                for record in records:
                    copy.write_row((record.cve_id, record.score, record.percentile))
            conn.execute("""INSERT INTO epss_daily_snapshots(epss_date,cve_id,epss_score,epss_percentile,source_run_id)
              SELECT %s,cve_id,epss_score,epss_percentile,%s FROM epss_import
              ON CONFLICT (epss_date,cve_id) DO UPDATE SET epss_score=EXCLUDED.epss_score,epss_percentile=EXCLUDED.epss_percentile,source_run_id=EXCLUDED.source_run_id,imported_at=now()""", (score_date, run_id))
            conn.execute("""INSERT INTO epss_current_scores(cve_id,epss_score,epss_percentile,epss_date,source_run_id)
              SELECT cve_id,epss_score,epss_percentile,%s,%s FROM epss_import
              ON CONFLICT (cve_id) DO UPDATE SET epss_score=EXCLUDED.epss_score,epss_percentile=EXCLUDED.epss_percentile,
              epss_date=EXCLUDED.epss_date,source_run_id=EXCLUDED.source_run_id,updated_at=now()
              WHERE epss_current_scores.epss_date <= EXCLUDED.epss_date""", (score_date, run_id))

    def _run(self, run_id: str, target_date: date):
        with self._worker_lock:
            try:
                with connection() as conn:
                    conn.execute("UPDATE epss_download_runs SET status='running',started_at=now(),next_retry_at=NULL WHERE epss_run_id=%s", (run_id,))
                score_date, records = parse_epss_csv(self._download())
                if score_date != target_date:
                    raise ValueError(f"EPSS file is dated {score_date}; expected {target_date}")
                self._store_snapshot(run_id, score_date, records)
                affected = recalculate_organization_risk()
                with connection() as conn:
                    conn.execute("UPDATE epss_download_runs SET status='completed',records_received=%s,finished_at=now() WHERE epss_run_id=%s", (len(records), run_id))
                if self._publish:
                    self._publish("EPSS_UPDATED", {"epss_run_id": run_id, "epss_date": str(score_date), "records": len(records), "risk_matches": affected})
            except Exception as exc:
                retry_at = datetime.now(timezone.utc) + timedelta(minutes=settings.epss_retry_minutes)
                with connection() as conn:
                    conn.execute("UPDATE epss_download_runs SET status='failed',error_message=%s,finished_at=now(),next_retry_at=%s WHERE epss_run_id=%s", (str(exc)[:2000], retry_at, run_id))
                if self._publish:
                    self._publish("EPSS_FAILED", {"epss_run_id": run_id, "error": str(exc), "next_retry_at": retry_at.isoformat()})

    def _scheduler_loop(self):
        schedule_at = parse_schedule_time(settings.epss_schedule_time)
        while not self._stop_event.is_set():
            now = datetime.now(self.local_timezone)
            target = now.date()
            with connection() as conn:
                latest = conn.execute("SELECT status,next_retry_at FROM epss_download_runs WHERE target_date=%s ORDER BY queued_at DESC LIMIT 1", (target,)).fetchone()
            if latest and latest["status"] == "failed" and latest["next_retry_at"] and datetime.now(timezone.utc) >= latest["next_retry_at"]:
                self.schedule(target, "retry")
            elif not latest and now.time() >= schedule_at:
                self.schedule(target, "startup" if now.time() > schedule_at else "scheduled")
            self._stop_event.wait(30)


coordinator = EpssCoordinator()

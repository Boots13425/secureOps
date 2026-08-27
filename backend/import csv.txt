import csv
import gzip
import ssl
import threading
import urllib.request
from datetime import datetime, timezone

import certifi

from .config import settings
from .database import connection

EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())


def _download_epss_csv() -> tuple[list[dict], str, str | None]:
    """Download and parse the daily FIRST EPSS CSV.

    Returns (rows, model_version, score_date).
    """
    request = urllib.request.Request(
        EPSS_CSV_URL, headers={"User-Agent": "SecureOps-Prototype/1.0"}
    )
    with urllib.request.urlopen(request, timeout=60, context=_SSL_CONTEXT) as response:
        raw = gzip.decompress(response.read())

    text = raw.decode("utf-8")
    lines = text.splitlines()

    model_version = "unknown"
    score_date = None
    if lines and lines[0].startswith("#"):
        header_comment = lines[0].lstrip("#")
        for part in header_comment.split(","):
            if part.startswith("model_version:"):
                model_version = part.split(":", 1)[1]
            elif part.startswith("score_date:"):
                score_date = part.split(":", 1)[1][:10]
        lines = lines[1:]

    reader = csv.DictReader(lines)
    rows = []
    for row in reader:
        try:
            rows.append(
                {
                    "cve": row["cve"].strip(),
                    "epss": float(row["epss"]),
                    "percentile": float(row["percentile"]),
                }
            )
        except (KeyError, ValueError):
            continue

    return rows, model_version, score_date


def _store_scores(rows: list[dict], model_version: str, score_date: str | None) -> tuple[int, int]:
    """Update epss fields on vulnerabilities for CVEs we already track.

    Returns (queued_count, matched_count).
    """
    refreshed_at = datetime.now(timezone.utc)
    matched = 0
    with connection() as conn:
        existing = {
            r["cve_id"]
            for r in conn.execute("SELECT cve_id FROM vulnerabilities").fetchall()
        }
        relevant_rows = [row for row in rows if row["cve"] in existing]
        for row in relevant_rows:
            conn.execute(
                """UPDATE vulnerabilities
                   SET epss_score=%s, epss_percentile=%s, epss_model_version=%s,
                       epss_score_date=%s, epss_refreshed_at=%s, updated_at=now()
                   WHERE cve_id=%s""",
                (
                    row["epss"],
                    row["percentile"],
                    model_version,
                    score_date,
                    refreshed_at,
                    row["cve"],
                ),
            )
            matched += 1
    return len(existing), matched


class EpssEnrichmentCoordinator:
    def __init__(self):
        self._worker_lock = threading.Lock()

    def schedule(self, scan_id=None, trigger_source: str = "manual") -> str:
        with connection() as conn:
            job = conn.execute(
                """INSERT INTO epss_enrichment_runs(scan_id, trigger_source, status)
                   VALUES (%s, %s, 'queued') RETURNING enrichment_run_id""",
                (scan_id, trigger_source),
            ).fetchone()
        thread = threading.Thread(
            target=self._run, args=(str(job["enrichment_run_id"]),), daemon=True,
            name=f"epss-refresh-{job['enrichment_run_id']}",
        )
        thread.start()
        return str(job["enrichment_run_id"])

    def _run(self, job_id: str):
        with self._worker_lock:
            with connection() as conn:
                conn.execute(
                    "UPDATE epss_enrichment_runs SET status='running', started_at=now() WHERE enrichment_run_id=%s",
                    (job_id,),
                )
            try:
                rows, model_version, score_date = _download_epss_csv()
                queued, matched = _store_scores(rows, model_version, score_date)
                with connection() as conn:
                    conn.execute(
                        """UPDATE epss_enrichment_runs
                           SET status='completed', cves_queued=%s, cves_matched=%s,
                               finished_at=now()
                           WHERE enrichment_run_id=%s""",
                        (queued, matched, job_id),
                    )
            except Exception as exc:
                with connection() as conn:
                    conn.execute(
                        """UPDATE epss_enrichment_runs
                           SET status='failed', error_message=%s, finished_at=now()
                           WHERE enrichment_run_id=%s""",
                        (str(exc)[:500], job_id),
                    )


coordinator = EpssEnrichmentCoordinator()
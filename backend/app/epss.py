import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from psycopg.types.json import Jsonb

from .config import settings
from .database import connection


EPSS_API = "https://api.first.org/data/v1/epss"


class EpssClient:
    def __init__(self):
        self._request_lock = threading.Lock()
        self._last_request = 0.0

    def _paced_request(self, url: str) -> dict:
        with self._request_lock:
            minimum_interval = 1.0
            wait = minimum_interval - (time.monotonic() - self._last_request)
            if wait > 0:
                time.sleep(wait)
            headers = {"User-Agent": "SecureOps-Prototype/1.0", "Accept": "application/json"}
            request = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=settings.nvd_request_timeout_seconds) as response:
                    payload = json.loads(response.read().decode("utf-8"))
            finally:
                self._last_request = time.monotonic()
            return payload

    def query(self, cve_ids: list[str]) -> dict:
        # FIRST's API accepts comma-separated CVE IDs, batch up to ~100 per call
        params = {"cve": ",".join(cve_ids)}
        url = f"{EPSS_API}?{urllib.parse.urlencode(params)}"
        try:
            return self._paced_request(url)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                retry_after = int(exc.headers.get("Retry-After", "30"))
                time.sleep(min(retry_after, 60))
                return self._paced_request(url)
            raise


client = EpssClient()


def _cached_scores(cve_ids: list[str]) -> dict:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.nvd_cache_hours)
    with connection() as conn:
        rows = conn.execute(
            "SELECT cve_id, epss_score, epss_percentile FROM epss_cache "
            "WHERE cve_id = ANY(%s) AND last_refreshed_at >= %s",
            (cve_ids, cutoff),
        ).fetchall()
    return {row["cve_id"]: row for row in rows}


def _store_cache(scores: list[dict]):
    now = datetime.now(timezone.utc)
    with connection() as conn:
        for item in scores:
            conn.execute(
                """INSERT INTO epss_cache(cve_id, epss_score, epss_percentile, last_refreshed_at)
                   VALUES (%s,%s,%s,%s)
                   ON CONFLICT (cve_id) DO UPDATE SET
                     epss_score=EXCLUDED.epss_score,
                     epss_percentile=EXCLUDED.epss_percentile,
                     last_refreshed_at=EXCLUDED.last_refreshed_at""",
                (item["cve"], float(item["epss"]), float(item["percentile"]), now),
            )


def _apply_to_vulnerabilities(scores: list[dict]):
    with connection() as conn:
        for item in scores:
            conn.execute(
                """UPDATE vulnerabilities SET
                     epss_score=%s, epss_percentile=%s, epss_last_refreshed_at=%s
                   WHERE cve_id=%s""",
                (float(item["epss"]), float(item["percentile"]),
                 datetime.now(timezone.utc), item["cve"]),
            )


class EpssEnrichmentCoordinator:
    def __init__(self):
        self._worker_lock = threading.Lock()

    def schedule(self, scan_id=None, trigger_source="manual"):
        with connection() as conn:
            cve_ids = [
                row["cve_id"]
                for row in conn.execute("SELECT DISTINCT cve_id FROM vulnerabilities").fetchall()
            ]
            job = conn.execute(
                "INSERT INTO epss_enrichment_runs(scan_id, trigger_source, status, cves_queued) "
                "VALUES (%s,%s,'queued',%s) RETURNING enrichment_run_id",
                (scan_id, trigger_source, len(cve_ids)),
            ).fetchone()
        thread = threading.Thread(
            target=self._run, args=(str(job["enrichment_run_id"]), cve_ids),
            daemon=True, name=f"epss-{job['enrichment_run_id']}"
        )
        thread.start()
        return str(job["enrichment_run_id"])

    def _run(self, job_id, cve_ids):
        with self._worker_lock:
            queried = cache_hits = matched = 0
            errors = []
            with connection() as conn:
                conn.execute(
                    "UPDATE epss_enrichment_runs SET status='running', started_at=now() "
                    "WHERE enrichment_run_id=%s", (job_id,)
                )
            cached = _cached_scores(cve_ids)
            to_fetch = [cve for cve in cve_ids if cve not in cached]
            all_scores = [
                {"cve": cve, "epss": row["epss_score"], "percentile": row["epss_percentile"]}
                for cve, row in cached.items()
            ]
            cache_hits = len(cached)

            for i in range(0, len(to_fetch), 100):
                batch = to_fetch[i:i + 100]
                try:
                    response = client.query(batch)
                    data = response.get("data") or []
                    _store_cache(data)
                    all_scores.extend(data)
                    queried += len(batch)
                except Exception as exc:
                    errors.append(f"batch {i}: {exc}")

            try:
                _apply_to_vulnerabilities(all_scores)
                matched = len(all_scores)
            except Exception as exc:
                errors.append(f"apply: {exc}")

            status = "partial" if errors and (queried or cache_hits) else "failed" if errors else "completed"
            with connection() as conn:
                conn.execute(
                    """UPDATE epss_enrichment_runs SET status=%s, cves_queried=%s,
                       cache_hits=%s, cves_matched=%s, error_message=%s, finished_at=now()
                       WHERE enrichment_run_id=%s""",
                    (status, queried, cache_hits, matched,
                     "\n".join(errors)[:4000] or None, job_id),
                )


coordinator = EpssEnrichmentCoordinator()
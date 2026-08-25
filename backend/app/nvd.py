import json
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import certifi
from psycopg.types.json import Jsonb

from .config import settings
from .database import connection


NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVSS_PRIORITY = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

# The OS/Python default trust store is frequently stale (especially on Windows
# python.org builds), which surfaces as a false "certificate has expired" error
# even when the real certificate chain is valid. certifi ships a maintained,
# up-to-date CA bundle independent of the OS store, so pin outbound HTTPS
# requests to it rather than trusting whatever the platform bundles.
_SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())


def _split_cpe(value: str) -> list[str]:
    parts, current, escaped = [], [], False
    for char in value:
        if char == ":" and not escaped:
            parts.append("".join(current)); current = []; continue
        current.append(char)
        escaped = char == "\\" and not escaped
        if char != "\\": escaped = False
    parts.append("".join(current))
    return parts


def normalize_cpe(cpe: str) -> str:
    """Convert the common Nmap CPE 2.2 URI form to a CPE 2.3 formatted string."""
    cpe = cpe.strip()
    if cpe.startswith("cpe:2.3:"):
        fields = _split_cpe(cpe)[2:]
    elif cpe.startswith("cpe:/"):
        fields = _split_cpe(cpe[5:])
    else:
        raise ValueError(f"Unsupported CPE format: {cpe}")
    fields = [(field if field else "*") for field in fields]
    fields.extend(["*"] * (11 - len(fields)))
    return "cpe:2.3:" + ":".join(fields[:11])


def cpe_query_profile(cpe: str) -> tuple[str, str, str, str]:
    normalized = normalize_cpe(cpe)
    fields = _split_cpe(normalized)[2:]
    vendor, product, version = fields[1], fields[2], fields[3]
    if vendor in {"*", "-"} or product in {"*", "-"}:
        return normalized, "skip", "low", "CPE does not identify both vendor and product"
    exact_version = version not in {"*", "-"}
    generic_unversioned = product.lower() in {"windows", "linux", "android", "ios", "mac_os", "macos"} and not exact_version
    if generic_unversioned:
        return normalized, "skip", "low", "Generic unversioned platform CPE is too broad for safe automatic CVE matching"
    if exact_version:
        return normalized, "cpeName", "high", "Exact vendor, product and version CPE submitted to NVD applicability filtering"
    return normalized, "virtualMatchString", "medium", "Vendor and product identified, but version requires validation"


def select_cvss(metrics: dict) -> dict:
    for family in CVSS_PRIORITY:
        entries = metrics.get(family) or []
        if not entries:
            continue
        primary = next((entry for entry in entries if entry.get("type") == "Primary"), entries[0])
        data = primary.get("cvssData") or {}
        return {
            "version": data.get("version"),
            "score": data.get("baseScore"),
            "severity": data.get("baseSeverity") or primary.get("baseSeverity"),
            "vector": data.get("vectorString"),
        }
    return {"version": None, "score": None, "severity": None, "vector": None}


def parse_nvd_cve(item: dict, refreshed_at: datetime) -> dict:
    cve = item.get("cve") or item
    descriptions = cve.get("descriptions") or []
    description = next((entry.get("value") for entry in descriptions if entry.get("lang") == "en"), None)
    description = description or next((entry.get("value") for entry in descriptions if entry.get("value")), "No English NVD description available.")
    cvss = select_cvss(cve.get("metrics") or {})
    return {
        "cve_id": cve["id"], "source_identifier": cve.get("sourceIdentifier"),
        "published_at": cve.get("published"), "modified_at": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"), "description": description,
        "cvss_version": cvss["version"], "cvss_base_score": cvss["score"],
        "cvss_base_severity": cvss["severity"], "cvss_vector": cvss["vector"],
        "applicability_data": cve.get("configurations") or [], "raw": cve,
        "refreshed_at": refreshed_at,
    }


class NvdClient:
    def __init__(self):
        self._request_lock = threading.Lock()
        self._last_request = 0.0

    def _paced_request(self, url: str) -> dict:
        with self._request_lock:
            minimum_interval = 0.7 if settings.nvd_api_key else 6.2
            wait = minimum_interval - (time.monotonic() - self._last_request)
            if wait > 0: time.sleep(wait)
            headers = {"User-Agent": "SecureOps-Prototype/1.0", "Accept": "application/json"}
            if settings.nvd_api_key: headers["apiKey"] = settings.nvd_api_key
            request = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=settings.nvd_request_timeout_seconds, context=_SSL_CONTEXT) as response:
                    payload = json.loads(response.read().decode("utf-8"))
            finally:
                self._last_request = time.monotonic()
            return payload

    def query(self, query_type: str, query_cpe: str) -> dict:
        params = {query_type: query_cpe, "resultsPerPage": str(min(settings.nvd_max_results_per_cpe, 2000))}
        url = f"{NVD_CVE_API}?{urllib.parse.urlencode(params)}"
        try:
            return self._paced_request(url)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                retry_after = int(exc.headers.get("Retry-After", "30"))
                time.sleep(min(retry_after, 60))
                return self._paced_request(url)
            raise


client = NvdClient()


def _cached_response(cpe: str):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.nvd_cache_hours)
    with connection() as conn:
        return conn.execute("SELECT * FROM nvd_cpe_cache WHERE cpe_name=%s AND last_refreshed_at >= %s AND response_data IS NOT NULL", (cpe, cutoff)).fetchone()


def _store_cache(cpe, query_cpe, query_type, response, error=None):
    now = datetime.now(timezone.utc)
    count = len((response or {}).get("vulnerabilities") or [])
    with connection() as conn:
        conn.execute("""INSERT INTO nvd_cpe_cache(cpe_name,query_cpe,query_type,result_count,response_data,last_refreshed_at,last_error,next_retry_at)
          VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (cpe_name) DO UPDATE SET query_cpe=EXCLUDED.query_cpe,query_type=EXCLUDED.query_type,
          result_count=EXCLUDED.result_count,response_data=EXCLUDED.response_data,last_refreshed_at=EXCLUDED.last_refreshed_at,last_error=EXCLUDED.last_error,next_retry_at=EXCLUDED.next_retry_at""",
          (cpe,query_cpe,query_type,count,Jsonb(response) if response is not None else None,now,error,now + timedelta(hours=24) if error else None))


def _upsert_matches(services: list[dict], cpe: str, response: dict, base_confidence: str, reason: str) -> int:
    refreshed_at = datetime.now(timezone.utc)
    parsed = [parse_nvd_cve(item, refreshed_at) for item in response.get("vulnerabilities") or []]
    parsed = parsed[: settings.nvd_max_results_per_cpe]
    with connection() as conn:
        for vulnerability in parsed:
            conn.execute("""INSERT INTO vulnerabilities(cve_id,source_identifier,published_at,modified_at,vuln_status,description,cvss_version,cvss_base_score,cvss_base_severity,cvss_vector,applicability_data,raw_nvd_data,nvd_last_refreshed_at)
              VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (cve_id) DO UPDATE SET source_identifier=EXCLUDED.source_identifier,
              published_at=EXCLUDED.published_at,modified_at=EXCLUDED.modified_at,vuln_status=EXCLUDED.vuln_status,description=EXCLUDED.description,
              cvss_version=EXCLUDED.cvss_version,cvss_base_score=EXCLUDED.cvss_base_score,cvss_base_severity=EXCLUDED.cvss_base_severity,
              cvss_vector=EXCLUDED.cvss_vector,applicability_data=EXCLUDED.applicability_data,raw_nvd_data=EXCLUDED.raw_nvd_data,nvd_last_refreshed_at=EXCLUDED.nvd_last_refreshed_at,updated_at=now()""",
              (vulnerability["cve_id"],vulnerability["source_identifier"],vulnerability["published_at"],vulnerability["modified_at"],vulnerability["vuln_status"],vulnerability["description"],vulnerability["cvss_version"],vulnerability["cvss_base_score"],vulnerability["cvss_base_severity"],vulnerability["cvss_vector"],Jsonb(vulnerability["applicability_data"]),Jsonb(vulnerability["raw"]),refreshed_at))
            for service in services:
                service_confidence = service.get("confidence") or "low"
                confidence = base_confidence
                if service_confidence == "low": confidence = "low"
                elif service_confidence == "medium" and confidence == "high": confidence = "medium"
                wording = {"high":"Likely affected - high-confidence match","medium":"Potentially affected - verify version","low":"Possible exposure - requires validation"}[confidence]
                applicability = "likely" if confidence == "high" else "candidate"
                conn.execute("""INSERT INTO service_vulnerabilities(service_id,cve_id,matched_cpe,match_confidence,match_wording,match_reason,applicability_status,status,first_seen,last_seen,last_checked_at)
                  VALUES (%s,%s,%s,%s,%s,%s,%s,'active',%s,%s,%s) ON CONFLICT (service_id,cve_id) DO UPDATE SET matched_cpe=EXCLUDED.matched_cpe,
                  match_confidence=EXCLUDED.match_confidence,match_wording=EXCLUDED.match_wording,match_reason=EXCLUDED.match_reason,
                  applicability_status=EXCLUDED.applicability_status,last_seen=EXCLUDED.last_seen,last_checked_at=EXCLUDED.last_checked_at""",
                  (service["service_id"],vulnerability["cve_id"],cpe,confidence,wording,reason,applicability,refreshed_at,refreshed_at,refreshed_at))
                conn.execute("UPDATE services SET enrichment_status='enriched',updated_at=now() WHERE service_id=%s", (service["service_id"],))
    return len(parsed) * len(services)


class NvdEnrichmentCoordinator:
    def __init__(self):
        self._worker_lock = threading.Lock()

    def schedule(self, scan_id=None, trigger_source="scan", service_ids=None):
        with connection() as conn:
            if service_ids is not None:
                rows = conn.execute("SELECT service_id,cpe,confidence FROM services WHERE service_id=ANY(%s::uuid[]) AND cpe IS NOT NULL AND state='open'", (service_ids,)).fetchall()
            else:
                rows = conn.execute("SELECT service_id,cpe,confidence FROM services WHERE cpe IS NOT NULL AND state='open'").fetchall()
            unique_cpes = {row["cpe"] for row in rows}
            job = conn.execute("INSERT INTO nvd_enrichment_runs(scan_id,trigger_source,status,cpes_queued) VALUES (%s,%s,'queued',%s) RETURNING enrichment_run_id", (scan_id,trigger_source,len(unique_cpes))).fetchone()
        thread = threading.Thread(target=self._run, args=(str(job["enrichment_run_id"]), rows), daemon=True, name=f"nvd-{job['enrichment_run_id']}")
        thread.start()
        return str(job["enrichment_run_id"])

    def _run(self, job_id, rows):
        with self._worker_lock:
            queried = cache_hits = matched = 0
            errors = []
            with connection() as conn:
                conn.execute("UPDATE nvd_enrichment_runs SET status='running',started_at=now() WHERE enrichment_run_id=%s", (job_id,))
            grouped = {}
            for row in rows: grouped.setdefault(row["cpe"], []).append(row)
            for cpe, services in grouped.items():
                try:
                    query_cpe, query_type, confidence, reason = cpe_query_profile(cpe)
                    if query_type == "skip":
                        _store_cache(cpe, query_cpe, query_type, None, reason)
                        continue
                    cached = _cached_response(cpe)
                    if cached:
                        response = cached["response_data"]; cache_hits += 1
                    else:
                        response = client.query(query_type, query_cpe); queried += 1
                        _store_cache(cpe, query_cpe, query_type, response)
                    matched += _upsert_matches(services, cpe, response, confidence, reason)
                except Exception as exc:
                    errors.append(f"{cpe}: {exc}")
                    try: _store_cache(cpe, cpe, "failed", None, str(exc)[:500])
                    except Exception: pass
            status = "partial" if errors and (queried or cache_hits) else "failed" if errors else "completed"
            with connection() as conn:
                conn.execute("""UPDATE nvd_enrichment_runs SET status=%s,cpes_queried=%s,cache_hits=%s,cves_matched=%s,error_message=%s,finished_at=now()
                  WHERE enrichment_run_id=%s""", (status,queried,cache_hits,matched,"\n".join(errors)[:4000] or None,job_id))


coordinator = NvdEnrichmentCoordinator()

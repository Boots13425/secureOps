import json
import ssl
import urllib.request

import certifi

from .database import connection

KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# See nvd.py for why this is pinned rather than trusting the platform default.
_SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())


def _download_kev_catalog() -> list[dict]:
    request = urllib.request.Request(KEV_JSON_URL, headers={"User-Agent": "SecureOps-Prototype/1.0"})
    with urllib.request.urlopen(request, timeout=60, context=_SSL_CONTEXT) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return payload.get("vulnerabilities") or []


def refresh_kev() -> dict:
    """Flag every CVE Layer 4 has already matched that also appears in CISA's
    Known Exploited Vulnerabilities catalog — confirmed real-world exploitation,
    not a prediction, so it must outrank CVSS/EPSS in prioritization.

    Re-derives kev_flag from scratch each run (rather than only ever setting it
    true) so a CVE that's later removed from the catalog stops being flagged
    too, instead of staying stuck as a stale positive forever."""
    with connection() as conn:
        known = {row["cve_id"] for row in conn.execute("SELECT cve_id FROM vulnerabilities").fetchall()}
    if not known:
        return {"flagged": 0}
    kev_by_cve = {entry.get("cveID"): entry for entry in _download_kev_catalog()}
    flagged = 0
    with connection() as conn:
        for cve_id in known:
            entry = kev_by_cve.get(cve_id)
            if entry:
                conn.execute(
                    """UPDATE vulnerabilities SET kev_flag=true, kev_date_added=%s, kev_required_action=%s,
                      kev_due_date=%s, updated_at=now() WHERE cve_id=%s""",
                    (entry.get("dateAdded"), entry.get("requiredAction"), entry.get("dueDate"), cve_id),
                )
                flagged += 1
            else:
                conn.execute("UPDATE vulnerabilities SET kev_flag=false WHERE cve_id=%s AND kev_flag=true", (cve_id,))
    return {"flagged": flagged}

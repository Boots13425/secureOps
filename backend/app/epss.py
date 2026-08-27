import csv
import gzip
import re
import ssl
import urllib.request
from datetime import date, datetime, timezone

import certifi

from .database import connection

EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

# See nvd.py for why this is pinned rather than trusting the platform default.
_SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())


def _download_epss_csv() -> tuple[date, list[dict]]:
    request = urllib.request.Request(EPSS_CSV_URL, headers={"User-Agent": "SecureOps-Prototype/1.0"})
    with urllib.request.urlopen(request, timeout=60, context=_SSL_CONTEXT) as response:
        raw = gzip.decompress(response.read())
    lines = raw.decode("utf-8").splitlines()
    match = re.search(r"score_date:(\S+)", lines[0])
    score_date = datetime.fromisoformat(match.group(1).replace("Z", "+00:00")).date() if match else datetime.now(timezone.utc).date()
    return score_date, list(csv.DictReader(lines[1:]))


def refresh_epss() -> dict:
    """Attach FIRST.org's daily exploitation-probability score to every CVE
    Layer 4 has already matched. A CVE Layer 4 hasn't found yet has nothing
    to attach a score to, so this only ever enriches existing rows."""
    with connection() as conn:
        known = {row["cve_id"] for row in conn.execute("SELECT cve_id FROM vulnerabilities").fetchall()}
    if not known:
        return {"updated": 0, "score_date": None}
    score_date, rows = _download_epss_csv()
    updated = 0
    with connection() as conn:
        for row in rows:
            cve_id = row.get("cve")
            if cve_id not in known:
                continue
            conn.execute(
                "UPDATE vulnerabilities SET epss_score=%s, epss_percentile=%s, epss_date=%s, updated_at=now() WHERE cve_id=%s",
                (float(row["epss"]), float(row["percentile"]), score_date, cve_id),
            )
            updated += 1
    return {"updated": updated, "score_date": score_date.isoformat()}

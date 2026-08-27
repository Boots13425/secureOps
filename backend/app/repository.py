import ipaddress
from datetime import datetime, timezone
from uuid import UUID
from psycopg.types.json import Jsonb

from .database import connection
from .scanner import HostObservation
from .findings import evaluate_host


def _serialize(row):
    if row is None: return None
    string_types = (UUID, ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address, ipaddress.IPv6Network)
    return {key: (str(value) if isinstance(value, string_types) else value) for key, value in row.items()}


def list_assets(status=None, device_type=None):
    clauses, params = [], []
    if status: clauses.append("a.status = %s"); params.append(status)
    if device_type: clauses.append("a.device_type = %s"); params.append(device_type)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""
      SELECT a.asset_id AS id, a.asset_id, host(a.ip_address) AS ip,
             host(a.ip_address) AS ip_address, a.mac_address::text, a.vendor,
             a.hostname, a.device_type, a.os_family AS os_name, a.os_confidence,
             CASE WHEN a.os_family IS NOT NULL THEN 'nmap' END AS os_source,
             a.status, a.first_seen, a.last_seen,
             (SELECT count(*) FROM services current_service WHERE current_service.asset_id=a.asset_id AND current_service.state='open') AS service_count,
             CASE WHEN EXISTS (SELECT 1 FROM asset_observations o WHERE o.asset_id=a.asset_id)
               THEN ARRAY['nmap']::text[] ELSE ARRAY[]::text[] END AS discovery_sources,
             COALESCE((SELECT json_agg(json_build_object('service_id',s.service_id,'port',s.port,'protocol',s.protocol,'name',s.service_name,'product',s.product,'version',s.version,'cpe',s.cpe,'confidence',s.confidence,'enrichment_status',s.enrichment_status) ORDER BY s.port)
               FROM services s WHERE s.asset_id=a.asset_id AND s.state='open'), '[]') AS services
      FROM assets a {where} ORDER BY a.last_seen DESC
    """
    with connection() as conn: return [_serialize(row) for row in conn.execute(sql, params).fetchall()]


def update_asset(asset_id, values):
    allowed = {key: value for key, value in values.items() if value is not None and key in {"status", "device_type"}}
    if not allowed: return None
    assignments = ", ".join(f"{key} = %s" for key in allowed)
    with connection() as conn:
        row = conn.execute(f"UPDATE assets SET {assignments}, updated_at=now() WHERE asset_id=%s RETURNING asset_id AS id, *", [*allowed.values(), asset_id]).fetchone()
        return _serialize(row)


def create_session(subnet, duration_minutes=None, source="manual"):
    mode = "bounded" if duration_minutes else "continuous"
    with connection() as conn:
        row = conn.execute("INSERT INTO scan_sessions(subnet,status,mode,duration_minutes,source) VALUES (%s,'RUNNING',%s,%s,%s) RETURNING *", (subnet, mode, duration_minutes, source)).fetchone()
        conn.execute("INSERT INTO scan_activity(scan_id,event_type,message,detail) VALUES (%s,'SESSION_STARTED','Scan session started',%s)", (row["id"], subnet))
        return _serialize(row)


def get_session(session_id):
    with connection() as conn: return _serialize(conn.execute("SELECT * FROM scan_sessions WHERE id=%s", (session_id,)).fetchone())


def list_sessions():
    with connection() as conn: return [_serialize(row) for row in conn.execute("SELECT *, started_at, finished_at FROM scan_sessions ORDER BY started_at DESC LIMIT 100").fetchall()]


def finish_session(session_id, status, devices_found=0, error=None):
    with connection() as conn:
        row = conn.execute("UPDATE scan_sessions SET status=%s, finished_at=now(), devices_found=%s, error_message=%s WHERE id=%s RETURNING *", (status, devices_found, error, session_id)).fetchone()
        event = f"SESSION_{status}"
        message = {"COMPLETED":"Scan completed","STOPPED":"Scan stopped","FAILED":"Scan failed"}[status]
        conn.execute("INSERT INTO scan_activity(scan_id,event_type,message,detail) VALUES (%s,%s,%s,%s)", (session_id, event, message, error or f"{devices_found} live hosts"))
        return _serialize(row)


def store_scan_results(session_id, subnet, hosts: list[HostObservation], record_activity=True):
    observed_at = datetime.now(timezone.utc)
    seen_ids = []
    with connection() as conn:
        for host in hosts:
            existing = None
            if host.mac_address:
                existing = conn.execute("SELECT * FROM assets WHERE mac_address=%s", (host.mac_address,)).fetchone()
            if not existing:
                existing = conn.execute("SELECT * FROM assets WHERE ip_address=%s AND mac_address IS NULL", (host.ip_address,)).fetchone()
            if existing:
                next_status = existing["status"] if existing["status"] in {"approved", "unknown", "known"} else "known"
                asset = conn.execute("""UPDATE assets SET ip_address=%s, mac_address=COALESCE(%s,mac_address), vendor=COALESCE(%s,vendor), hostname=COALESCE(%s,hostname),
                  device_type=CASE WHEN %s='unknown' THEN device_type ELSE %s END, os_family=COALESCE(%s,os_family), os_confidence=COALESCE(%s,os_confidence), status=%s, last_seen=%s, updated_at=now()
                  WHERE asset_id=%s RETURNING *""", (host.ip_address,host.mac_address,host.vendor,host.hostname,host.device_type,host.device_type,host.os_family,host.os_confidence,next_status,observed_at,existing["asset_id"])).fetchone()
                event_type, message = "ASSET_UPDATED", "Known asset observed"
            else:
                asset = conn.execute("""INSERT INTO assets(ip_address,mac_address,vendor,hostname,device_type,os_family,os_confidence,status,first_seen,last_seen)
                  VALUES (%s,%s,%s,%s,%s,%s,%s,'unknown',%s,%s) RETURNING *""", (host.ip_address,host.mac_address,host.vendor,host.hostname,host.device_type,host.os_family,host.os_confidence,observed_at,observed_at)).fetchone()
                event_type, message = "ASSET_DISCOVERED", "New unknown asset discovered"
                host.is_new_asset = True
            host.asset_id = str(asset["asset_id"])
            seen_ids.append(asset["asset_id"])
            observation = conn.execute("""INSERT INTO asset_observations(asset_id,scan_id,observed_at,ip_address,mac_address,hostname,vendor,os_family,os_confidence)
              VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
              ON CONFLICT (asset_id,scan_id) DO UPDATE SET ip_address=EXCLUDED.ip_address, mac_address=COALESCE(EXCLUDED.mac_address,asset_observations.mac_address),
                hostname=COALESCE(EXCLUDED.hostname,asset_observations.hostname), vendor=COALESCE(EXCLUDED.vendor,asset_observations.vendor),
                os_family=COALESCE(EXCLUDED.os_family,asset_observations.os_family), os_confidence=COALESCE(EXCLUDED.os_confidence,asset_observations.os_confidence)
              RETURNING observation_id""", (asset["asset_id"],session_id,observed_at,host.ip_address,host.mac_address,host.hostname,host.vendor,host.os_family,host.os_confidence)).fetchone()
            for service in host.services:
                existing_service = conn.execute("SELECT service_id FROM services WHERE asset_id=%s AND port=%s AND protocol=%s", (asset["asset_id"],service.port,service.protocol)).fetchone()
                conn.execute("""INSERT INTO observed_services(observation_id,port,protocol,state,service_name,product,version,cpe,detection_source,confidence,confidence_score,enrichment_status,observed_at)
                  VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                  ON CONFLICT (observation_id,port,protocol) DO UPDATE SET state=EXCLUDED.state, service_name=EXCLUDED.service_name,
                    product=EXCLUDED.product, version=EXCLUDED.version, cpe=EXCLUDED.cpe, detection_source=EXCLUDED.detection_source,
                    confidence=EXCLUDED.confidence, confidence_score=EXCLUDED.confidence_score, enrichment_status=EXCLUDED.enrichment_status,
                    observed_at=EXCLUDED.observed_at""", (observation["observation_id"],service.port,service.protocol,service.state,service.name,service.product,service.version,service.cpe,service.detection_source,service.confidence,service.confidence_score,service.enrichment_status,observed_at))
                current_service = conn.execute("""INSERT INTO services(asset_id,port,protocol,state,service_name,product,version,cpe,detection_source,confidence,confidence_score,enrichment_status,first_seen,last_seen,last_observation_id)
                  VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                  ON CONFLICT (asset_id,port,protocol) DO UPDATE SET state=EXCLUDED.state, service_name=COALESCE(EXCLUDED.service_name,services.service_name),
                    product=COALESCE(EXCLUDED.product,services.product), version=COALESCE(EXCLUDED.version,services.version), cpe=COALESCE(EXCLUDED.cpe,services.cpe),
                    detection_source=EXCLUDED.detection_source, confidence=EXCLUDED.confidence, confidence_score=EXCLUDED.confidence_score,
                    enrichment_status=CASE WHEN EXCLUDED.cpe IS NULL THEN services.enrichment_status ELSE EXCLUDED.enrichment_status END,
                    last_seen=EXCLUDED.last_seen, last_observation_id=EXCLUDED.last_observation_id, updated_at=now()
                  RETURNING service_id""",
                    (asset["asset_id"],service.port,service.protocol,service.state,service.name,service.product,service.version,service.cpe,service.detection_source,service.confidence,service.confidence_score,service.enrichment_status,observed_at,observed_at,observation["observation_id"])).fetchone()
                service.service_id = str(current_service["service_id"])
                service.is_new = existing_service is None and not host.is_new_asset
            if record_activity:
                conn.execute("INSERT INTO scan_activity(scan_id,event_type,message,detail) VALUES (%s,%s,%s,%s)", (session_id,event_type,message,f"{host.ip_address} · {host.hostname or 'unresolved'} · {len(host.services)} services"))
        if seen_ids:
            conn.execute("UPDATE assets SET status='missing', updated_at=now() WHERE ip_address <<= %s::cidr AND asset_id <> ALL(%s::uuid[])", (subnet, seen_ids))
        else:
            conn.execute("UPDATE assets SET status='missing', updated_at=now() WHERE ip_address <<= %s::cidr", (subnet,))


def list_activity(limit):
    with connection() as conn:
        rows = conn.execute("SELECT id,message,detail,created_at AS timestamp,event_type FROM scan_activity ORDER BY created_at DESC LIMIT %s", (limit,)).fetchall()
        return [_serialize(row) for row in rows]


def add_activity(session_id, event_type, message, detail=None):
    with connection() as conn:
        conn.execute("INSERT INTO scan_activity(scan_id,event_type,message,detail) VALUES (%s,%s,%s,%s)", (session_id,event_type,message,detail))


def list_exposure_checks(session_id):
    with connection() as conn:
        rows = conn.execute("""SELECT r.check_run_id,r.scan_id,r.asset_id,r.check_id,r.port,r.protocol,r.status,r.output,r.executed_at,
          host(a.ip_address) AS ip_address,a.hostname FROM exposure_check_runs r JOIN assets a ON a.asset_id=r.asset_id
          WHERE r.scan_id=%s ORDER BY a.ip_address,r.port,r.check_id""", (session_id,)).fetchall()
        return [_serialize(row) for row in rows]


def scan_history():
    with connection() as conn:
        rows = conn.execute("""SELECT finished_at AS ts, devices_found, (SELECT count(*) FROM assets) AS known_total
          FROM scan_sessions WHERE status='COMPLETED' ORDER BY finished_at ASC LIMIT 100""").fetchall()
        return [_serialize(row) for row in rows]


def list_services(asset_id=None, confidence=None, enrichment_status=None, port=None, query=None):
    clauses, params = ["s.state = 'open'"], []
    if asset_id: clauses.append("s.asset_id = %s"); params.append(asset_id)
    if confidence: clauses.append("s.confidence = %s"); params.append(confidence)
    if enrichment_status: clauses.append("s.enrichment_status = %s"); params.append(enrichment_status)
    if port: clauses.append("s.port = %s"); params.append(port)
    if query:
        clauses.append("(a.hostname ILIKE %s OR host(a.ip_address) ILIKE %s OR s.service_name ILIKE %s OR s.product ILIKE %s OR s.version ILIKE %s OR s.cpe ILIKE %s)")
        params.extend([f"%{query}%"] * 6)
    sql = f"""SELECT s.service_id, s.asset_id, host(a.ip_address) AS ip_address, a.hostname, a.device_type,
      s.port, s.protocol, s.state, s.service_name, s.product, s.version, s.cpe, s.detection_source,
      s.confidence, s.confidence_score, s.enrichment_status, s.first_seen, s.last_seen
      FROM services s JOIN assets a ON a.asset_id=s.asset_id
      WHERE {' AND '.join(clauses)} ORDER BY s.last_seen DESC, a.ip_address, s.port"""
    with connection() as conn:
        return [_serialize(row) for row in conn.execute(sql, params).fetchall()]


def service_summary():
    with connection() as conn:
        row = conn.execute("""SELECT count(*) FILTER (WHERE state='open') AS total,
          count(DISTINCT asset_id) FILTER (WHERE state='open') AS exposed_assets,
          count(*) FILTER (WHERE state='open' AND cpe IS NOT NULL AND enrichment_status <> 'not_enriched') AS cpe_ready,
          count(*) FILTER (WHERE state='open' AND enrichment_status='not_enriched') AS not_enriched,
          count(*) FILTER (WHERE state='open' AND confidence='high') AS high_confidence
          FROM services""").fetchone()
        return _serialize(row)


def store_exposure_results(session_id, hosts: list[HostObservation]):
    observed_at = datetime.now(timezone.utc)
    created = 0
    with connection() as conn:
        for host in hosts:
            if not host.asset_id:
                continue
            for check in host.exposure_checks:
                row = conn.execute("""INSERT INTO exposure_check_runs(scan_id,asset_id,check_id,port,protocol,status,output,structured_output,executed_at)
                  VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING check_run_id""",
                  (session_id,host.asset_id,check.check_id,check.port,check.protocol,check.status,check.output,Jsonb(check.structured_output),observed_at)).fetchone()
                check.check_run_id = str(row["check_run_id"])
            for candidate in evaluate_host(host, observed_at):
                finding = conn.execute("""INSERT INTO findings(finding_key,asset_id,service_id,check_id,title,evidence,severity,confidence,why_it_matters,recommendation,source,status,first_seen,last_seen)
                  VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'network_exposure_check','open',%s,%s)
                  ON CONFLICT (finding_key) DO UPDATE SET service_id=EXCLUDED.service_id, evidence=EXCLUDED.evidence,
                    severity=EXCLUDED.severity, confidence=EXCLUDED.confidence, why_it_matters=EXCLUDED.why_it_matters,
                    recommendation=EXCLUDED.recommendation, status=CASE WHEN findings.status='resolved' THEN 'open' ELSE findings.status END,
                    last_seen=EXCLUDED.last_seen, updated_at=now()
                  RETURNING finding_id, (xmax = 0) AS inserted""",
                  (candidate.key,candidate.asset_id,candidate.service_id,candidate.check_id,candidate.title,candidate.evidence,candidate.severity,candidate.confidence,candidate.why_it_matters,candidate.recommendation,observed_at,observed_at)).fetchone()
                conn.execute("""INSERT INTO finding_observations(finding_id,scan_id,check_run_id,evidence,observed_at)
                  VALUES (%s,%s,%s,%s,%s) ON CONFLICT (finding_id,scan_id) DO UPDATE SET check_run_id=EXCLUDED.check_run_id,evidence=EXCLUDED.evidence,observed_at=EXCLUDED.observed_at""",
                  (finding["finding_id"],session_id,candidate.check_run_id,candidate.evidence,observed_at))
                created += int(finding["inserted"])
        if created:
            conn.execute("INSERT INTO scan_activity(scan_id,event_type,message,detail) VALUES (%s,'FINDINGS_UPDATED','Security exposure findings updated',%s)", (session_id,f"{created} new finding(s)"))
    return created


def list_findings(status=None, severity=None, confidence=None, check_id=None, query=None):
    clauses, params = [], []
    if status: clauses.append("f.status=%s"); params.append(status)
    if severity: clauses.append("f.severity=%s"); params.append(severity)
    if confidence: clauses.append("f.confidence=%s"); params.append(confidence)
    if check_id: clauses.append("f.check_id=%s"); params.append(check_id)
    if query:
        clauses.append("(f.title ILIKE %s OR f.evidence ILIKE %s OR a.hostname ILIKE %s OR host(a.ip_address) ILIKE %s)")
        params.extend([f"%{query}%"] * 4)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""SELECT f.*, host(a.ip_address) AS ip_address, a.hostname, a.device_type,
      s.port, s.protocol, s.service_name, s.product, s.version
      FROM findings f JOIN assets a ON a.asset_id=f.asset_id LEFT JOIN services s ON s.service_id=f.service_id
      {where} ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.last_seen DESC"""
    with connection() as conn:
        return [_serialize(row) for row in conn.execute(sql, params).fetchall()]


def findings_summary():
    with connection() as conn:
        return _serialize(conn.execute("""SELECT count(*) FILTER (WHERE status='open') AS open,
          count(*) FILTER (WHERE status='open' AND severity='critical') AS critical,
          count(*) FILTER (WHERE status='open' AND severity='high') AS high,
          count(*) FILTER (WHERE status='open' AND severity='medium') AS medium,
          count(DISTINCT asset_id) FILTER (WHERE status='open') AS affected_assets
          FROM findings""").fetchone())


def update_finding_status(finding_id, status):
    with connection() as conn:
        return _serialize(conn.execute("UPDATE findings SET status=%s,updated_at=now() WHERE finding_id=%s RETURNING *", (status,finding_id)).fetchone())


def list_vulnerabilities(status=None, severity=None, confidence=None, query=None):
    clauses, params = [], []
    if status: clauses.append("sv.status=%s"); params.append(status)
    if severity: clauses.append("upper(v.cvss_base_severity)=%s"); params.append(severity.upper())
    if confidence: clauses.append("sv.match_confidence=%s"); params.append(confidence)
    if query:
        clauses.append("(v.cve_id ILIKE %s OR v.description ILIKE %s OR a.hostname ILIKE %s OR host(a.ip_address) ILIKE %s OR s.product ILIKE %s OR s.cpe ILIKE %s)")
        params.extend([f"%{query}%"] * 6)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""SELECT sv.service_vulnerability_id,sv.service_id,sv.cve_id,sv.matched_cpe,sv.match_confidence,sv.match_wording,
      sv.match_reason,sv.applicability_status,sv.status,sv.first_seen,sv.last_seen,sv.last_checked_at,
      v.description,v.published_at,v.modified_at,v.vuln_status,v.cvss_version,v.cvss_base_score,v.cvss_base_severity,v.cvss_vector,v.nvd_last_refreshed_at,
      e.epss_score,e.epss_percentile,e.epss_date,sv.organization_risk_score,sv.organization_risk_band,sv.risk_calculated_at,
      s.asset_id,s.port,s.protocol,s.service_name,s.product,s.version,s.cpe,host(a.ip_address) AS ip_address,a.hostname,a.device_type
      FROM service_vulnerabilities sv JOIN vulnerabilities v ON v.cve_id=sv.cve_id JOIN services s ON s.service_id=sv.service_id
      JOIN assets a ON a.asset_id=s.asset_id LEFT JOIN epss_current_scores e ON e.cve_id=v.cve_id {where}
      ORDER BY sv.organization_risk_score DESC NULLS LAST,v.cvss_base_score DESC NULLS LAST,sv.match_confidence,sv.last_seen DESC"""
    with connection() as conn:
        return [_serialize(row) for row in conn.execute(sql, params).fetchall()]


def vulnerabilities_summary():
    with connection() as conn:
        return _serialize(conn.execute("""SELECT count(*) FILTER (WHERE sv.status='active') AS active_matches,
          count(*) FILTER (WHERE sv.status='active' AND upper(v.cvss_base_severity)='CRITICAL') AS critical,
          count(*) FILTER (WHERE sv.status='active' AND upper(v.cvss_base_severity)='HIGH') AS high,
          count(*) FILTER (WHERE sv.status='active' AND sv.match_confidence='high') AS high_confidence,
          count(DISTINCT s.asset_id) FILTER (WHERE sv.status='active') AS affected_assets,
          max(v.nvd_last_refreshed_at) AS last_refreshed_at
          FROM service_vulnerabilities sv JOIN vulnerabilities v ON v.cve_id=sv.cve_id JOIN services s ON s.service_id=sv.service_id""").fetchone())


def update_vulnerability_match_status(match_id, status):
    with connection() as conn:
        return _serialize(conn.execute("UPDATE service_vulnerabilities SET status=%s,last_checked_at=now() WHERE service_vulnerability_id=%s RETURNING *", (status,match_id)).fetchone())


def list_enrichment_runs(limit=20):
    with connection() as conn:
        return [_serialize(row) for row in conn.execute("SELECT * FROM nvd_enrichment_runs ORDER BY queued_at DESC LIMIT %s", (limit,)).fetchall()]


def list_epss_intelligence(status="active", query=None):
    clauses, params = [], []
    if status: clauses.append("sv.status=%s"); params.append(status)
    if query:
        clauses.append("(v.cve_id ILIKE %s OR v.description ILIKE %s OR a.hostname ILIKE %s OR host(a.ip_address) ILIKE %s OR s.product ILIKE %s)")
        params.extend([f"%{query}%"] * 5)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""SELECT sv.service_vulnerability_id,sv.status,sv.match_confidence,sv.match_wording,
      sv.organization_risk_score,sv.organization_risk_band,sv.risk_calculated_at,
      v.cve_id,v.description,v.cvss_base_score,v.cvss_base_severity,
      e.epss_score,e.epss_percentile,e.epss_date,
      s.asset_id,s.port,s.protocol,s.service_name,s.product,s.version,
      host(a.ip_address) AS ip_address,a.hostname,a.device_type,a.status AS asset_status
      FROM service_vulnerabilities sv
      JOIN vulnerabilities v ON v.cve_id=sv.cve_id
      JOIN services s ON s.service_id=sv.service_id
      JOIN assets a ON a.asset_id=s.asset_id
      LEFT JOIN epss_current_scores e ON e.cve_id=v.cve_id
      {where}
      ORDER BY sv.organization_risk_score DESC NULLS LAST,e.epss_score DESC NULLS LAST,v.cvss_base_score DESC NULLS LAST"""
    with connection() as conn:
        return [_serialize(row) for row in conn.execute(sql, params).fetchall()]


def epss_summary():
    with connection() as conn:
        return _serialize(conn.execute("""SELECT
          count(DISTINCT v.cve_id) FILTER (WHERE sv.status='active') AS discovered_cves,
          count(DISTINCT v.cve_id) FILTER (WHERE sv.status='active' AND e.cve_id IS NOT NULL) AS scored_cves,
          max(e.epss_score) FILTER (WHERE sv.status='active') AS highest_epss_score,
          max(e.epss_percentile) FILTER (WHERE sv.status='active') AS highest_percentile,
          count(*) FILTER (WHERE sv.status='active' AND sv.organization_risk_band IN ('critical','high')) AS high_risk_matches,
          max(e.epss_date) AS latest_epss_date
          FROM service_vulnerabilities sv
          JOIN vulnerabilities v ON v.cve_id=sv.cve_id
          LEFT JOIN epss_current_scores e ON e.cve_id=v.cve_id""").fetchone())


def list_epss_runs(limit=20):
    with connection() as conn:
        return [_serialize(row) for row in conn.execute("SELECT * FROM epss_download_runs ORDER BY queued_at DESC LIMIT %s", (limit,)).fetchall()]

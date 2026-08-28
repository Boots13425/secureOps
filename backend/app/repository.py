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


def list_assets(status=None, device_type=None, scan_id=None):
    clauses, params = [], []
    if status: clauses.append("a.status = %s"); params.append(status)
    if device_type: clauses.append("a.device_type = %s"); params.append(device_type)
    if scan_id: clauses.append("EXISTS (SELECT 1 FROM asset_observations so WHERE so.asset_id=a.asset_id AND so.scan_id=%s)"); params.append(scan_id)
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
    allowed = {key: value for key, value in values.items() if value is not None and key in {"status", "device_type", "criticality"}}
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


def list_activity(limit, scan_id=None):
    clause = "WHERE scan_id=%s " if scan_id else ""
    params = (scan_id, limit) if scan_id else (limit,)
    with connection() as conn:
        rows = conn.execute(f"SELECT id,message,detail,created_at AS timestamp,event_type FROM scan_activity {clause}ORDER BY created_at DESC LIMIT %s", params).fetchall()
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


def list_services(asset_id=None, confidence=None, enrichment_status=None, port=None, query=None, scan_id=None):
    clauses, params = ["s.state = 'open'"], []
    if asset_id: clauses.append("s.asset_id = %s"); params.append(asset_id)
    if confidence: clauses.append("s.confidence = %s"); params.append(confidence)
    if enrichment_status: clauses.append("s.enrichment_status = %s"); params.append(enrichment_status)
    if port: clauses.append("s.port = %s"); params.append(port)
    if scan_id:
        clauses.append("""EXISTS (SELECT 1 FROM observed_services os JOIN asset_observations ao ON ao.observation_id=os.observation_id
          WHERE ao.asset_id=s.asset_id AND os.port=s.port AND os.protocol=s.protocol AND ao.scan_id=%s)""")
        params.append(scan_id)
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


def list_findings(status=None, severity=None, confidence=None, check_id=None, query=None, scan_id=None):
    clauses, params = [], []
    if status: clauses.append("f.status=%s"); params.append(status)
    if severity: clauses.append("f.severity=%s"); params.append(severity)
    if confidence: clauses.append("f.confidence=%s"); params.append(confidence)
    if check_id: clauses.append("f.check_id=%s"); params.append(check_id)
    if scan_id: clauses.append("EXISTS (SELECT 1 FROM finding_observations fo WHERE fo.finding_id=f.finding_id AND fo.scan_id=%s)"); params.append(scan_id)
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


def list_vulnerabilities(status=None, severity=None, confidence=None, query=None, scan_id=None):
    clauses, params = [], []
    if status: clauses.append("sv.status=%s"); params.append(status)
    if severity: clauses.append("upper(v.cvss_base_severity)=%s"); params.append(severity.upper())
    if confidence: clauses.append("sv.match_confidence=%s"); params.append(confidence)
    if query:
        clauses.append("(v.cve_id ILIKE %s OR v.description ILIKE %s OR a.hostname ILIKE %s OR host(a.ip_address) ILIKE %s OR s.product ILIKE %s OR s.cpe ILIKE %s)")
        params.extend([f"%{query}%"] * 6)
    if scan_id:
        clauses.append("""EXISTS (SELECT 1 FROM observed_services os JOIN asset_observations ao ON ao.observation_id=os.observation_id
          WHERE ao.asset_id=s.asset_id AND os.port=s.port AND os.protocol=s.protocol AND ao.scan_id=%s)""")
        params.append(scan_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""SELECT sv.service_vulnerability_id,sv.service_id,sv.cve_id,sv.matched_cpe,sv.match_confidence,sv.match_wording,
      sv.match_reason,sv.applicability_status,sv.status,sv.first_seen,sv.last_seen,sv.last_checked_at,
      sv.organization_risk_score,sv.organization_risk_band,
      v.description,v.published_at,v.modified_at,v.vuln_status,v.cvss_version,v.cvss_base_score,v.cvss_base_severity,v.cvss_vector,v.nvd_last_refreshed_at,
      e.epss_score,e.epss_percentile,e.epss_date,sv.risk_calculated_at,
      v.kev_flag,v.kev_date_added,v.kev_required_action,v.kev_due_date,
      s.asset_id,s.port,s.protocol,s.service_name,s.product,s.version,s.cpe,host(a.ip_address) AS ip_address,a.hostname,a.device_type
      FROM service_vulnerabilities sv JOIN vulnerabilities v ON v.cve_id=sv.cve_id JOIN services s ON s.service_id=sv.service_id
      JOIN assets a ON a.asset_id=s.asset_id
      LEFT JOIN epss_current_scores e ON e.cve_id=v.cve_id
      {where}
      ORDER BY v.kev_flag DESC, sv.organization_risk_score DESC NULLS LAST, v.cvss_base_score DESC NULLS LAST,sv.match_confidence,sv.last_seen DESC"""
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


def list_epss_intelligence(status="active", query=None, scan_id=None):
    clauses, params = [], []
    if status: clauses.append("sv.status=%s"); params.append(status)
    if query:
        clauses.append("(v.cve_id ILIKE %s OR v.description ILIKE %s OR a.hostname ILIKE %s OR host(a.ip_address) ILIKE %s OR s.product ILIKE %s)")
        params.extend([f"%{query}%"] * 5)
    if scan_id:
        clauses.append("""EXISTS (SELECT 1 FROM observed_services os JOIN asset_observations ao ON ao.observation_id=os.observation_id
          WHERE ao.asset_id=s.asset_id AND os.port=s.port AND os.protocol=s.protocol AND ao.scan_id=%s)""")
        params.append(scan_id)
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


def list_kev_intelligence(status="active", query=None, scan_id=None):
    clauses, params = ["v.kev_flag = true"], []
    if status: clauses.append("sv.status=%s"); params.append(status)
    if query:
        clauses.append("(v.cve_id ILIKE %s OR v.description ILIKE %s OR a.hostname ILIKE %s OR host(a.ip_address) ILIKE %s OR s.product ILIKE %s)")
        params.extend([f"%{query}%"] * 5)
    if scan_id:
        clauses.append("""EXISTS (SELECT 1 FROM observed_services os JOIN asset_observations ao ON ao.observation_id=os.observation_id
          WHERE ao.asset_id=s.asset_id AND os.port=s.port AND os.protocol=s.protocol AND ao.scan_id=%s)""")
        params.append(scan_id)
    where = f"WHERE {' AND '.join(clauses)}"
    sql = f"""SELECT sv.service_vulnerability_id,sv.status,sv.match_confidence,sv.match_wording,
      v.cve_id,v.description,v.cvss_base_score,v.cvss_base_severity,
      v.kev_date_added,v.kev_required_action,v.kev_due_date,
      s.asset_id,s.port,s.protocol,s.service_name,s.product,s.version,
      host(a.ip_address) AS ip_address,a.hostname,a.device_type,a.status AS asset_status
      FROM service_vulnerabilities sv
      JOIN vulnerabilities v ON v.cve_id=sv.cve_id
      JOIN services s ON s.service_id=sv.service_id
      JOIN assets a ON a.asset_id=s.asset_id
      {where}
      ORDER BY v.kev_due_date ASC NULLS LAST, v.kev_date_added DESC NULLS LAST"""
    with connection() as conn:
        return [_serialize(row) for row in conn.execute(sql, params).fetchall()]


def kev_summary():
    with connection() as conn:
        return _serialize(conn.execute("""SELECT
          count(*) FILTER (WHERE sv.status='active') AS active_matches,
          count(DISTINCT s.asset_id) FILTER (WHERE sv.status='active') AS affected_assets,
          count(*) FILTER (WHERE sv.status='active' AND v.kev_due_date IS NOT NULL AND v.kev_due_date <= current_date + interval '14 days') AS due_soon,
          count(DISTINCT v.cve_id) FILTER (WHERE sv.status='active') AS distinct_cves
          FROM service_vulnerabilities sv
          JOIN vulnerabilities v ON v.cve_id=sv.cve_id
          JOIN services s ON s.service_id=sv.service_id
          WHERE v.kev_flag = true""").fetchone())


def list_kev_runs(limit=20):
    with connection() as conn:
        return [_serialize(row) for row in conn.execute("SELECT * FROM kev_refresh_runs ORDER BY started_at DESC LIMIT %s", (limit,)).fetchall()]


def update_vulnerability_match_status(match_id, status):
    with connection() as conn:
        return _serialize(conn.execute("UPDATE service_vulnerabilities SET status=%s,last_checked_at=now() WHERE service_vulnerability_id=%s RETURNING *", (status,match_id)).fetchone())


def list_enrichment_runs(limit=20):
    with connection() as conn:
        return [_serialize(row) for row in conn.execute("SELECT * FROM nvd_enrichment_runs ORDER BY queued_at DESC LIMIT %s", (limit,)).fetchall()]


# Layer 7 — every scan already snapshots its own asset_observations/observed_services
# rows, so "what changed" is just a diff between two scans' snapshots rather than
# needing any new storage.
def telemetry_changes(to_scan_id=None, from_scan_id=None):
    with connection() as conn:
        if not to_scan_id:
            latest = conn.execute("SELECT id FROM scan_sessions WHERE status='COMPLETED' ORDER BY started_at DESC LIMIT 1").fetchone()
            to_scan_id = latest["id"] if latest else None
        if not to_scan_id:
            return {"to_scan": None, "from_scan": None, "baseline": False, "new_devices": [], "missing_devices": [], "port_changes": [], "config_changes": [], "finding_changes": []}

        if not from_scan_id:
            previous = conn.execute(
                "SELECT id FROM scan_sessions WHERE status='COMPLETED' AND started_at < (SELECT started_at FROM scan_sessions WHERE id=%s) ORDER BY started_at DESC LIMIT 1",
                (to_scan_id,),
            ).fetchone()
            from_scan_id = previous["id"] if previous else None

        to_scan = _serialize(conn.execute("SELECT id,started_at FROM scan_sessions WHERE id=%s", (to_scan_id,)).fetchone())
        if not from_scan_id:
            return {"to_scan": to_scan, "from_scan": None, "baseline": True, "new_devices": [], "missing_devices": [], "port_changes": [], "config_changes": [], "finding_changes": []}
        from_scan = _serialize(conn.execute("SELECT id,started_at FROM scan_sessions WHERE id=%s", (from_scan_id,)).fetchone())

        new_devices = [_serialize(row) for row in conn.execute("""
          SELECT a.asset_id,host(a.ip_address) AS ip_address,a.hostname,a.device_type
          FROM assets a
          WHERE EXISTS (SELECT 1 FROM asset_observations o WHERE o.asset_id=a.asset_id AND o.scan_id=%s)
            AND NOT EXISTS (SELECT 1 FROM asset_observations o WHERE o.asset_id=a.asset_id AND o.scan_id=%s)
          ORDER BY a.hostname NULLS LAST""", (to_scan_id, from_scan_id)).fetchall()]

        missing_devices = [_serialize(row) for row in conn.execute("""
          SELECT a.asset_id,host(a.ip_address) AS ip_address,a.hostname,a.device_type
          FROM assets a
          WHERE EXISTS (SELECT 1 FROM asset_observations o WHERE o.asset_id=a.asset_id AND o.scan_id=%s)
            AND NOT EXISTS (SELECT 1 FROM asset_observations o WHERE o.asset_id=a.asset_id AND o.scan_id=%s)
          ORDER BY a.hostname NULLS LAST""", (from_scan_id, to_scan_id)).fetchall()]

        port_changes = [_serialize(row) for row in conn.execute("""
          WITH to_ports AS (
            SELECT ao.asset_id,os.port,os.protocol,os.service_name,os.product,os.version
            FROM asset_observations ao JOIN observed_services os ON os.observation_id=ao.observation_id
            WHERE ao.scan_id=%(to)s AND os.state='open'
          ), from_ports AS (
            SELECT ao.asset_id,os.port,os.protocol,os.service_name,os.product,os.version
            FROM asset_observations ao JOIN observed_services os ON os.observation_id=ao.observation_id
            WHERE ao.scan_id=%(from)s AND os.state='open'
          )
          SELECT t.asset_id,host(a.ip_address) AS ip_address,a.hostname,t.port,t.protocol,t.service_name,t.product,
            NULL AS old_version,t.version AS new_version,'opened' AS change
          FROM to_ports t JOIN assets a ON a.asset_id=t.asset_id
          LEFT JOIN from_ports f ON f.asset_id=t.asset_id AND f.port=t.port AND f.protocol=t.protocol
          WHERE f.port IS NULL
          UNION ALL
          SELECT f.asset_id,host(a.ip_address) AS ip_address,a.hostname,f.port,f.protocol,f.service_name,f.product,
            f.version AS old_version,NULL AS new_version,'closed' AS change
          FROM from_ports f JOIN assets a ON a.asset_id=f.asset_id
          LEFT JOIN to_ports t ON t.asset_id=f.asset_id AND t.port=f.port AND t.protocol=f.protocol
          WHERE t.port IS NULL
          UNION ALL
          SELECT t.asset_id,host(a.ip_address) AS ip_address,a.hostname,t.port,t.protocol,t.service_name,t.product,
            f.version AS old_version,t.version AS new_version,'updated' AS change
          FROM to_ports t
          JOIN from_ports f ON f.asset_id=t.asset_id AND f.port=t.port AND f.protocol=t.protocol
          JOIN assets a ON a.asset_id=t.asset_id
          WHERE t.version IS DISTINCT FROM f.version AND (t.version IS NOT NULL OR f.version IS NOT NULL)
          ORDER BY hostname NULLS LAST,port""", {"to": to_scan_id, "from": from_scan_id}).fetchall()]

        # Covers every field asset_observations actually snapshots per scan.
        # device_type is deliberately excluded: it lives only on the current
        # `assets` row, not per-observation, so there is no history to diff.
        config_changes = [_serialize(row) for row in conn.execute("""
          SELECT t.asset_id,host(a.ip_address) AS ip_address,a.hostname,'os' AS field,f.os_family AS old_value,t.os_family AS new_value
          FROM asset_observations t JOIN asset_observations f ON f.asset_id=t.asset_id AND f.scan_id=%(from)s
          JOIN assets a ON a.asset_id=t.asset_id
          WHERE t.scan_id=%(to)s AND t.os_family IS DISTINCT FROM f.os_family
          UNION ALL
          SELECT t.asset_id,host(a.ip_address) AS ip_address,a.hostname,'vendor' AS field,f.vendor AS old_value,t.vendor AS new_value
          FROM asset_observations t JOIN asset_observations f ON f.asset_id=t.asset_id AND f.scan_id=%(from)s
          JOIN assets a ON a.asset_id=t.asset_id
          WHERE t.scan_id=%(to)s AND t.vendor IS DISTINCT FROM f.vendor
          UNION ALL
          SELECT t.asset_id,host(a.ip_address) AS ip_address,a.hostname,'mac_address' AS field,f.mac_address::text AS old_value,t.mac_address::text AS new_value
          FROM asset_observations t JOIN asset_observations f ON f.asset_id=t.asset_id AND f.scan_id=%(from)s
          JOIN assets a ON a.asset_id=t.asset_id
          WHERE t.scan_id=%(to)s AND t.mac_address IS DISTINCT FROM f.mac_address
          UNION ALL
          SELECT t.asset_id,host(a.ip_address) AS ip_address,a.hostname,'hostname' AS field,f.hostname AS old_value,t.hostname AS new_value
          FROM asset_observations t JOIN asset_observations f ON f.asset_id=t.asset_id AND f.scan_id=%(from)s
          JOIN assets a ON a.asset_id=t.asset_id
          WHERE t.scan_id=%(to)s AND t.hostname IS DISTINCT FROM f.hostname
          ORDER BY hostname NULLS LAST""", {"to": to_scan_id, "from": from_scan_id}).fetchall()]

        # Layer 3 findings are observed per-scan too (finding_observations),
        # so a finding appearing/disappearing between scans is just another
        # diff over existing data, same as the checks above.
        finding_changes = [_serialize(row) for row in conn.execute("""
          SELECT f.finding_id,f.title,f.severity,f.check_id,host(a.ip_address) AS ip_address,a.hostname,'new' AS change
          FROM findings f JOIN assets a ON a.asset_id=f.asset_id
          WHERE EXISTS (SELECT 1 FROM finding_observations fo WHERE fo.finding_id=f.finding_id AND fo.scan_id=%(to)s)
            AND NOT EXISTS (SELECT 1 FROM finding_observations fo WHERE fo.finding_id=f.finding_id AND fo.scan_id=%(from)s)
          UNION ALL
          SELECT f.finding_id,f.title,f.severity,f.check_id,host(a.ip_address) AS ip_address,a.hostname,'resolved' AS change
          FROM findings f JOIN assets a ON a.asset_id=f.asset_id
          WHERE EXISTS (SELECT 1 FROM finding_observations fo WHERE fo.finding_id=f.finding_id AND fo.scan_id=%(from)s)
            AND NOT EXISTS (SELECT 1 FROM finding_observations fo WHERE fo.finding_id=f.finding_id AND fo.scan_id=%(to)s)
          ORDER BY hostname NULLS LAST""", {"to": to_scan_id, "from": from_scan_id}).fetchall()]

        return {"to_scan": to_scan, "from_scan": from_scan, "baseline": False,
                "new_devices": new_devices, "missing_devices": missing_devices,
                "port_changes": port_changes, "config_changes": config_changes,
                "finding_changes": finding_changes}


# Layer 8 — combines severity (Layer 4), likelihood (Layer 5/6), exposure
# (Layer 3 findings), and organizational criticality (set by a person, since
# nothing in a scan can tell the system how much an asset matters) into one
# 0-100 per-asset risk score. A confirmed KEV match always forces the band to
# 'critical', matching the same real-world-exploitation-outranks-everything
# rule used on the Vulnerabilities/EPSS/KEV pages.
#
# Shared as one constant (rather than copy-pasted into telemetry_trend below)
# so the risk trend line and the Risk Engine page can never silently drift
# out of agreement with each other.
_ASSET_RISK_SCORED_CTE = """
  WITH vuln_agg AS (
    SELECT s.asset_id,
      max(v.cvss_base_score) AS max_cvss,
      max(e.epss_score) AS max_epss,
      bool_or(v.kev_flag) AS has_kev,
      count(*) AS active_vuln_count
    FROM service_vulnerabilities sv
    JOIN vulnerabilities v ON v.cve_id=sv.cve_id
    JOIN services s ON s.service_id=sv.service_id
    LEFT JOIN epss_current_scores e ON e.cve_id=v.cve_id
    WHERE sv.status='active'
    GROUP BY s.asset_id
  ), finding_agg AS (
    -- Weighted rather than a flat count: a critical finding should move the
    -- needle more than several mediums combined, not count the same as a high.
    SELECT asset_id,
      count(*) FILTER (WHERE severity='critical') AS critical_finding_count,
      count(*) FILTER (WHERE severity='high') AS high_finding_count,
      count(*) FILTER (WHERE severity='medium') AS medium_finding_count,
      count(*) AS open_finding_count
    FROM findings
    WHERE status='open'
    GROUP BY asset_id
  ), scored AS (
    SELECT a.asset_id,host(a.ip_address) AS ip_address,a.hostname,a.device_type,a.status,a.criticality,
      COALESCE(va.max_cvss,0) AS max_cvss,
      COALESCE(va.max_epss,0) AS max_epss,
      COALESCE(va.has_kev,false) AS has_kev,
      COALESCE(va.active_vuln_count,0) AS active_vuln_count,
      COALESCE(fa.critical_finding_count,0) AS critical_finding_count,
      COALESCE(fa.high_finding_count,0) AS high_finding_count,
      COALESCE(fa.medium_finding_count,0) AS medium_finding_count,
      COALESCE(fa.open_finding_count,0) AS open_finding_count,
      LEAST(COALESCE(fa.critical_finding_count,0)*40 + COALESCE(fa.high_finding_count,0)*20 + COALESCE(fa.medium_finding_count,0)*5,100) AS exposure_score,
      ROUND((
        (COALESCE(va.max_cvss,0)/10.0*100)*0.35
        + (CASE WHEN COALESCE(va.has_kev,false) THEN 100 ELSE COALESCE(va.max_epss,0)*100 END)*0.30
        + LEAST(COALESCE(fa.critical_finding_count,0)*40 + COALESCE(fa.high_finding_count,0)*20 + COALESCE(fa.medium_finding_count,0)*5,100)*0.20
        + (CASE a.criticality WHEN 'critical' THEN 100 WHEN 'high' THEN 75 WHEN 'low' THEN 25 ELSE 50 END)*0.15
      )::numeric,1) AS risk_score
    FROM assets a
    LEFT JOIN vuln_agg va ON va.asset_id=a.asset_id
    LEFT JOIN finding_agg fa ON fa.asset_id=a.asset_id
    WHERE a.status != 'missing'
  )
"""


def asset_risk_ranking():
    with connection() as conn:
        rows = conn.execute(_ASSET_RISK_SCORED_CTE + """
          SELECT *,
            CASE WHEN has_kev THEN 'critical'
                 WHEN risk_score >= 80 THEN 'critical'
                 WHEN risk_score >= 60 THEN 'high'
                 WHEN risk_score >= 35 THEN 'medium'
                 ELSE 'low' END AS risk_band,
            ROW_NUMBER() OVER (ORDER BY has_kev DESC,risk_score DESC NULLS LAST) AS priority_rank,
            count(*) OVER () AS priority_total
          FROM scored
          ORDER BY has_kev DESC,risk_score DESC NULLS LAST""").fetchall()
        return [_serialize(row) for row in rows]


# Now that Layer 8 exists, the trend uses assets' real current risk score
# rather than a raw vulnerability count. Same caveat as the vulnerability-count
# proxy it replaces: this is "based on what we know today, how risky were the
# assets seen in scan X" — CVSS/EPSS/KEV data isn't versioned per scan, so it
# is not a true point-in-time snapshot of risk at the moment of that scan.
def telemetry_trend(limit=10):
    with connection() as conn:
        rows = conn.execute(_ASSET_RISK_SCORED_CTE + """
          SELECT s.id AS scan_id,s.started_at,
            (SELECT count(*) FROM asset_observations ao WHERE ao.scan_id=s.id) AS device_count,
            (SELECT count(*) FROM asset_observations ao JOIN observed_services os ON os.observation_id=ao.observation_id
               WHERE ao.scan_id=s.id AND os.state='open') AS open_port_count,
            (SELECT ROUND(AVG(risk_score),1) FROM scored WHERE asset_id IN (SELECT asset_id FROM asset_observations ao WHERE ao.scan_id=s.id)) AS avg_risk_score,
            (SELECT MAX(risk_score) FROM scored WHERE asset_id IN (SELECT asset_id FROM asset_observations ao WHERE ao.scan_id=s.id)) AS max_risk_score
          FROM scan_sessions s
          WHERE s.status='COMPLETED'
          ORDER BY s.started_at DESC
          LIMIT %s""", (limit,)).fetchall()
        return [_serialize(row) for row in reversed(rows)]


def risk_summary():
    ranking = asset_risk_ranking()
    return {
        "assets_scored": len(ranking),
        "critical": sum(1 for r in ranking if r["risk_band"] == "critical"),
        "high": sum(1 for r in ranking if r["risk_band"] == "high"),
        "medium": sum(1 for r in ranking if r["risk_band"] == "medium"),
        "low": sum(1 for r in ranking if r["risk_band"] == "low"),
        "kev_matches": sum(1 for r in ranking if r["has_kev"]),
        "top_risk_asset": ranking[0] if ranking else None,
    }

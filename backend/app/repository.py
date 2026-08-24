import ipaddress
from datetime import datetime, timezone
from uuid import UUID

from .database import connection
from .scanner import HostObservation


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
             CASE WHEN EXISTS (SELECT 1 FROM asset_observations o WHERE o.asset_id=a.asset_id)
               THEN ARRAY['nmap']::text[] ELSE ARRAY[]::text[] END AS discovery_sources,
             COALESCE((SELECT json_agg(json_build_object('port',s.port,'protocol',s.protocol,'name',s.service_name,'product',s.product,'version',s.version,'cpe',s.cpe) ORDER BY s.port)
               FROM observed_services s JOIN asset_observations o ON o.observation_id=s.observation_id
               WHERE o.asset_id=a.asset_id AND o.observation_id=(SELECT observation_id FROM asset_observations WHERE asset_id=a.asset_id ORDER BY observed_at DESC LIMIT 1)), '[]') AS services
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
            seen_ids.append(asset["asset_id"])
            observation = conn.execute("""INSERT INTO asset_observations(asset_id,scan_id,observed_at,ip_address,mac_address,hostname,vendor,os_family,os_confidence)
              VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
              ON CONFLICT (asset_id,scan_id) DO UPDATE SET ip_address=EXCLUDED.ip_address, mac_address=COALESCE(EXCLUDED.mac_address,asset_observations.mac_address),
                hostname=COALESCE(EXCLUDED.hostname,asset_observations.hostname), vendor=COALESCE(EXCLUDED.vendor,asset_observations.vendor),
                os_family=COALESCE(EXCLUDED.os_family,asset_observations.os_family), os_confidence=COALESCE(EXCLUDED.os_confidence,asset_observations.os_confidence)
              RETURNING observation_id""", (asset["asset_id"],session_id,observed_at,host.ip_address,host.mac_address,host.hostname,host.vendor,host.os_family,host.os_confidence)).fetchone()
            for service in host.services:
                conn.execute("""INSERT INTO observed_services(observation_id,port,protocol,state,service_name,product,version,cpe)
                  VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                  ON CONFLICT (observation_id,port,protocol) DO UPDATE SET state=EXCLUDED.state, service_name=EXCLUDED.service_name,
                    product=EXCLUDED.product, version=EXCLUDED.version, cpe=EXCLUDED.cpe""", (observation["observation_id"],service.port,service.protocol,service.state,service.name,service.product,service.version,service.cpe))
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


def scan_history():
    with connection() as conn:
        rows = conn.execute("""SELECT finished_at AS ts, devices_found, (SELECT count(*) FROM assets) AS known_total
          FROM scan_sessions WHERE status='COMPLETED' ORDER BY finished_at ASC LIMIT 100""").fetchall()
        return [_serialize(row) for row in rows]

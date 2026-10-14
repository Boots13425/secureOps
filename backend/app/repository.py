import ipaddress
import json
from datetime import datetime, timezone
from decimal import Decimal
from uuid import UUID
from uuid import UUID as UUIDType
from psycopg.types.json import Jsonb

from .database import connection
from .scanner import HostObservation
from .findings import evaluate_host
from .risk_engine import (
    CRITICALITY_LABELS,
    DEFAULT_CRITICALITY_CATEGORY,
    DEFAULT_CRITICALITY_VALUE,
    MISSING_FROM_SCAN_NOTE,
    NOT_IN_DOCUMENT_NOTE,
    match_document_to_assets,
    recommendations,
    score_asset,
)
from .identification import AUTHORITATIVE_SOURCES, classify_device, confidence_for, source_rank
from .config import settings
from .risk_engine import (
    CRITICALITY_LABELS,
    DEFAULT_CRITICALITY_CATEGORY,
    DEFAULT_CRITICALITY_VALUE,
    MISSING_FROM_SCAN_NOTE,
    NOT_IN_DOCUMENT_NOTE,
    match_document_to_assets,
    recommendations,
    score_asset,
)


class AssetDocumentMissing(Exception):
    """Raised when ranking is attempted before an asset document is uploaded."""

    def __init__(self, readiness: dict):
        super().__init__("Asset document required before ranking")
        self.readiness = readiness


def _json_safe(value):
    """Make a row JSONB-storable (UUIDs, datetimes, Decimals -> text/number)."""
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, UUIDType):
        return str(value)
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (datetime,)):
        return value.isoformat()
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return str(value)
    return value



def _serialize(row):
    if row is None: return None
    string_types = (UUID, ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address, ipaddress.IPv6Network)
    return {key: (str(value) if isinstance(value, string_types) else value) for key, value in row.items()}


def list_assets(status=None, device_type=None, scan_id=None, last_24h=None, network_id=None, latest_scan_per_network=None, direct_probe_only=None):
    clauses, params = [], []
    if status: clauses.append("a.status = %s"); params.append(status)
    if device_type: clauses.append("a.device_type = %s"); params.append(device_type)
    if scan_id: clauses.append("EXISTS (SELECT 1 FROM asset_observations so WHERE so.asset_id=a.asset_id AND so.scan_id=%s)"); params.append(scan_id)
    if last_24h: clauses.append("a.last_seen >= now() - interval '24 hours'")
    if network_id: clauses.append("a.network_id = %s"); params.append(network_id)
    if direct_probe_only:
        clauses.append("(a.discovery_source IS NULL OR a.discovery_source != 'snmp_arp')")
    # latest_scan_per_network is mutually exclusive with scan_id
    if latest_scan_per_network and not scan_id:
        # Only assets observed in the latest completed scan of their network
        # Exclude missing devices - they belong on History page only
        clauses.append("a.status != 'missing'")
        clauses.append("""
            EXISTS (
                SELECT 1 FROM asset_observations ao
                JOIN scan_sessions ss ON ao.scan_id = ss.id
                WHERE ao.asset_id = a.asset_id
                  AND ss.status = 'COMPLETED'
                  AND ss.network_id = a.network_id
                  AND ss.finished_at = (
                      SELECT max(finished_at) FROM scan_sessions 
                      WHERE status = 'COMPLETED' AND network_id = a.network_id
                  )
            )
        """)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""
      SELECT a.asset_id AS id, a.asset_id, host(a.ip_address) AS ip,
             host(a.ip_address) AS ip_address, a.mac_address::text, a.vendor,
             a.hostname, a.device_type, a.os_family AS os_name, a.os_confidence,
             COALESCE(a.os_source, CASE WHEN a.os_family IS NOT NULL THEN 'nmap_heuristic' END) AS os_source,
             a.hostname_source, a.vendor_source, a.device_type_source,
             a.identification_provenance,
             a.status, a.first_seen, a.last_seen,
             n.cidr::text AS network_cidr,
             (SELECT count(*) FROM services current_service WHERE current_service.asset_id=a.asset_id AND current_service.state='open') AS service_count,
             CASE 
               WHEN a.discovery_source IS NULL THEN '["nmap"]'::jsonb
               ELSE jsonb_build_array(a.discovery_source)
             END AS discovery_sources,
             COALESCE((SELECT json_agg(json_build_object('service_id',s.service_id,'port',s.port,'protocol',s.protocol,'name',s.service_name,'product',s.product,'version',s.version,'cpe',s.cpe,'confidence',s.confidence,'enrichment_status',s.enrichment_status) ORDER BY s.port)
               FROM services s WHERE s.asset_id=a.asset_id AND s.state='open'), '[]') AS services
      FROM assets a 
      LEFT JOIN networks n ON a.network_id = n.network_id
      {where} ORDER BY a.last_seen DESC
    """
    with connection() as conn: return [_serialize(row) for row in conn.execute(sql, params).fetchall()]

def find_asset_by_identifier(identifier):
  identifier = identifier.strip().lower()
  for asset in list_assets():
    values = ((asset.get(field) or "").lower() for field in ("hostname", "ip_address", "mac_address"))
    if identifier in values:
      return asset
  return None

def find_asset_by_identifier(identifier):
    identifier = identifier.strip().lower()
    sql = """
      SELECT asset_id AS id, asset_id FROM assets
      WHERE lower(hostname) = %s OR lower(host(ip_address)) = %s OR lower(mac_address::text) = %s
      LIMIT 1
    """
    with connection() as conn: return _serialize(conn.execute(sql, (identifier, identifier, identifier)).fetchone())


def update_asset(asset_id, values):
    allowed = {key: value for key, value in values.items() if value is not None and key in {"status", "device_type", "criticality", "exposure"}}
    if not allowed: return None
    assignments = ", ".join(f"{key} = %s" for key in allowed)
    with connection() as conn:
        row = conn.execute(f"UPDATE assets SET {assignments}, updated_at=now() WHERE asset_id=%s RETURNING asset_id AS id, *", [*allowed.values(), asset_id]).fetchone()
        return _serialize(row)

def reclassify_stored_assets():
    """Re-derive device_type for every stored asset from its OS/vendor evidence.

    Assets already in the database were typed by the old port-only heuristic,
    so a Cisco switch exposing SSH/HTTPS was recorded as a "server" and would
    stay that way until its next scan. This replays the current classification
    priority over the evidence each asset already has stored, so already-known
    devices are corrected immediately.

    Only a classification backed by OS/platform, sysServices or naming evidence
    may overwrite an existing value; the port heuristic can never demote a
    device on its own, and a value that already came from an authoritative
    source is left alone.
    """
    with connection() as conn:
        rows = conn.execute("""
          SELECT a.asset_id, host(a.ip_address) AS ip_address, a.hostname, a.vendor,
                 a.os_family, a.os_source, a.device_type, a.device_type_source,
                 a.identification_provenance,
                 COALESCE(ARRAY(SELECT DISTINCT s.service_name FROM services s
                                 WHERE s.asset_id=a.asset_id AND s.state='open'
                                   AND s.service_name IS NOT NULL), ARRAY[]::text[]) AS service_names
            FROM assets a
        """).fetchall()

        corrections = []
        for row in rows:
            provenance = row.get("identification_provenance") or {}
            signals = provenance.get("signals") or {}
            result = classify_device(
                os_family=row["os_family"],
                sys_name=row["hostname"],
                hostname=row["hostname"],
                vendor=row["vendor"],
                sys_services=(signals.get("sys_services") or {}).get("value"),
                service_names=row["service_names"] or (),
            )
            current, current_source = row["device_type"], row["device_type_source"]
            if result.device_type == current or result.device_type == "unknown":
                continue
            if result.source == "service_heuristic":
                continue
            if current_source in AUTHORITATIVE_SOURCES:
                continue
            provenance = dict(provenance)
            type_provenance = dict(provenance.get("device_type") or {})
            type_provenance["candidates"] = {
                **(type_provenance.get("candidates") or {}),
                result.source: result.device_type,
            }
            type_provenance.update({
                "value": result.device_type,
                "source": result.source,
                "confidence": confidence_for(result.source),
                "detail": result.detail,
            })
            provenance["device_type"] = type_provenance
            conn.execute("""UPDATE assets SET device_type=%s, device_type_source=%s,
                              identification_provenance=%s, updated_at=now()
                            WHERE asset_id=%s""",
                         (result.device_type, result.source, Jsonb(provenance), row["asset_id"]))
            corrections.append({
                "ip_address": row["ip_address"], "hostname": row["hostname"],
                "from": current, "to": result.device_type, "source": result.source,
            })

        if corrections:
            conn.execute("""INSERT INTO scan_activity(event_type,message,detail) VALUES (%s,%s,%s)""",
                         ("ASSET_RECLASSIFIED", f"{len(corrections)} asset(s) reclassified from OS/vendor evidence",
                          "; ".join(f"{item['ip_address']} Â· {item['hostname'] or 'unresolved'}: {item['from']} â†’ {item['to']} ({item['source']})"
                                    for item in corrections[:25])))
    return corrections


def find_current_asset_identifier(identifier):
    try:
        UUIDType(str(identifier))
    except ValueError:
        pass
    else:
        with connection() as conn:
            row = conn.execute("SELECT asset_id FROM assets WHERE asset_id=%s AND status != 'missing'", (identifier,)).fetchone()
        if row:
            return str(row["asset_id"])
    asset = find_asset_by_identifier(identifier)
    return str(asset["asset_id"]) if asset else None


# --- Layer 8 asset document -------------------------------------------------
def save_asset_document(rows):
    """Replace the stored asset document with `rows` (a full replacement)."""
    with connection() as conn:
        # Deleting the previous upload cascades to its rows, so a new upload
        # never merges with or partially supersedes an old document.
        conn.execute("DELETE FROM asset_document_uploads")
        upload = conn.execute(
            "INSERT INTO asset_document_uploads(uploaded_at, row_count) VALUES (now(), %s) RETURNING upload_id, uploaded_at",
            (len(rows),),
        ).fetchone()
        for row in rows:
            conn.execute("""
              INSERT INTO asset_document_rows(upload_id, row_number, device_name, ip_address, purpose,
                                              criticality_category, criticality_value)
              VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (upload["upload_id"], row["row_number"], row["device_name"],
                  row["ip_address"], row["purpose"], row["criticality_category"],
                  row["criticality_value"]))
    return {"row_count": len(rows), "uploaded_at": upload["uploaded_at"]}


def load_asset_document():
    """Current document rows, or [] when nothing has been uploaded."""
    with connection() as conn:
        return conn.execute("""
          SELECT row_number, device_name, host(ip_address) AS ip_address, purpose,
                 criticality_category, criticality_value
            FROM asset_document_rows
           ORDER BY row_number
        """).fetchall()


def asset_document_state():
    with connection() as conn:
        state = conn.execute("""
          SELECT uploaded_at, row_count FROM asset_document_uploads
           ORDER BY uploaded_at DESC LIMIT 1
        """).fetchone()
    if not state:
        return {"asset_document_uploaded": False, "uploaded_at": None, "row_count": 0}
    return {
        "asset_document_uploaded": True,
        "uploaded_at": _serialize(state)["uploaded_at"],
        "row_count": state["row_count"],
    }


def create_session(subnet, duration_minutes=None, source="manual", network_id=None):
    mode = "bounded" if duration_minutes else "continuous"
    with connection() as conn:
        row = conn.execute("INSERT INTO scan_sessions(subnet,status,mode,duration_minutes,source,network_id,target_cidr) VALUES (%s,'RUNNING',%s,%s,%s,%s,%s) RETURNING *", (subnet, mode, duration_minutes, source, network_id, subnet if network_id else None)).fetchone()
        conn.execute("INSERT INTO scan_activity(scan_id,event_type,message,detail) VALUES (%s,'SESSION_STARTED','Scan session started',%s)", (row["id"], subnet))
        return _serialize(row)


def get_session(session_id):
    with connection() as conn: return _serialize(conn.execute("SELECT * FROM scan_sessions WHERE id=%s", (session_id,)).fetchone())


def list_sessions():
    with connection() as conn: return [_serialize(row) for row in conn.execute("SELECT *, started_at, finished_at FROM scan_sessions ORDER BY started_at DESC LIMIT 100").fetchall()]


def get_latest_completed_session():
    """Return the latest completed scan session, or None if none exist."""
    with connection() as conn:
        return _serialize(conn.execute(
            "SELECT * FROM scan_sessions WHERE status='COMPLETED' ORDER BY finished_at DESC LIMIT 1"
        ).fetchone())


def find_stale_running_sessions(max_age_seconds: int):
    """RUNNING sessions older than the budget, with no evidence of progress.

    started_at is the only durable timestamp available, so it is the basis for
    the check. It is deliberately conservative: the threshold is the scan
    timeout plus a grace margin.
    """
    with connection() as conn:
        return [_serialize(row) for row in conn.execute(
            "SELECT * FROM scan_sessions WHERE status='RUNNING' "
            "AND started_at < now() - make_interval(secs => %s) ORDER BY started_at",
            (max(0, int(max_age_seconds)),)).fetchall()]


def fail_orphaned_running_sessions():
    """Close out sessions left RUNNING by a process that exited.

    Scan threads are in-process, so any restart strands their rows at
    RUNNING with no thread left to finish them.
    """
    with connection() as conn:
        rows = conn.execute("""
            UPDATE scan_sessions SET status='FAILED', finished_at=now(),
                error_message=%s
            WHERE status='RUNNING' RETURNING *
        """, ("The scan was interrupted: the backend restarted before it "
              "finished, so this run is incomplete and must not be read as "
              "devices being absent.",)).fetchall()
        for row in rows:
            conn.execute(
                "INSERT INTO scan_activity(scan_id,event_type,message,detail) "
                "VALUES (%s,%s,%s,%s)",
                (row["id"], "SESSION_FAILED", "Scan failed",
                 "Backend restarted mid-scan; run is incomplete."),
            )
        return [_serialize(row) for row in rows]

def finish_session(session_id, status, devices_found=0, error=None):
    with connection() as conn:
        row = conn.execute("UPDATE scan_sessions SET status=%s, finished_at=now(), devices_found=%s, error_message=%s WHERE id=%s RETURNING *", (status, devices_found, error, session_id)).fetchone()
        event = f"SESSION_{status}"
        message = {"COMPLETED":"Scan completed","STOPPED":"Scan stopped","FAILED":"Scan failed"}[status]
        conn.execute("INSERT INTO scan_activity(scan_id,event_type,message,detail) VALUES (%s,%s,%s,%s)", (session_id, event, message, error or f"{devices_found} live hosts"))
        return _serialize(row)


def store_scan_results(session_id, subnet, hosts: list[HostObservation], record_activity=True, network_id=None):
    observed_at = datetime.now(timezone.utc)
    seen_ids = []
    with connection() as conn:
        for host in hosts:
            existing = None
            if host.mac_address:
                existing = conn.execute("SELECT * FROM assets WHERE mac_address=%s", (host.mac_address,)).fetchone()
            # Do NOT fall back to hostname or IP matching - MAC is the only stable identifier
            # Remote devices without MAC (known only via SNMP ARP) are tracked per IP separately

            # Requirement 2: Cross-segment MAC/vendor visibility via SNMP ARP tables.
            # If this host has no Layer-2 MAC from direct ARP, check if an SNMP router
            # or switch previously reported an ARP mapping for this IP.
            if not host.mac_address:
                snmp_mac_row = conn.execute(
                    "SELECT mac_address::text FROM snmp_mac_ip_observations WHERE ip_address=%s ORDER BY last_seen DESC LIMIT 1",
                    (host.ip_address,)
                ).fetchone()
                if snmp_mac_row and snmp_mac_row.get("mac_address"):
                    host.mac_address = snmp_mac_row["mac_address"]
                    if not existing:
                        existing = conn.execute("SELECT * FROM assets WHERE mac_address=%s", (host.mac_address,)).fetchone()

            if existing:
                next_status = existing["status"] if existing["status"] in {"approved", "unknown", "known"} else "known"

                # Requirement 6: Confidence-tagged field merging.
                # Never silently overwrite a higher-confidence existing value with a lower-confidence guess.
                # Only overwrite if the new candidate source has equal or higher priority (lower or equal source_rank),
                # or if the existing field is empty.
                def choose_field(current_val, current_source, new_val, new_source):
                    if not new_val or new_val == "unknown":
                        return current_val, current_source
                    if not current_val or current_val == "unknown":
                        return new_val, new_source or "nmap_heuristic"
                    curr_rank = source_rank(current_source or "nmap_heuristic")
                    new_rank = source_rank(new_source or "nmap_heuristic")
                    if new_rank <= curr_rank:
                        return new_val, new_source or "nmap_heuristic"
                    return current_val, current_source

                final_hostname, final_h_src = choose_field(
                    existing.get("hostname"), existing.get("hostname_source"),
                    host.hostname, host.hostname_source,
                )
                final_vendor, final_v_src = choose_field(
                    existing.get("vendor"), existing.get("vendor_source"),
                    host.vendor, host.vendor_source,
                )
                final_os, final_os_src = choose_field(
                    existing.get("os_family"), existing.get("os_source"),
                    host.os_family, host.os_source,
                )
                final_dtype, final_dtype_src = choose_field(
                    existing.get("device_type"), existing.get("device_type_source"),
                    host.device_type, host.device_type_source,
                )
                final_os_conf = host.os_confidence if final_os == host.os_family and host.os_confidence is not None else existing.get("os_confidence")

                # Merge provenance maps
                merged_prov = dict(existing.get("identification_provenance") or {})
                if host.identification_provenance:
                    merged_prov.update(host.identification_provenance)
                if host.hostname_unresolved_reason:
                    # Explains an unresolved name in the UI. Cleared automatically
                    # on a later scan where a name does resolve, because the
                    # merged provenance is rebuilt from the current observation.
                    merged_prov["hostname_unresolved_reason"] = host.hostname_unresolved_reason
                else:
                    merged_prov.pop("hostname_unresolved_reason", None)

                asset = conn.execute("""UPDATE assets SET
                  ip_address=%s, mac_address=COALESCE(%s, mac_address),
                  hostname=%s, hostname_source=%s,
                  vendor=%s, vendor_source=%s,
                  os_family=%s, os_source=%s, os_confidence=%s,
                  device_type=%s, device_type_source=%s,
                  identification_provenance=%s,
                  status=%s, last_seen=%s, updated_at=now(),
                  discovery_source=%s
                  WHERE asset_id=%s RETURNING *""", (
                    host.ip_address, host.mac_address,
                    final_hostname, final_h_src,
                    final_vendor, final_v_src,
                    final_os, final_os_src, final_os_conf,
                    final_dtype or "unknown", final_dtype_src,
                    Jsonb(merged_prov) if merged_prov else None,
                    next_status, observed_at,
                    (host.discovery_sources[0] if host.discovery_sources else None),
                    existing["asset_id"]
                )).fetchone()
                event_type, message = "ASSET_UPDATED", "Known asset observed"
            else:
                asset = conn.execute("""INSERT INTO assets(
                  ip_address, mac_address, vendor, vendor_source,
                  hostname, hostname_source,
                  device_type, device_type_source,
                  os_family, os_source, os_confidence,
                  identification_provenance, status, first_seen, last_seen,
                  discovery_source
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'unknown',%s,%s,%s) RETURNING *""", (
                    host.ip_address, host.mac_address,
                    host.vendor, host.vendor_source or ("nmap_heuristic" if host.vendor else None),
                    host.hostname, host.hostname_source or ("nmap_heuristic" if host.hostname else None),
                    host.device_type or "unknown", host.device_type_source or ("nmap_heuristic" if host.device_type != "unknown" else None),
                    host.os_family, host.os_source or ("nmap_heuristic" if host.os_family else None),
                    host.os_confidence,
                    Jsonb(host.identification_provenance) if host.identification_provenance else None,
                    observed_at, observed_at,
                    (host.discovery_sources[0] if host.discovery_sources else None)
                )).fetchone()
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
                conn.execute("INSERT INTO scan_activity(scan_id,event_type,message,detail) VALUES (%s,%s,%s,%s)", (session_id,event_type,message,f"{host.ip_address} Â· {host.hostname or 'unresolved'} Â· {len(host.services)} services"))
        # Only the final, fully-identified pass may declare anything absent.
        # This runs on the partial set after discovery too, and a scan that
        # times out or dies before identification finishes would otherwise mark
        # every device it simply never got to as "missing" - indistinguishable
        # from one that was probed and did not answer.
        if record_activity:
            if network_id:
                # Per-network missing: only mark assets in this network as missing
                if seen_ids:
                    conn.execute(
                        "UPDATE assets SET status='missing', updated_at=now() WHERE network_id=%s AND asset_id <> ALL(%s::uuid[])",
                        (network_id, seen_ids)
                    )
                else:
                    conn.execute(
                        "UPDATE assets SET status='missing', updated_at=now() WHERE network_id=%s",
                        (network_id,)
                    )
            else:
                # Legacy subnet-based missing (for local scans without network_id)
                if seen_ids:
                    conn.execute("UPDATE assets SET status='missing', updated_at=now() WHERE ip_address <<= %s::cidr AND asset_id <> ALL(%s::uuid[])", (subnet, seen_ids))
                else:
                    conn.execute("UPDATE assets SET status='missing', updated_at=now() WHERE ip_address <<= %s::cidr", (subnet,))


def list_activity(limit, scan_id=None):
    clause = "WHERE scan_id=%s " if scan_id else ""
    params = [scan_id, limit] if scan_id else [limit]
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
        return _serialize(conn.execute("""SELECT count(*) FILTER (WHERE f.status='open') AS open,
          count(*) FILTER (WHERE f.status='open' AND f.severity='critical') AS critical,
          count(*) FILTER (WHERE f.status='open' AND f.severity='high') AS high,
          count(*) FILTER (WHERE f.status='open' AND f.severity='medium') AS medium,
          count(DISTINCT f.asset_id) FILTER (WHERE f.status='open') AS affected_assets
          FROM findings f JOIN assets a ON a.asset_id=f.asset_id
          WHERE a.status != 'missing' AND a.last_seen >= now() - interval '24 hours'""").fetchone())


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
      v.kev_date_added,v.kev_required_action,v.kev_due_date,v.kev_known_ransomware_use,
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
          count(*) FILTER (WHERE sv.status='active' AND a.status != 'missing' AND a.last_seen >= now() - interval '24 hours') AS active_matches,
          count(DISTINCT s.asset_id) FILTER (WHERE sv.status='active' AND a.status != 'missing' AND a.last_seen >= now() - interval '24 hours') AS affected_assets,
          count(*) FILTER (WHERE sv.status='active' AND a.status != 'missing' AND a.last_seen >= now() - interval '24 hours' AND v.kev_due_date IS NOT NULL AND v.kev_due_date <= current_date + interval '14 days') AS due_soon,
          count(DISTINCT v.cve_id) FILTER (WHERE sv.status='active' AND a.status != 'missing' AND a.last_seen >= now() - interval '24 hours') AS distinct_cves
          FROM service_vulnerabilities sv
          JOIN vulnerabilities v ON v.cve_id=sv.cve_id
          JOIN services s ON s.service_id=sv.service_id
          JOIN assets a ON a.asset_id=s.asset_id
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


# Layer 7 â€” every scan already snapshots its own asset_observations/observed_services
# rows, so "what changed" is just a diff between two scans' snapshots rather than
# needing any new storage.
def telemetry_changes(to_scan_id=None, from_scan_id=None):
    with connection() as conn:
        if not to_scan_id:
            latest = conn.execute("SELECT id FROM scan_sessions WHERE status='COMPLETED' ORDER BY started_at DESC LIMIT 1").fetchone()
            to_scan_id = latest["id"] if latest else None
        if not to_scan_id:
            return {"to_scan": None, "from_scan": None, "baseline": False, "new_devices": [], "missing_devices": [], "port_changes": [], "config_changes": [], "finding_changes": [], "cve_changes": [], "risk_changes": []}

        if not from_scan_id:
            previous = conn.execute(
                "SELECT id FROM scan_sessions WHERE status='COMPLETED' AND started_at < (SELECT started_at FROM scan_sessions WHERE id=%s) ORDER BY started_at DESC LIMIT 1",
                (to_scan_id,),
            ).fetchone()
            from_scan_id = previous["id"] if previous else None

        to_scan = _serialize(conn.execute("SELECT id,started_at FROM scan_sessions WHERE id=%s", (to_scan_id,)).fetchone())
        if not from_scan_id:
            return {"to_scan": to_scan, "from_scan": None, "baseline": True, "new_devices": [], "missing_devices": [], "port_changes": [], "config_changes": [], "finding_changes": [], "cve_changes": [], "risk_changes": []}
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

        # NEW_CVE / CVE_RESOLVED (project guide Â§11). service_vulnerabilities
        # isn't scan-scoped like asset_observations/finding_observations â€” a
        # CVE match just has first_seen/status timestamps â€” so a match is
        # counted as NEW_CVE if it first appeared in the window between the
        # two scans' start times, and CVE_RESOLVED if it was marked
        # resolved/dismissed in that same window (there is no automatic
        # "NVD stopped returning this CVE" removal, so resolution is always
        # the result of an explicit status change).
        cve_changes = [_serialize(row) for row in conn.execute("""
          SELECT sv.service_vulnerability_id,sv.cve_id,v.cvss_base_score,v.cvss_base_severity,
            s.asset_id,host(a.ip_address) AS ip_address,a.hostname,'new' AS change
          FROM service_vulnerabilities sv
          JOIN vulnerabilities v ON v.cve_id=sv.cve_id
          JOIN services s ON s.service_id=sv.service_id
          JOIN assets a ON a.asset_id=s.asset_id
          WHERE sv.first_seen > (SELECT started_at FROM scan_sessions WHERE id=%(from)s)
            AND sv.first_seen <= (SELECT started_at FROM scan_sessions WHERE id=%(to)s)
          UNION ALL
          SELECT sv.service_vulnerability_id,sv.cve_id,v.cvss_base_score,v.cvss_base_severity,
            s.asset_id,host(a.ip_address) AS ip_address,a.hostname,'resolved' AS change
          FROM service_vulnerabilities sv
          JOIN vulnerabilities v ON v.cve_id=sv.cve_id
          JOIN services s ON s.service_id=sv.service_id
          JOIN assets a ON a.asset_id=s.asset_id
          WHERE sv.status IN ('resolved','dismissed')
            AND sv.last_checked_at > (SELECT started_at FROM scan_sessions WHERE id=%(from)s)
            AND sv.last_checked_at <= (SELECT started_at FROM scan_sessions WHERE id=%(to)s)
          ORDER BY hostname NULLS LAST""", {"to": to_scan_id, "from": from_scan_id}).fetchall()]

        # RISK_CHANGED (project guide Â§11) â€” the one event type that needs the
        # asset_risk_snapshots table below, since it's a real diff between two
        # points in time rather than something derivable from current state.
        # Scans that predate the snapshot table (or a manual-only enrichment
        # with no scan_id) simply won't have a row here, same as any other
        # "not enough history yet" case elsewhere in this app.
        risk_changes = [_serialize(row) for row in conn.execute("""
          SELECT t.asset_id,host(a.ip_address) AS ip_address,a.hostname,
            f.risk_band AS old_band,t.risk_band AS new_band,f.risk_score AS old_score,t.risk_score AS new_score
          FROM asset_risk_snapshots t
          JOIN asset_risk_snapshots f ON f.asset_id=t.asset_id AND f.scan_id=%(from)s
          JOIN assets a ON a.asset_id=t.asset_id
          WHERE t.scan_id=%(to)s AND t.risk_band IS DISTINCT FROM f.risk_band
          ORDER BY hostname NULLS LAST""", {"to": to_scan_id, "from": from_scan_id}).fetchall()]

        return {"to_scan": to_scan, "from_scan": from_scan, "baseline": False,
                "new_devices": new_devices, "missing_devices": missing_devices,
                "port_changes": port_changes, "config_changes": config_changes,
                "finding_changes": finding_changes, "cve_changes": cve_changes,
                "risk_changes": risk_changes}


# Layer 8 â€” the ETSNTECH Asset Risk Index (EARI), project guide Â§12. Five
# independently weighted 0-100 inputs, exactly as specified:
#   0.30 severity (max CVSS of active CVEs, scaled x10)
# + 0.20 exploit likelihood (max EPSS score, scaled x100)
# + 0.20 known exploitation (100 if any active CVE is in CISA KEV, else 0)
# + 0.15 network exposure (categorical, set by a person â€” Â§12.3 table)
# + 0.15 asset criticality (categorical, set by a person â€” Â§12.4 table)
# A confirmed KEV match enforces a minimum *score* of 80 (not just the band â€”
# Â§12.2 "enforce a minimum priority score of 80"), which then naturally lands
# in the High band (70-84) or above once the banding below is applied.
#
# Open findings (Layer 3) are NOT one of the five EARI inputs per the spec â€”
# they are surfaced separately as finding_pressure_score, an auxiliary signal
# used only for the human-readable "why" explanation, never for the score.
#
# Shared as one constant (rather than copy-pasted into telemetry_trend below)
# so the risk trend line and the Risk Engine page can never silently drift
# out of agreement with each other.
_EXPOSURE_CASE = """CASE a.exposure
  WHEN 'isolated_lab' THEN 20 WHEN 'management_segment' THEN 30 WHEN 'server_vlan' THEN 50
  WHEN 'staff_network' THEN 65 WHEN 'guest_network' THEN 80 WHEN 'internet_facing' THEN 100
  ELSE 65 END"""
_CRITICALITY_CASE = """CASE a.criticality
  WHEN 'test_temporary' THEN 20 WHEN 'peripheral' THEN 30 WHEN 'standard_workstation' THEN 50
  WHEN 'privileged_workstation' THEN 70 WHEN 'business_server' THEN 85 WHEN 'critical_service' THEN 100
  ELSE 50 END"""

_ASSET_RISK_SCORED_CTE = f"""
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
    -- Not a scoring input (see note above) â€” kept only to explain the score.
    -- The four bool_or flags identify which Â§12.5 recommendation template(s)
    -- apply, by the exact title findings.py assigns each Layer 3 finding type.
    SELECT asset_id,
      count(*) FILTER (WHERE severity='critical') AS critical_finding_count,
      count(*) FILTER (WHERE severity='high') AS high_finding_count,
      count(*) FILTER (WHERE severity='medium') AS medium_finding_count,
      count(*) AS open_finding_count,
      bool_or(title = 'Legacy SMB protocol detected') AS has_smbv1_finding,
      bool_or(title = 'Anonymous FTP access accepted') AS has_anon_ftp_finding,
      bool_or(title = 'Remote Desktop service exposed') AS has_rdp_exposure_finding,
      bool_or(title IN ('Expired TLS certificate detected','TLS certificate expires soon')) AS has_cert_finding
    FROM findings
    WHERE status='open'
    GROUP BY asset_id
  ), scored AS (
    SELECT a.asset_id,host(a.ip_address) AS ip_address,a.hostname,a.device_type,a.status,
      a.criticality,a.exposure,
      COALESCE(va.max_cvss,0) AS max_cvss,
      COALESCE(va.max_epss,0) AS max_epss,
      COALESCE(va.has_kev,false) AS has_kev,
      COALESCE(va.active_vuln_count,0) AS active_vuln_count,
      COALESCE(fa.critical_finding_count,0) AS critical_finding_count,
      COALESCE(fa.high_finding_count,0) AS high_finding_count,
      COALESCE(fa.medium_finding_count,0) AS medium_finding_count,
      COALESCE(fa.open_finding_count,0) AS open_finding_count,
      COALESCE(fa.has_smbv1_finding,false) AS has_smbv1_finding,
      COALESCE(fa.has_anon_ftp_finding,false) AS has_anon_ftp_finding,
      COALESCE(fa.has_rdp_exposure_finding,false) AS has_rdp_exposure_finding,
      COALESCE(fa.has_cert_finding,false) AS has_cert_finding,
      LEAST(COALESCE(fa.critical_finding_count,0)*40 + COALESCE(fa.high_finding_count,0)*20 + COALESCE(fa.medium_finding_count,0)*5,100) AS finding_pressure_score,
      ROUND(COALESCE(va.max_cvss,0)/10.0*100,1) AS severity_normalized,
      ROUND(COALESCE(va.max_epss,0)*100,1) AS epss_normalized,
      (CASE WHEN COALESCE(va.has_kev,false) THEN 100 ELSE 0 END) AS kev_normalized,
      ({_EXPOSURE_CASE}) AS exposure_normalized,
      ({_CRITICALITY_CASE}) AS criticality_normalized,
      GREATEST(
        ROUND((
          (COALESCE(va.max_cvss,0)/10.0*100)*0.30
          + (COALESCE(va.max_epss,0)*100)*0.20
          + (CASE WHEN COALESCE(va.has_kev,false) THEN 100 ELSE 0 END)*0.20
          + ({_EXPOSURE_CASE})*0.15
          + ({_CRITICALITY_CASE})*0.15
        )::numeric,1),
        CASE WHEN COALESCE(va.has_kev,false) THEN 80 ELSE 0 END
      ) AS risk_score
    FROM assets a
    LEFT JOIN vuln_agg va ON va.asset_id=a.asset_id
    LEFT JOIN finding_agg fa ON fa.asset_id=a.asset_id
    WHERE a.status != 'missing'
  )
"""

# Project guide Â§12.2 suggested labels â€” five bands, not four.
_RISK_BAND_CASE = """CASE WHEN risk_score >= 85 THEN 'critical'
  WHEN risk_score >= 70 THEN 'high'
  WHEN risk_score >= 50 THEN 'elevated'
  WHEN risk_score >= 30 THEN 'moderate'
  ELSE 'low' END"""


def _recommended_action(row):
    """Rule-based recommendation engine, project guide Â§12.5 â€” deterministic,
    no generative-AI dependency, one short template per condition. Every
    condition the asset currently matches is combined into one action line,
    same as the worked example in Â§13.2 ("validate/patch KEV vulnerability;
    disable SMBv1; restrict RDP") rather than returning only the single
    highest-priority driver."""
    actions = []
    if row["has_kev"]:
        actions.append("prioritize vendor-supported remediation/mitigation; verify exposure and rescan after action")
    if row["max_cvss"] >= 7 and row["max_epss"] >= 0.5:
        actions.append("prioritize validation and vendor remediation because both impact and exploitation likelihood are elevated")
    if row["has_smbv1_finding"]:
        actions.append("disable SMBv1 after validating business dependencies, then rescan")
    if row["has_anon_ftp_finding"]:
        actions.append("disable anonymous FTP access unless explicitly required; restrict writable areas and network reachability")
    if row["has_rdp_exposure_finding"]:
        actions.append("restrict RDP to approved management sources/VPN and enforce strong authentication policy")
    if row["has_cert_finding"]:
        actions.append("renew/replace the certificate and verify service continuity")
    if not actions and row["active_vuln_count"]:
        actions.append("validate the matched CVEs against the actual deployed version, then plan remediation")
    if not actions and (row["critical_finding_count"] or row["high_finding_count"]):
        actions.append("review and remediate the open high-severity exposure findings on this asset, then rescan")
    if not actions:
        return "No urgent action required; continue routine monitoring."
    combined = "; ".join(actions)
    return combined[0].upper() + combined[1:] + "."


def _score_rows_for_calculation():
    with connection() as conn:
        return conn.execute("""
          SELECT a.asset_id,host(a.ip_address) AS ip_address,a.hostname,a.mac_address::text,
                 a.device_type,a.status,
                 COALESCE((SELECT jsonb_agg(jsonb_build_object('port',s.port,'protocol',s.protocol,
                   'name',s.service_name,'product',s.product,'version',s.version))
                   FROM services s WHERE s.asset_id=a.asset_id AND s.state='open'),'[]'::jsonb) AS services,
                 COALESCE((SELECT jsonb_agg(jsonb_build_object('title',f.title,'check_id',f.check_id,
                   'evidence',f.evidence,'why_it_matters',f.why_it_matters))
                   FROM findings f WHERE f.asset_id=a.asset_id AND f.status='open'),'[]'::jsonb) AS findings,
                 COALESCE((SELECT jsonb_agg(jsonb_build_object('cve_id',v.cve_id,
                   'cvss',v.cvss_base_score,'epss',e.epss_score,'kev',v.kev_flag))
                   FROM service_vulnerabilities sv
                   JOIN vulnerabilities v ON v.cve_id=sv.cve_id
                   JOIN services s ON s.service_id=sv.service_id
                   LEFT JOIN epss_current_scores e ON e.cve_id=v.cve_id
                   WHERE s.asset_id=a.asset_id AND sv.status='active'),'[]'::jsonb) AS vulnerabilities
            FROM assets a 
            LEFT JOIN networks n ON a.network_id = n.network_id
            WHERE a.status != 'missing'
              AND EXISTS (
                SELECT 1 FROM asset_observations ao
                JOIN scan_sessions ss ON ao.scan_id = ss.id
                WHERE ao.asset_id = a.asset_id
                  AND ss.status = 'COMPLETED'
                  AND ss.network_id = a.network_id
                  AND ss.finished_at = (
                      SELECT max(finished_at) FROM scan_sessions 
                      WHERE status = 'COMPLETED' AND network_id = a.network_id
                  )
              )
              AND (a.discovery_source IS NULL OR a.discovery_source != 'snmp_arp')
        """).fetchall()


def _deduplicate_by_mac(assets):
    """Merge multiple asset rows for the same physical device.

    Primary grouping: normalized hostname (e.g., DESKTOP-M60QFGK.local -> DESKTOP-M60QFGK).
    Within each hostname group, prefer entry with MAC address, then by completeness.
    For entries without hostname, fall back to MAC address grouping.
    """
    from app.risk_engine import normalize_hostname

    # Group by normalized hostname first
    by_hostname = {}
    no_hostname = []

    for asset in assets:
        hostname = asset.get("hostname")
        if not hostname:
            no_hostname.append(asset)
            continue

        norm_host = normalize_hostname(hostname)
        existing = by_hostname.get(norm_host)
        if not existing:
            by_hostname[norm_host] = asset
            continue

        # Prefer entry with MAC address
        has_mac_new = bool(asset.get("mac_address"))
        has_mac_existing = bool(existing.get("mac_address"))
        if has_mac_new and not has_mac_existing:
            by_hostname[norm_host] = asset
            continue
        if has_mac_existing and not has_mac_new:
            continue

        # If both have MAC or both lack MAC, prefer more complete data
        if _completeness(asset) > _completeness(existing):
            by_hostname[norm_host] = asset

    # For entries without hostname, group by MAC address
    by_mac = {}
    no_mac_no_hostname = []

    for asset in no_hostname:
        mac = asset.get("mac_address")
        if not mac:
            no_mac_no_hostname.append(asset)
            continue

        mac = mac.lower()
        existing = by_mac.get(mac)
        if not existing:
            by_mac[mac] = asset
            continue

        if _completeness(asset) > _completeness(existing):
            by_mac[mac] = asset

    return list(by_hostname.values()) + list(by_mac.values()) + no_mac_no_hostname


def _completeness(a):
    """Score data completeness for deduplication preference."""
    score = 0
    if a.get("hostname"):
        score += 2
        if "." in str(a.get("hostname")):
            score += 1  # FQDN preferred over short name
    if a.get("services"):
        score += min(len(a["services"]), 5)
    if a.get("findings"):
        score += min(len(a["findings"]), 5)
    if a.get("vulnerabilities"):
        score += min(len(a["vulnerabilities"]), 5)
    if a.get("ip_address"):
        score += 1
    return score


def _calculate_asset_ranking():
    """Score active assets and split them into the three Layer 8 groups.

    Criticality comes from the uploaded asset document (IP first, then
    hostname); exposure is a single network-wide value because the network is
    flat. Group 1 (document matches) is ranked purely by score. Group 3
    (unmatched scanned devices) is ranked among itself by score but always
    placed after every group 1 device, with ranks continuing the sequence.
    """
    assets = _deduplicate_by_mac(_score_rows_for_calculation())
    document = load_asset_document()
    matches, unmatched_rows = match_document_to_assets(document, assets)
    exposure = settings.network_exposure_value

    ranked, not_in_document = [], []
    for asset in assets:
        vulnerabilities = asset["vulnerabilities"] or []
        severity = max((float(item.get("cvss") or 0) for item in vulnerabilities), default=0) * 10
        epss = max((float(item.get("epss") or 0) for item in vulnerabilities), default=0) * 100
        kev = 100 if any(item.get("kev") for item in vulnerabilities) else 0

        match = matches.get(asset["asset_id"])
        if match:
            row = match["row"]
            criticality = row["criticality_value"]
            criticality_category = row["criticality_category"]
            purpose = row["purpose"]
            matched_device_name = row["device_name"]
            match_flag = match["flag"]
            match_group = "ranked"
        else:
            criticality = DEFAULT_CRITICALITY_VALUE
            criticality_category = DEFAULT_CRITICALITY_CATEGORY
            purpose = None
            matched_device_name = None
            match_flag = None
            match_group = "not_in_document"

        scored = {
            **_serialize(asset),
            "device_identifier": asset["hostname"] or asset["ip_address"],
            "severity_normalized": round(severity, 1),
            "epss_normalized": round(epss, 1),
            "kev_normalized": kev,
            "exposure": exposure,
            "asset_criticality": criticality,
            # criticality_category is already the exact document label; the
            # *_key form is what the rest of the app uses to group categories.
            "criticality_category": criticality_category,
            "criticality_label": criticality_category,
            "criticality_source": "asset_document" if match else "default",
            "matched_device_name": matched_device_name,
            "purpose": purpose,
            "match_flag": match_flag,
            "match_group": match_group,
            "document_note": None if match else NOT_IN_DOCUMENT_NOTE,
        }
        score, label = score_asset(severity, epss, kev, exposure, criticality)
        scored.update({"score": score, "label": label, "risk_score": score, "risk_band": label.lower()})
        scored["max_cvss"] = round(severity / 10, 1)
        scored["max_epss"] = round(epss / 100, 4)
        scored["has_kev"] = kev == 100
        scored["active_vuln_count"] = len(vulnerabilities)
        scored["recommendations"] = recommendations(scored)
        (ranked if match_group == "ranked" else not_in_document).append(scored)

    def order(item):
        return (-item["score"], str(item["device_identifier"] or "").lower())

    ranked.sort(key=order)
    not_in_document.sort(key=order)
    total = len(ranked) + len(not_in_document)
    for index, item in enumerate(ranked + not_in_document, start=1):
        item["priority_rank"] = index
        item["priority_total"] = total

    missing_from_scan = [{
        "device_name": row["device_name"],
        "ip_address": row["ip_address"],
        "purpose": row["purpose"],
        "criticality_category": row["criticality_category"],
        "criticality_value": row["criticality_value"],
        "note": MISSING_FROM_SCAN_NOTE,
    } for row in unmatched_rows]
    return {
        "ranked": ranked,
        "not_in_document": not_in_document,
        "missing_from_scan": missing_from_scan,
    }


def risk_readiness():
    # Readiness is now a single precondition: an asset document must exist.
    # There is no network-context CSV to require and no per-device criticality
    # to assign, so nothing else can block ranking.
    state = asset_document_state()
    return {
        "asset_document_uploaded": state["asset_document_uploaded"],
        "uploaded_at": state["uploaded_at"],
        "ready_to_rank": state["asset_document_uploaded"],
    }


def get_current_ranking():
    with connection() as conn:
        state = conn.execute("SELECT ranked_at FROM risk_ranking_state WHERE state_id=1").fetchone()
        results = conn.execute("""
          SELECT match_group, priority_rank, payload
            FROM risk_ranking_results
           ORDER BY priority_rank ASC
        """).fetchall()
        missing = conn.execute("""
          SELECT device_name, host(ip_address) AS ip_address, purpose, criticality_category, criticality_value, note
            FROM risk_ranking_missing ORDER BY device_name NULLS LAST, ip_address
        """).fetchall()
    ranked_at = _serialize(state)["ranked_at"] if state else None
    return {
        "last_ranked_at": ranked_at,
        "ranking_stale": bool(ranked_at and _ranking_is_stale(ranked_at)),
        "ranked": [row["payload"] for row in results if row["match_group"] == "ranked"],
        "not_in_document": [row["payload"] for row in results if row["match_group"] == "not_in_document"],
        "missing_from_scan": missing,
    }


def _ranking_is_stale(ranked_at):
    # A ranking goes stale when the inputs to it move: a new document upload
    # or a device observed after the ranking ran. It is never recalculated
    # silently - the UI asks the administrator to do it.
    with connection() as conn:
        row = conn.execute("""
          SELECT GREATEST(
            COALESCE((SELECT max(last_seen) FROM assets), '-infinity'::timestamptz),
            COALESCE((SELECT max(uploaded_at) FROM asset_document_uploads), '-infinity'::timestamptz)
          ) > %s AS stale
        """, (ranked_at,)).fetchone()
    return bool(row["stale"])


def calculate_and_store_ranking():
    state = risk_readiness()
    if not state["ready_to_rank"]:
        raise AssetDocumentMissing(state)
    groups = _calculate_asset_ranking()
    ranked_at = datetime.now(timezone.utc)
    with connection() as conn:
        conn.execute("DELETE FROM risk_ranking_results")
        conn.execute("DELETE FROM risk_ranking_missing")
        for item in groups["ranked"] + groups["not_in_document"]:
            conn.execute("""
              INSERT INTO risk_ranking_results(asset_id, priority_rank, match_group, risk_score, risk_band, payload, ranked_at)
              VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (item["asset_id"], item["priority_rank"], item["match_group"],
                  item["risk_score"], item["risk_band"], Jsonb(_json_safe(item)), ranked_at))
        for item in groups["missing_from_scan"]:
            conn.execute("""
              INSERT INTO risk_ranking_missing(device_name, ip_address, purpose, criticality_category,
                                               criticality_value, note, ranked_at)
              VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (item["device_name"], item["ip_address"], item["purpose"],
                  item["criticality_category"], item["criticality_value"], item["note"], ranked_at))
        conn.execute("""INSERT INTO risk_ranking_state(state_id,ranked_at,ranking)
          VALUES (1,%s,%s)
          ON CONFLICT (state_id) DO UPDATE SET ranked_at=EXCLUDED.ranked_at,ranking=EXCLUDED.ranking""",
          (ranked_at, Jsonb({"ranked": len(groups["ranked"]),
                             "not_in_document": len(groups["not_in_document"]),
                             "missing_from_scan": len(groups["missing_from_scan"])})))
    return {"last_ranked_at": ranked_at, **groups}


def asset_risk_ranking():
    return get_current_ranking()


# Captures the current document-driven ETSNTECH score for a scan snapshot.
def snapshot_asset_risk(scan_id):
    current = get_current_ranking()
    # Both groups of scored devices are snapshotted; only group 1 and group 3
    # have a score at all (group 2 is document rows that were never seen).
    rows = [row for row in (current["ranked"] + current["not_in_document"])
            if row.get("risk_score") is not None]
    with connection() as conn:
        for row in rows:
            conn.execute("""INSERT INTO asset_risk_snapshots(scan_id,asset_id,risk_score,risk_band)
              VALUES (%s,%s,%s,%s)
              ON CONFLICT (scan_id,asset_id) DO UPDATE SET risk_score=EXCLUDED.risk_score,risk_band=EXCLUDED.risk_band,captured_at=now()""",
              (scan_id, row["asset_id"], row["risk_score"], row["risk_band"]))
    return len(rows)


# Now that Layer 8 exists, the trend uses assets' real current risk score
# rather than a raw vulnerability count. Same caveat as the vulnerability-count
# proxy it replaces: this is "based on what we know today, how risky were the
# assets seen in scan X" â€” CVSS/EPSS/KEV data isn't versioned per scan, so it
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


# Project guide Â§12.2: "This formula ... must be labelled 'ETSNTECH prototype
# prioritization index'. Do not describe the result as the probability that
# an organization will be breached." Carried in the API response so every
# consumer (current UI and any future one) inherits the required wording.
EARI_INDEX_LABEL = "ETSNTECH prototype prioritization index"


def risk_summary():
    current = get_current_ranking()
    # Counts are derived from exactly the devices the page renders (group 1 +
    # group 3), so the summary can never disagree with the list below it.
    shown = [row for row in (current["ranked"] + current["not_in_document"])
             if row.get("risk_score") is not None]
    return {
        "index_label": EARI_INDEX_LABEL,
        "assets_scored": len(shown),
        "critical": sum(1 for r in shown if r["risk_band"] == "critical"),
        "high": sum(1 for r in shown if r["risk_band"] == "high"),
        "elevated": sum(1 for r in shown if r["label"] == "Elevated"),
        "moderate": sum(1 for r in shown if r["label"] == "Moderate"),
        "medium": sum(1 for r in shown if r["label"] in {"Elevated", "Moderate"}),
        "low": sum(1 for r in shown if r["risk_band"] == "low"),
        "kev_matches": sum(1 for r in shown if r["has_kev"]),
        "top_risk_asset": shown[0] if shown else None,
        "not_in_document_count": len(current["not_in_document"]),
        "missing_from_scan_count": len(current["missing_from_scan"]),
        "data_freshness": risk_data_freshness(),
        "ranked_at": current["last_ranked_at"],
        "ranking_stale": current["ranking_stale"],
    }


def risk_data_freshness():
    """Return source timestamps used by the Layer 8 score and Layer 9 copy."""
    with connection() as conn:
        row = conn.execute("""
          SELECT
            (SELECT max(nvd_last_refreshed_at) FROM vulnerabilities) AS nvd_last_refreshed_at,
            (SELECT max(last_refreshed_at) FROM nvd_cpe_cache) AS nvd_cache_last_refreshed_at,
            (SELECT max(finished_at) FROM epss_download_runs WHERE status='completed') AS epss_last_completed_at,
            (SELECT max(updated_at) FROM epss_current_scores) AS epss_last_updated_at,
            (SELECT max(finished_at) FROM kev_refresh_runs WHERE status='completed') AS kev_last_completed_at
        """).fetchone()
        return _serialize(row)

# --- Cross-network per-VLAN detection --------------------------------------
# A VLAN is keyed by vlan_id and a routed network by cidr (both unique indexes
# are partial), so detection upserts on whichever it actually learned. Evidence
# from every device that reported the same VLAN is merged into `sources` rather
# than overwritten, so a network seen by two switches keeps both.


def upsert_detected_network(network):
    """Insert or refresh one detected VLAN/network, preserving merge history."""
    sources = network.get("sources") or []
    cidr_value = str(network["cidr"]) if network.get("cidr") else None
    vlan_value = network.get("vlan_id")
    hops = network.get("reachability_hops") or []
    hops_json = json.dumps(hops) if hops else None
    with connection() as conn:
        # IS NOT DISTINCT FROM keeps the NULL-aware match, and keeps Postgres
        # able to infer each placeholder's type from the column it is compared
        # against. A bare `%s IS NOT NULL` guard is untyped and errors out.
        existing = conn.execute(
            "SELECT network_id, sources FROM networks "
            "WHERE (vlan_id IS NOT NULL AND vlan_id IS NOT DISTINCT FROM %s) "
            "   OR (cidr IS NOT NULL AND cidr IS NOT DISTINCT FROM %s::cidr) "
            "ORDER BY last_seen DESC LIMIT 1",
            (vlan_value, cidr_value),
        ).fetchone()
        if existing:
            merged = list(existing.get("sources") or [])
            for source in sources:
                if source not in merged:
                    merged.append(source)
            row = conn.execute(
                """UPDATE networks SET cidr=COALESCE(%s::cidr, cidr), vlan_id=COALESCE(%s, vlan_id),
                   label=COALESCE(%s, label), estimated_device_count=%s, count_method=COALESCE(%s, count_method),
                   is_scannable=%s, reachability_reason=%s, subnet_evidence=%s, if_indexes=%s,
                   reachability_path=COALESCE(%s, reachability_path),
                   reachability_hops=CASE WHEN %s::jsonb IS NULL THEN reachability_hops ELSE %s::jsonb END,
                   sources=%s, last_seen=now()
                   WHERE network_id=%s RETURNING *""",
                (cidr_value, vlan_value, network.get("label"),
                 network.get("estimated_device_count"), network.get("count_method"),
                 bool(network.get("scannable", network.get("is_scannable"))), network.get("reachability_reason"),
                 network.get("subnet_evidence"), network.get("if_indexes") or [],
                 network.get("reachability_path"), hops_json, hops_json,
                 Jsonb(merged), existing["network_id"]),
            ).fetchone()
            return _serialize(row)
        row = conn.execute(
            """INSERT INTO networks(cidr, vlan_id, label, is_local, sources, estimated_device_count,
               count_method, is_scannable, reachability_reason, subnet_evidence, if_indexes,
               reachability_path, reachability_hops)
               VALUES (%s::cidr,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (cidr_value, vlan_value, network.get("label"), bool(network.get("is_local")),
             Jsonb(sources), network.get("estimated_device_count"), network.get("count_method"),
             bool(network.get("scannable", network.get("is_scannable"))), network.get("reachability_reason"),
             network.get("subnet_evidence"), network.get("if_indexes") or [],
             network.get("reachability_path"), Jsonb(hops or [])),
        ).fetchone()
        return _serialize(row)


def list_networks():
    """Every detected VLAN/network, one row each, local first then by VLAN id."""
    from .config import settings
    freshness_window = settings.scan_freshness_window_minutes
    with connection() as conn:
        rows = conn.execute(
            f"""SELECT n.*, n.cidr::text AS cidr_text,
               (SELECT count(*) FROM assets a WHERE a.network_id = n.network_id) AS known_asset_count,
               (SELECT scan_summary FROM scan_sessions s
                WHERE s.network_id = n.network_id AND s.status = 'COMPLETED'
                ORDER BY s.finished_at DESC LIMIT 1) AS scan_summary,
               (SELECT s.finished_at FROM scan_sessions s
                WHERE s.network_id = n.network_id AND s.status = 'COMPLETED'
                ORDER BY s.finished_at DESC LIMIT 1) AS last_scanned_at,
               CASE 
                 WHEN n.is_local THEN false
                 WHEN (SELECT s.finished_at FROM scan_sessions s
                       WHERE s.network_id = n.network_id AND s.status = 'COMPLETED'
                       ORDER BY s.finished_at DESC LIMIT 1) IS NULL THEN true
                 ELSE (SELECT s.finished_at < now() - make_interval(mins => %s) FROM scan_sessions s
                       WHERE s.network_id = n.network_id AND s.status = 'COMPLETED'
                       ORDER BY s.finished_at DESC LIMIT 1)
               END AS is_stale
               FROM networks n ORDER BY n.is_local DESC, n.vlan_id NULLS LAST, n.cidr NULLS LAST""",
            (freshness_window,)
        ).fetchall()
    return [_serialize(row) for row in rows]


def update_network_is_local(network_id: str, is_local: bool):
    """Update the is_local flag for a network."""
    with connection() as conn:
        conn.execute(
            "UPDATE networks SET is_local=%s WHERE network_id=%s",
            (is_local, network_id)
        )


def get_network(network_id):
    with connection() as conn:
        row = conn.execute(
            "SELECT *, cidr::text AS cidr_text FROM networks WHERE network_id=%s", (network_id,)
        ).fetchone()
    return _serialize(row) if row else None


def approve_network(network_id: str, approved_by: str, reason: str | None = None):
    """Approve a network for automatic scanning."""
    with connection() as conn:
        conn.execute(
            """UPDATE networks SET approved=true, approved_by=%s, approved_at=now()
               WHERE network_id=%s""",
            (approved_by, network_id)
        )
        conn.execute(
            """INSERT INTO network_approvals(network_id, approved, approved_by, reason)
               VALUES (%s, true, %s, %s)""",
            (network_id, approved_by, reason)
        )
    return get_network(network_id)


def revoke_network(network_id: str, approved_by: str, reason: str | None = None):
    """Revoke approval for a network."""
    with connection() as conn:
        conn.execute(
            """UPDATE networks SET approved=false, approved_by=%s, approved_at=now()
               WHERE network_id=%s""",
            (approved_by, network_id)
        )
        conn.execute(
            """INSERT INTO network_approvals(network_id, approved, approved_by, reason)
               VALUES (%s, false, %s, %s)""",
            (network_id, approved_by, reason)
        )
    return get_network(network_id)


def get_network_approvals(network_id: str):
    """Get approval history for a network."""
    with connection() as conn:
        rows = conn.execute(
            "SELECT * FROM network_approvals WHERE network_id=%s ORDER BY approved_at DESC",
            (network_id,)
        ).fetchall()
    return [_serialize(row) for row in rows]


def get_approved_networks():
    """Get all approved networks for automatic scanning."""
    with connection() as conn:
        rows = conn.execute(
            "SELECT *, cidr::text AS cidr_text FROM networks WHERE approved=true AND cidr IS NOT NULL"
        ).fetchall()
    return [_serialize(row) for row in rows]


def get_snmp_arp_entries_for_subnet(subnet: str) -> dict[str, str]:
    """Return {ip: mac} for all SNMP ARP observations within the given subnet."""
    network = ipaddress.ip_network(subnet, strict=False)
    with connection() as conn:
        rows = conn.execute(
            "SELECT host(ip_address)::text as ip, mac_address::text FROM snmp_mac_ip_observations WHERE ip_address <<= %s",
            (str(network),)
        ).fetchall()
    return {row["ip"]: row["mac_address"] for row in rows}


def store_scan_summary(session_id: str, summary: dict):
    """Store scan summary statistics."""
    import json
    with connection() as conn:
        conn.execute(
            "UPDATE scan_sessions SET scan_summary = %s WHERE id = %s",
            (json.dumps(summary), session_id)
        )


def mark_network_scanned(network_id, session_id=None):
    with connection() as conn:
        row = conn.execute(
            "UPDATE networks SET status='scanned', last_scanned_at=now() WHERE network_id=%s RETURNING *",
            (network_id,),
        ).fetchone()
        if session_id:
            conn.execute("UPDATE network_scan_requests SET status='running', scan_session_id=%s "
                         "WHERE network_id=%s AND status='accepted'", (session_id, network_id))
    return _serialize(row) if row else None


def mark_network_scanned_by_cidr(cidr, session_id=None):
    """Update last_scanned_at for a network by CIDR (for manual scans without network_id)."""
    with connection() as conn:
        row = conn.execute(
            "UPDATE networks SET status='scanned', last_scanned_at=now() WHERE cidr=%s::cidr RETURNING *",
            (cidr,),
        ).fetchone()
    return _serialize(row) if row else None


def finish_network_scan_request(request_id, status, session_id=None, rejection_reason=None):
    with connection() as conn:
        row = conn.execute(
            "UPDATE network_scan_requests SET status=%s, scan_session_id=COALESCE(%s, scan_session_id), "
            "rejection_reason=%s WHERE request_id=%s RETURNING *",
            (status, session_id, rejection_reason, request_id),
        ).fetchone()
    return _serialize(row) if row else None


def create_network_scan_request(network_id, requested_by, confirmed_authorization, status,
                                rejection_reason=None):
    with connection() as conn:
        row = conn.execute(
            """INSERT INTO network_scan_requests(network_id, requested_by, confirmed_authorization,
               status, rejection_reason) VALUES (%s,%s,%s,%s,%s) RETURNING *""",
            (network_id, requested_by, confirmed_authorization, status, rejection_reason),
        ).fetchone()
    return _serialize(row)


def attribute_assets_to_networks():
    """Assign each asset to a network by IP-in-CIDR (null when ambiguous).

    Longest-prefix wins so a specific remote network is preferred over a broad
    one. Assets with no containing network are left null rather than guessed.
    """
    with connection() as conn:
        return conn.execute(
            """UPDATE assets a SET network_id = m.network_id
               FROM (
                   SELECT DISTINCT ON (a2.asset_id) a2.asset_id, n.network_id
                   FROM assets a2 JOIN networks n ON n.cidr IS NOT NULL
                   WHERE a2.ip_address <<= n.cidr
                   ORDER BY a2.asset_id, masklen(n.cidr) DESC
               ) m
               WHERE a.asset_id = m.asset_id AND a.network_id IS DISTINCT FROM m.network_id"""
        ).rowcount

import asyncio
import csv
import io
import json
import logging
import threading
from pathlib import Path

import psycopg
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from openpyxl import load_workbook

from . import repository
from . import cross_network
from .config import settings
from .database import connection, initialize_schema
from .scan_service import ScanAlreadyRunning, ScanCoordinator
from .scanner import validate_authorized_subnet
from .network import connected_ipv4_networks
from .schemas import (AssetUpdate, FindingUpdate, NetworkScanRequest, ScanStart,
                      VulnerabilityMatchUpdate)
from .nvd import coordinator as nvd_coordinator
from .epss import coordinator as epss_coordinator, recalculate_organization_risk
from .kev import refresh_kev as run_kev_refresh
from datetime import datetime, timezone
from .risk_engine import parse_asset_document

# Shown verbatim by the UI (tooltip, inline line, and the 409 body) so the
# blocked-ranking reason is worded identically everywhere.
READINESS_BLOCKED_MESSAGE = "Upload the asset document first. Ranking runs only after it is uploaded."

class EventHub:
    def __init__(self): self.clients: set[WebSocket] = set(); self.loop = None
    async def connect(self, socket): await socket.accept(); self.clients.add(socket)
    def publish(self, event, data):
        if not self.loop: return
        asyncio.run_coroutine_threadsafe(self._broadcast({"event": event, "data": data}), self.loop)
    async def _broadcast(self, payload):
        stale = []
        for socket in self.clients:
            try: await socket.send_text(json.dumps(payload, default=str))
            except Exception: stale.append(socket)
        for socket in stale: self.clients.discard(socket)


hub = EventHub()
coordinator = ScanCoordinator(hub.publish)


@asynccontextmanager
async def lifespan(_app):
    initialize_schema()
    hub.loop = asyncio.get_running_loop()
    _reconcile_orphaned_sessions()
    _reclassify_existing_assets()
    epss_coordinator.start(hub.publish)
    coordinator.start_sweeper()
    try:
        yield
    finally:
        coordinator.stop_sweeper()
        epss_coordinator.stop()


def _reconcile_orphaned_sessions():
    """Fail any session still marked RUNNING at startup.

    Scan work happens in in-process threads, so a restart (crash, redeploy,
    Ctrl+C) kills those threads outright and leaves their rows stuck at
    RUNNING forever. Nothing ever finishes them: the dashboard then shows
    "Stop Session" permanently, and a device that was never probed stays
    counted exactly like one that was probed and did not answer.
    """
    try:
        stranded = repository.fail_orphaned_running_sessions()
    except Exception:
        return
    for session in stranded:
        logging.info(
            "marked orphaned session %s as FAILED (its scan thread did not "
            "survive a restart)", session["id"],
        )


def _reclassify_existing_assets():
    """Apply the current device-classification priority to stored assets.

    Devices discovered before the OS/vendor-aware classifier existed still carry
    the old port-only type, so every stored asset is re-evaluated against the
    evidence already on record instead of waiting for its next scan.
    """
    try:
        corrections = repository.reclassify_stored_assets()
    except Exception:
        return []
    for item in corrections:
        logging.info(
            "reclassified %s (%s): %s -> %s via %s",
            item["ip_address"], item["hostname"] or "unresolved",
            item["from"], item["to"], item["source"],
        )
    return corrections


app = FastAPI(title="SecureOps Asset Discovery API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_origin_regex=settings.cors_origin_regex, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    with connection() as conn: conn.execute("SELECT 1")
    return {"status": "UP", "service": "asset-discovery"}


@app.get("/api/v1/devices")
def devices(
    status: str | None = None, 
    device_type: str | None = Query(default=None, alias="type"), 
    scan_id: str | None = None,
    last_24h: bool | None = Query(default=None, alias="last24h"),
    network_id: str | None = None,
    latest_scan_per_network: bool | None = Query(default=None, alias="latestScanPerNetwork"),
    direct_probe_only: bool | None = Query(default=None, alias="directProbeOnly"),
):
    # Default to latest scan per network and direct probe only for "Devices - right now" view
    if latest_scan_per_network is None:
        latest_scan_per_network = True
    if direct_probe_only is None:
        direct_probe_only = True
    return {"data": repository.list_assets(
        status, device_type, scan_id, last_24h, network_id, 
        latest_scan_per_network, direct_probe_only
    )}


@app.get("/api/v1/devices/{asset_id}/services")
def asset_services(asset_id: str):
    return {"data": repository.list_services(asset_id=asset_id)}


@app.get("/api/v1/services")
def services(
    asset_id: str | None = None,
    confidence: str | None = None,
    enrichment_status: str | None = None,
    port: int | None = Query(default=None, ge=1, le=65535),
    q: str | None = Query(default=None, max_length=120),
    scan_id: str | None = None,
):
    if confidence and confidence not in {"high", "medium", "low"}:
        raise HTTPException(400, "confidence must be high, medium, or low")
    if enrichment_status and enrichment_status not in {"not_enriched", "cpe_ready", "enriched"}:
        raise HTTPException(400, "invalid enrichment status")
    return {"data": repository.list_services(asset_id, confidence, enrichment_status, port, q, scan_id)}


@app.get("/api/v1/services/summary")
def services_summary():
    return {"data": repository.service_summary()}


@app.get("/api/v1/findings")
def findings(
    status: str | None = None,
    severity: str | None = None,
    confidence: str | None = None,
    check_id: str | None = None,
    q: str | None = Query(default=None, max_length=120),
    scan_id: str | None = None,
):
    return {"data": repository.list_findings(status, severity, confidence, check_id, q, scan_id)}


@app.get("/api/v1/findings/summary")
def findings_summary():
    return {"data": repository.findings_summary()}


@app.patch("/api/v1/findings/{finding_id}")
def patch_finding(finding_id: str, payload: FindingUpdate):
    result = repository.update_finding_status(finding_id, payload.status)
    if not result: raise HTTPException(404, "Finding not found")
    hub.publish("FINDING_UPDATED", result)
    return {"data": result}


@app.get("/api/v1/vulnerabilities")
def vulnerabilities(
    status: str | None = "active", severity: str | None = None,
    confidence: str | None = None, q: str | None = Query(default=None, max_length=120),
    scan_id: str | None = None,
):
    return {"data": repository.list_vulnerabilities(status, severity, confidence, q, scan_id)}


@app.get("/api/v1/vulnerabilities/summary")
def vulnerabilities_summary():
    return {"data": repository.vulnerabilities_summary()}


@app.patch("/api/v1/vulnerabilities/{match_id}")
def patch_vulnerability_match(match_id: str, payload: VulnerabilityMatchUpdate):
    result = repository.update_vulnerability_match_status(match_id, payload.status)
    if not result: raise HTTPException(404, "Vulnerability match not found")
    hub.publish("VULNERABILITY_UPDATED", result)
    return {"data": result}


@app.get("/api/v1/enrichment/runs")
def enrichment_runs(limit: int = Query(20, ge=1, le=100)):
    return {"data": repository.list_enrichment_runs(limit)}


@app.post("/api/v1/enrichment/refresh", status_code=202)
def refresh_enrichment():
    job_id = nvd_coordinator.schedule(None, "manual")
    return {"enrichment_run_id": job_id, "status": "queued"}


@app.get("/api/v1/epss/intelligence")
def epss_intelligence(status: str | None = "active", q: str | None = Query(default=None, max_length=120), scan_id: str | None = None):
    return {"data": repository.list_epss_intelligence(status, q, scan_id)}


@app.get("/api/v1/epss/summary")
def epss_summary():
    return {"data": repository.epss_summary()}


@app.get("/api/v1/epss/runs")
def epss_runs(limit: int = Query(20, ge=1, le=100)):
    return {"data": repository.list_epss_runs(limit)}


@app.post("/api/v1/epss/refresh", status_code=202)
def refresh_epss():
    run_id = epss_coordinator.schedule(trigger_source="manual", force=True)
    return {"epss_run_id": run_id, "status": "queued"}


@app.get("/api/v1/kev/intelligence")
def kev_intelligence(status: str | None = "active", q: str | None = Query(default=None, max_length=120), scan_id: str | None = None):
    return {"data": repository.list_kev_intelligence(status, q, scan_id)}


@app.get("/api/v1/kev/summary")
def kev_summary():
    return {"data": repository.kev_summary()}


@app.get("/api/v1/kev/runs")
def kev_runs(limit: int = Query(20, ge=1, le=100)):
    return {"data": repository.list_kev_runs(limit)}


@app.post("/api/v1/kev/refresh", status_code=202)
def refresh_kev():
    threading.Thread(target=run_kev_refresh, args=("manual",), daemon=True, name="kev-manual").start()
    return {"status": "queued"}


@app.get("/api/v1/telemetry/changes")
def telemetry_changes(to_scan_id: str | None = None, from_scan_id: str | None = None):
    return {"data": repository.telemetry_changes(to_scan_id, from_scan_id)}


@app.get("/api/v1/telemetry/trend")
def telemetry_trend(limit: int = Query(10, ge=2, le=50)):
    return {"data": repository.telemetry_trend(limit)}


@app.get("/api/v1/risk/assets")
def risk_assets():
    return {"data": repository.asset_risk_ranking()}


@app.get("/api/v1/risk/readiness")
def risk_readiness():
    return {"data": repository.risk_readiness()}


@app.post("/api/v1/risk/calculate")
def calculate_risk():
    # Ranking is never produced without an asset document, and the 409 body is
    # the readiness payload so the UI can explain exactly what is missing.
    readiness = repository.risk_readiness()
    if not readiness["ready_to_rank"]:
        raise HTTPException(409, {**readiness, "message": READINESS_BLOCKED_MESSAGE})
    result = repository.calculate_and_store_ranking()
    return {"data": result, "ranked_at": result["last_ranked_at"]}


@app.get("/api/v1/risk/summary")
def risk_summary():
    return {"data": repository.risk_summary()}


@app.patch("/api/v1/devices/{asset_id}")
def patch_device(asset_id: str, payload: AssetUpdate):
    result = repository.update_asset(asset_id, payload.model_dump())
    if not result: raise HTTPException(404, "Asset not found or no changes supplied")
    recalculate_organization_risk()
    hub.publish("ASSET_UPDATED", result)
    return {"data": result}


ASSET_DOCUMENT_SHEET_NAME = "Device Criticality"


def _decode_asset_document(filename: str, content: bytes) -> list[list]:
    """Return the document as a list of rows, from .csv or .xlsx."""
    suffix = Path(filename or "").suffix.lower()
    if suffix in {".xlsx", ".xlsm"}:
        try:
            workbook = load_workbook(io.BytesIO(content), data_only=True, read_only=True)
        except Exception as exc:
            raise HTTPException(400, {"message": "The file could not be read as a spreadsheet", "errors": [
                {"row": 0, "column": "-", "problem": str(exc)[:300], "expected": "A readable .xlsx workbook"}]}) from exc
        # Prefer the named sheet so a workbook may keep its own cover/index
        # sheets alongside the device list.
        if ASSET_DOCUMENT_SHEET_NAME in workbook.sheetnames:
            sheet = workbook[ASSET_DOCUMENT_SHEET_NAME]
        else:
            sheet = workbook[workbook.sheetnames[0]] if workbook.sheetnames else None
        if sheet is None:
            raise HTTPException(400, {"message": "The spreadsheet has no sheets", "errors": []})
        return [[cell for cell in row] for row in sheet.iter_rows(values_only=True)]
    if suffix in {".xls"}:
        raise HTTPException(400, {"message": "Only .csv and .xlsx are supported", "errors": [
            {"row": 0, "column": "-", "problem": "Legacy .xls workbooks are not supported",
             "expected": "Upload a .csv or re-save as .xlsx"}]})
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(400, {"message": "The file must be UTF-8 encoded CSV or a .xlsx workbook", "errors": [
            {"row": 0, "column": "-", "problem": "The file is not valid UTF-8 text",
             "expected": "A UTF-8 .csv file, or a .xlsx workbook"}]}) from exc
    return [row for row in csv.reader(io.StringIO(text))]


@app.post("/api/v1/risk/policy/asset-document")
async def upload_asset_document(file: UploadFile = File(...)):
    """Upload the single asset document that drives Layer 8 ranking.

    The whole file is validated: if any row is wrong the upload is rejected
    and every problem is returned, so nothing partially replaces the document
    already in force.
    """
    content = await file.read()
    rows = _decode_asset_document(file.filename, content)
    valid_rows, errors = parse_asset_document(rows)
    if errors:
        raise HTTPException(400, {
            "message": "The asset document was rejected. Nothing was uploaded - fix the rows below and try again.",
            "errors": errors,
        })
    result = repository.save_asset_document(valid_rows)
    current = repository.get_current_ranking()
    return {
        "rows_uploaded": result["row_count"],
        "uploaded_at": result["uploaded_at"].isoformat(),
        "ranking_stale": current["ranking_stale"],
    }


@app.get("/api/v1/scan/activity")
def activity(limit: int = Query(8, ge=1, le=200), scan_id: str | None = None): return {"data": repository.list_activity(limit, scan_id)}


@app.get("/api/v1/scan/history")
def history(): return {"data": repository.scan_history()}


@app.get("/api/v1/networks")
def list_networks():
    """Every detected VLAN/network as its own entry, with a reachability verdict.

    One row per VLAN, straight from the cross-network detection module so the
    scannable/not-reachable decision the UI disables a button on is the same
    decision the scan endpoint enforces.
    """
    rows = repository.list_networks()
    for row in rows:
        scannable, reason = cross_network.network_is_scannable(row)
        row["is_scannable"] = scannable
        row["reachability_reason"] = reason
    from .config import settings
    return {"data": {
        "networks": rows,
        "summary": cross_network.summarize_networks(rows),
        "targets": cross_network.discover_candidates(),
        "freshness_window_minutes": settings.scan_freshness_window_minutes,
    }}


@app.post("/api/v1/networks/{network_id}/approve")
def approve_network(network_id: str, payload: dict):
    """Approve a network for automatic inclusion in scans."""
    network = repository.get_network(network_id)
    if not network:
        raise HTTPException(404, "Network not found")
    approved_by = payload.get("approved_by", "unknown")
    reason = payload.get("reason")
    result = repository.approve_network(network_id, approved_by, reason)
    return {"data": result}


@app.post("/api/v1/networks/{network_id}/revoke")
def revoke_network(network_id: str, payload: dict):
    """Revoke approval for a network."""
    network = repository.get_network(network_id)
    if not network:
        raise HTTPException(404, "Network not found")
    approved_by = payload.get("approved_by", "unknown")
    reason = payload.get("reason")
    result = repository.revoke_network(network_id, approved_by, reason)
    return {"data": result}


@app.get("/api/v1/networks/{network_id}/approvals")
def get_network_approvals(network_id: str):
    """Get approval history for a network."""
    network = repository.get_network(network_id)
    if not network:
        raise HTTPException(404, "Network not found")
    approvals = repository.get_network_approvals(network_id)
    return {"data": approvals}


@app.post("/api/v1/networks/detect")
def detect_networks():
    """Re-run detection against every classified router/switch in inventory.

    Two layers, both read-only SNMP: per-VLAN direct detection, then multi-router
    traversal of the routing tables. Takes no router IP, gateway or any other
    per-run input - the targets are devices a previous scan already classified.
    """
    result = cross_network.detect_all()
    repository.attribute_assets_to_networks()
    return {"data": result}


@app.post("/api/v1/networks/{network_id}/scan", status_code=202)
def scan_network_by_id(network_id: str, payload: NetworkScanRequest):
    """Scan exactly one VLAN's subnet, after explicit authorization.

    Refuses outright - and records the refusal - when the VLAN was never
    reachable or authorization was not confirmed. An unreachable VLAN is never
    attempted, so a "scanned, 0 devices found" result can only ever mean the
    network was genuinely scanned and genuinely had no answering hosts.
    """
    network = repository.get_network(network_id)
    if not network:
        raise HTTPException(404, "Network not found")

    scannable, reason = cross_network.network_is_scannable(network)
    if not scannable:
        request = repository.create_network_scan_request(
            network_id, "unknown", payload.confirmed_authorization, "rejected", reason)
        raise HTTPException(409, {"message": reason, "request_id": request["request_id"]})

    if not payload.confirmed_authorization:
        message = ("Scanning another network requires confirming you are authorized to "
                   "scan it. No probe was sent.")
        request = repository.create_network_scan_request(
            network_id, "unknown", False, "rejected", message)
        raise HTTPException(403, {"message": message, "request_id": request["request_id"]})

    cidr = cross_network.record_cidr(network)
    session = repository.create_session(
        cidr, payload.durationMinutes, source="cross_network", network_id=network_id)
    request = repository.create_network_scan_request(
        network_id, "unknown", True, "accepted")
    try:
        coordinator.start(session)
    except ScanAlreadyRunning as exc:
        repository.finish_session(session["id"], "FAILED", 0,
                                  "Another scan was already running, so this one was never started.")
        repository.finish_network_scan_request(
            request["request_id"], "failed", rejection_reason="another scan was already running")
        raise HTTPException(409, {
            "message": "A scan is already running. Wait for it to finish, or stop it first.",
            "running_session_id": exc.running_session_id,
        }) from exc
    repository.finish_network_scan_request(request["request_id"], "running", session_id=session["id"])
    repository.mark_network_scanned(network_id, session_id=session["id"])
    hub.publish("SESSION_STARTED", session)
    return {"data": {"session": session, "request": request, "network": network_id}}


@app.post("/api/v1/networks/scan-all", status_code=202)
def scan_all_networks(payload: NetworkScanRequest):
    """Scan all detected non-local scannable networks at once, after explicit authorization.

    This scans each reachable network sequentially. If any network is not scannable,
    it is skipped with a warning. The authorization confirmation applies to all networks.
    """
    networks = repository.list_networks()
    non_local_scannable = [
        n for n in networks
        if not n.get("is_local") and cross_network.network_is_scannable(n)[0]
    ]
    
    # Also include approved networks (which may be local or remote)
    approved_networks = [
        n for n in networks
        if n.get("approved") and cross_network.network_is_scannable(n)[0]
    ]
    
    # Combine and deduplicate
    all_networks = {}
    for n in non_local_scannable + approved_networks:
        all_networks[n["network_id"]] = n
    networks_to_scan = list(all_networks.values())

    if not networks_to_scan:
        raise HTTPException(409, {"message": "No scannable networks detected (including approved)."})

    if not payload.confirmed_authorization:
        message = ("Scanning all networks requires confirming you are authorized to "
                   "scan each of them. No probes were sent.")
        raise HTTPException(403, {"message": message})

    results = []
    for network in networks_to_scan:
        cidr = cross_network.record_cidr(network)
        session = repository.create_session(
            cidr, payload.durationMinutes, source="cross_network", network_id=network["network_id"])
        request = repository.create_network_scan_request(
            network["network_id"], "unknown", True, "accepted")
        try:
            coordinator.start(session)
        except ScanAlreadyRunning as exc:
            repository.finish_session(session["id"], "FAILED", 0,
                                      "Another scan was already running, so this one was never started.")
            repository.finish_network_scan_request(
                request["request_id"], "failed", rejection_reason="another scan was already running")
            results.append({
                "network_id": network["network_id"],
                "cidr": cidr,
                "status": "error",
                "message": "Another scan was already running",
                "running_session_id": exc.running_session_id,
            })
            break
        repository.finish_network_scan_request(request["request_id"], "running", session_id=session["id"])
        repository.mark_network_scanned(network["network_id"], session_id=session["id"])
        hub.publish("SESSION_STARTED", session)
        results.append({
            "network_id": network["network_id"],
            "cidr": cidr,
            "session_id": session["id"],
            "status": "started",
        })

    return {"data": {"results": results, "total": len(networks_to_scan)}}


@app.post("/api/v1/scan/start-all", status_code=202)
def start_all_networks_scan(payload: NetworkScanRequest):
    """Start a scan covering all directly-attached networks plus approved networks.

    This is the "Start Scan Session" button: one scan that covers every network
    the host is directly attached to (every active adapter) plus every detected
    routed network the administrator has approved.
    """
    # Get all directly attached networks
    local_networks = connected_ipv4_networks()
    if not local_networks:
        raise HTTPException(409, {"message": "No active network adapters found."})
    
    # Get approved networks
    approved_networks = repository.get_approved_networks()
    
    # Build list of unique subnets to scan
    subnets_to_scan = []
    network_ids = []
    
    # Add local networks
    for net in local_networks:
        cidr = str(net)
        subnets_to_scan.append(cidr)
        network_ids.append(None)  # local networks don't have network_id
    
    # Add approved networks
    for net in approved_networks:
        cidr = cross_network.record_cidr(net)
        if cidr and cidr not in subnets_to_scan:
            subnets_to_scan.append(cidr)
            network_ids.append(net["network_id"])
    
    if not payload.confirmed_authorization:
        message = ("Scanning all attached and approved networks requires confirming "
                   "you are authorized. No probes were sent.")
        raise HTTPException(403, {"message": message})

    results = []
    for cidr, network_id in zip(subnets_to_scan, network_ids):
        session = repository.create_session(
            cidr, payload.durationMinutes, source="multi_network", network_id=network_id)
        if network_id:
            request = repository.create_network_scan_request(
                network_id, "unknown", True, "accepted")
        try:
            coordinator.start(session)
        except ScanAlreadyRunning as exc:
            repository.finish_session(session["id"], "FAILED", 0,
                                      "Another scan was already running, so this one was never started.")
            if network_id:
                repository.finish_network_scan_request(
                    request["request_id"], "failed", rejection_reason="another scan was already running")
            results.append({
                "cidr": cidr,
                "network_id": network_id,
                "status": "error",
                "message": "Another scan was already running",
                "running_session_id": exc.running_session_id,
            })
            break
        if network_id:
            repository.finish_network_scan_request(request["request_id"], "running", session_id=session["id"])
            repository.mark_network_scanned(network_id, session_id=session["id"])
        hub.publish("SESSION_STARTED", session)
        results.append({
            "cidr": cidr,
            "network_id": network_id,
            "session_id": session["id"],
            "status": "started",
        })

    return {"data": {"results": results, "total": len(subnets_to_scan)}}


@app.get("/api/v1/scan/sessions")
def sessions(): return {"data": repository.list_sessions()}


@app.get("/api/v1/scan/sessions/latest")
def latest_completed_session():
    """Return the latest completed scan session."""
    session = repository.get_latest_completed_session()
    return {"data": session}


@app.get("/api/v1/scan/sessions/{session_id}/checks")
def session_checks(session_id: str):
    return {"data": repository.list_exposure_checks(session_id)}


@app.get("/api/v1/scan/network")
def scan_network():
    networks = [str(network) for network in connected_ipv4_networks()]
    return {"data": {"selected": networks[0] if networks else None, "connected": networks}}


@app.post("/api/v1/scan/sessions", status_code=202)
def start_session(payload: ScanStart):
    try: subnet = validate_authorized_subnet(payload.subnet)
    except ValueError as exc: raise HTTPException(400, str(exc)) from exc
    session = repository.create_session(subnet, payload.durationMinutes)
    try: coordinator.start(session)
    except ScanAlreadyRunning as exc:
        # Do not leave the rejected attempt behind as a second RUNNING row.
        repository.finish_session(session["id"], "FAILED", 0,
                                  "Another scan was already running, so this one was never started.")
        raise HTTPException(409, {
            "message": "A scan is already running. Wait for it to finish, or stop it first.",
            "running_session_id": exc.running_session_id,
        }) from exc
    hub.publish("SESSION_STARTED", session)
    return session


@app.post("/api/v1/scan/sessions/reset")
def reset_scan_status():
    """Safety valve: clear anything that is not genuinely running.

    The coordinator reaps stale scans on its own, but if a wedged scan ever
    survives that, this clears the in-memory and database state so the team is
    never blocked without a way to recover.
    """
    cleared = coordinator.reap_stale()
    with connection() as conn:
        remaining = conn.execute(
            "SELECT count(*) AS n FROM scan_sessions WHERE status='RUNNING'"
        ).fetchone()["n"]
    return {
        "data": {
            "cleared": cleared,
            "running_sessions": remaining,
            "stale_after_seconds": coordinator.stale_after_seconds,
        }
    }


@app.post("/api/v1/scan/sessions/{session_id}/stop")
def stop_session(session_id: str):
    result = coordinator.stop(session_id)
    if not result: raise HTTPException(404, "Scan session not found")
    return result


@app.post("/api/v1/scan/sessions/{session_id}/resume", status_code=202)
def resume_session(session_id: str):
    previous = repository.get_session(session_id)
    if not previous: raise HTTPException(404, "Scan session not found")
    try: subnet = validate_authorized_subnet(previous["subnet"])
    except ValueError as exc: raise HTTPException(400, str(exc)) from exc
    session = repository.create_session(subnet, previous["duration_minutes"])
    coordinator.start(session); hub.publish("SESSION_STARTED", session)
    return session


@app.websocket("/ws/events")
async def events(socket: WebSocket):
    await hub.connect(socket)
    try:
        while True: await socket.receive_text()
    except WebSocketDisconnect: hub.clients.discard(socket)

import asyncio
import csv
import io
import json
import logging
import threading
import psycopg
from contextlib import asynccontextmanager
from typing import get_args

from fastapi import FastAPI, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from . import repository
from .config import settings
from .database import connection, initialize_schema
from .scan_service import ScanCoordinator
from .scanner import validate_authorized_subnet
from .network import connected_ipv4_networks
from .schemas import AssetCriticality, AssetUpdate, CriticalityUpdate, FindingUpdate, ScanStart, VulnerabilityMatchUpdate
from .nvd import coordinator as nvd_coordinator
from .epss import coordinator as epss_coordinator, recalculate_organization_risk
from .kev import refresh_kev as run_kev_refresh
from datetime import datetime, timezone
from ipaddress import ip_network
from .risk_engine import CRITICALITY_CATEGORY_VALUES, CRITICALITY_LABELS, CRITICALITY_VALUES, NETWORK_CONTEXT_VALUES

ASSET_CRITICALITY_VALUES = set(get_args(AssetCriticality))

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
    _reclassify_existing_assets()
    epss_coordinator.start(hub.publish)
    try:
        yield
    finally:
        epss_coordinator.stop()


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
app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    with connection() as conn: conn.execute("SELECT 1")
    return {"status": "UP", "service": "asset-discovery"}


@app.get("/api/v1/devices")
def devices(status: str | None = None, device_type: str | None = Query(default=None, alias="type"), scan_id: str | None = None):
    return {"data": repository.list_assets(status, device_type, scan_id)}


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
    readiness = repository.risk_readiness()
    if not readiness["ready_to_rank"]:
        raise HTTPException(409, readiness)
    result = repository.calculate_and_store_ranking()
    return {"data": result["assets"], "ranked_at": result["ranked_at"]}


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


@app.patch("/api/v1/risk/assets/{device_identifier}/criticality")
def patch_risk_criticality(device_identifier: str, payload: CriticalityUpdate):
    if payload.criticality_category not in CRITICALITY_CATEGORY_VALUES:
        raise HTTPException(422, {"message": "invalid criticality category", "allowed": list(CRITICALITY_CATEGORY_VALUES)})
    asset_id = repository.find_current_asset_identifier(device_identifier)
    if not asset_id:
        raise HTTPException(404, {"message": "device not found"})
    criticality = CRITICALITY_CATEGORY_VALUES[payload.criticality_category]
    try:
        result = repository.set_manual_criticality(asset_id, criticality)
    except psycopg.Error as exc:
        raise HTTPException(500, {"message": "database write failed", "detail": str(exc).splitlines()[0]}) from exc
    if not result:
        raise HTTPException(404, {"message": "device not found or is not currently present"})
    hub.publish("ASSET_UPDATED", result)
    current = repository.get_current_ranking()
    return {"data": result, "ranking": current["assets"], "ranked_at": current["ranked_at"], "ranking_stale": current["ranking_stale"], "criticality_category": payload.criticality_category}

def _policy_rows(content, required_headers, row_validator):
    try:
        reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
    except UnicodeDecodeError as exc:
        raise HTTPException(400, {"message": "Policy file must be a UTF-8 CSV", "errors": []}) from exc
    headers = [header.strip().lower() for header in (reader.fieldnames or []) if header is not None]
    if set(headers) != required_headers or len(headers) != len(required_headers):
        raise HTTPException(400, {"message": "CSV headers do not match the required columns", "expected": sorted(required_headers), "errors": []})
    valid_rows, errors = [], []
    for row_number, row in enumerate(reader, start=2):
        normalized = {str(key).strip().lower(): (value or "").strip() for key, value in row.items() if key is not None}
        error = row_validator(row_number, normalized)
        if error:
            errors.append(error)
        else:
            valid_rows.append(normalized)
    if errors:
        raise HTTPException(400, {"message": "Policy validation failed", "errors": errors})
    if not valid_rows:
        raise HTTPException(400, {"message": "Policy CSV contains no data rows", "errors": []})
    return valid_rows


@app.post("/api/v1/risk/policy/device-criticality")
async def upload_device_criticality_policy(file: UploadFile = File(...)):
    content = await file.read()
    allowed = {"low", "normal", "high", "critical"}

    def validate(row_number, row):
        if not row["device_identifier"]:
            return {"row": row_number, "message": "device_identifier must not be empty"}
        if row["criticality"] not in allowed:
            return {"row": row_number, "message": f"criticality must be one of {sorted(allowed)}, got '{row['criticality']}'"}
        return None

    rows = _policy_rows(content, {"device_identifier", "criticality"}, validate)
    updated_at = repository.save_device_criticality_policy(rows)
    return {"rows_uploaded": len(rows), "updated_at": updated_at.isoformat()}


@app.post("/api/v1/risk/policy/network-context")
async def upload_network_context_policy(file: UploadFile = File(...)):
    content = await file.read()

    def validate(row_number, row):
        if not row["subnet_cidr"]:
            return {"row": row_number, "message": "subnet_cidr must not be empty"}
        try:
            ip_network(row["subnet_cidr"], strict=False)
        except ValueError:
            return {"row": row_number, "message": f"subnet_cidr is not valid CIDR notation: '{row['subnet_cidr']}'"}
        if row["context_label"] not in NETWORK_CONTEXT_VALUES:
            return {"row": row_number, "message": f"context_label must be one of the six exact values, got '{row['context_label']}'"}
        return None

    rows = _policy_rows(content, {"subnet_cidr", "context_label", "notes"}, validate)
    updated_at = repository.save_network_context_policy(rows)
    return {"rows_uploaded": len(rows), "updated_at": updated_at.isoformat()}


@app.post("/api/v1/assets/policy/upload")
async def upload_asset_policy_compatibility(file: UploadFile = File(...)):
    return await upload_device_criticality_policy(file)


@app.post("/api/v1/assets/criticality/upload")
async def upload_asset_criticality(file: UploadFile = File(...)):
    content = await file.read()
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(400, "Policy file must be a UTF-8 CSV") from exc

    reader = csv.DictReader(io.StringIO(text))
    headers = {(header or "").strip().lower() for header in (reader.fieldnames or [])}
    if not {"device_identifier", "criticality"}.issubset(headers):
        raise HTTPException(400, "CSV must contain device_identifier and criticality columns")

    updated, not_found, invalid = [], [], []
    for row in reader:
        normalized = {(key or "").strip().lower(): (value or "").strip() for key, value in row.items() if key}
        identifier = normalized.get("device_identifier", "")
        criticality = normalized.get("criticality", "").lower()
        if not identifier: continue
        if criticality not in ASSET_CRITICALITY_VALUES:
            invalid.append(identifier); continue
        asset = repository.find_asset_by_identifier(identifier)
        if not asset:
            not_found.append(identifier); continue
        repository.set_csv_criticality(asset["asset_id"], criticality)
        result = repository.find_asset_by_identifier(identifier)
        hub.publish("ASSET_UPDATED", result)
        updated.append(identifier)

    if updated: recalculate_organization_risk()
    return {"updated": len(updated), "not_found": not_found, "invalid_criticality": invalid}


@app.get("/api/v1/scan/activity")
def activity(limit: int = Query(8, ge=1, le=200), scan_id: str | None = None): return {"data": repository.list_activity(limit, scan_id)}


@app.get("/api/v1/scan/history")
def history(): return {"data": repository.scan_history()}


@app.get("/api/v1/scan/sessions")
def sessions(): return {"data": repository.list_sessions()}


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
    coordinator.start(session); hub.publish("SESSION_STARTED", session)
    return session


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

import asyncio
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from . import repository
from .config import settings
from .database import connection, initialize_schema
from .scan_service import ScanCoordinator
from .scanner import validate_authorized_subnet
from .network import connected_ipv4_networks
from .schemas import AssetUpdate, FindingUpdate, ScanStart, VulnerabilityMatchUpdate
from .epss import coordinator as epss_coordinator


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
    yield


app = FastAPI(title="SecureOps Asset Discovery API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    with connection() as conn: conn.execute("SELECT 1")
    return {"status": "UP", "service": "asset-discovery"}


@app.get("/api/v1/devices")
def devices(status: str | None = None, device_type: str | None = Query(default=None, alias="type")):
    return {"data": repository.list_assets(status, device_type)}


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
):
    if confidence and confidence not in {"high", "medium", "low"}:
        raise HTTPException(400, "confidence must be high, medium, or low")
    if enrichment_status and enrichment_status not in {"not_enriched", "cpe_ready", "enriched"}:
        raise HTTPException(400, "invalid enrichment status")
    return {"data": repository.list_services(asset_id, confidence, enrichment_status, port, q)}


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
):
    return {"data": repository.list_findings(status, severity, confidence, check_id, q)}


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
):
    return {"data": repository.list_vulnerabilities(status, severity, confidence, q)}


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


@app.get("/api/v1/enrichment/epss/runs")
def epss_enrichment_runs(limit: int = Query(20, ge=1, le=100)):
    return {"data": repository.list_epss_enrichment_runs(limit)}


@app.post("/api/v1/enrichment/epss/refresh", status_code=202)
def refresh_epss_enrichment():
    job_id = epss_coordinator.schedule(None, "manual")
    return {"enrichment_run_id": job_id, "status": "queued"}


@app.patch("/api/v1/devices/{asset_id}")
def patch_device(asset_id: str, payload: AssetUpdate):
    result = repository.update_asset(asset_id, payload.model_dump())
    if not result: raise HTTPException(404, "Asset not found or no changes supplied")
    hub.publish("ASSET_UPDATED", result)
    return {"data": result}


@app.get("/api/v1/scan/activity")
def activity(limit: int = Query(8, ge=1, le=200)): return {"data": repository.list_activity(limit)}


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

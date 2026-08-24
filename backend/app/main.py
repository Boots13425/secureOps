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
from .schemas import AssetUpdate, ScanStart


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


@app.post("/api/v1/scan/sessions", status_code=202)
def start_session(payload: ScanStart):
    try: subnet = validate_authorized_subnet(payload.subnet or settings.default_subnet)
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
    session = repository.create_session(previous["subnet"], previous["duration_minutes"])
    coordinator.start(session); hub.publish("SESSION_STARTED", session)
    return session


@app.websocket("/ws/events")
async def events(socket: WebSocket):
    await hub.connect(socket)
    try:
        while True: await socket.receive_text()
    except WebSocketDisconnect: hub.clients.discard(socket)

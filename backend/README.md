# SecureOps Layer 1 — Asset Discovery

Python/FastAPI service for authorized local-network discovery. It uses a two-pass Nmap workflow: fast host discovery, followed by service/version fingerprinting only for live hosts. Nmap XML is parsed directly.

## Setup

1. Install PostgreSQL and Nmap. Ensure `nmap.exe` is on `PATH` or set `NMAP_PATH`.
2. Copy `.env.example` to `.env` at the project root or in this folder and set the PostgreSQL credentials.
3. Restrict `SCAN_ALLOWED_SUBNETS` to networks you are explicitly authorized to scan.
4. Install and start:

```powershell
python -m pip install -r requirements.txt
python run.py
```

The schema is additive and initialized at startup. The service listens on port 8007 by default.

## API

- `GET /health`
- `GET /api/v1/devices?status=unknown&type=router`
- `PATCH /api/v1/devices/{asset_id}` with `{"status":"approved"}`
- `POST /api/v1/scan/sessions` with optional `subnet` and `durationMinutes`
- `POST /api/v1/scan/sessions/{id}/stop`
- `POST /api/v1/scan/sessions/{id}/resume`
- `GET /api/v1/scan/sessions`
- `GET /api/v1/scan/activity`
- `GET /api/v1/scan/history`
- `WS /ws/events`

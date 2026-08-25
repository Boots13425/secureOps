# SecureOps Layer 1 — Asset Discovery

Python/FastAPI service for authorized local-network discovery. It uses a two-pass Nmap workflow: fast host discovery, followed by service/version fingerprinting only for live hosts. Nmap XML is parsed directly.

## Setup

1. Install PostgreSQL and Nmap. Ensure `nmap.exe` is on `PATH` or set `NMAP_PATH`.
2. Copy `.env.example` to `.env` at the project root or in this folder and set the PostgreSQL credentials.
3. Keep `SCAN_DEFAULT_SUBNET=auto` and `SCAN_ALLOWED_SUBNETS=auto` to select the
   currently connected default private network at scan time. Explicit CIDRs can
   still be configured when an organization requires a fixed allowlist.
4. Install and start:

```powershell
python -m pip install -r requirements.txt
python run.py
```

The schema is additive and initialized at startup. The service listens on port 8007 by default.

Discovery combines local ARP, ICMP, and common TCP probes. Fingerprinting is
bounded to the top ports configured by `NMAP_TOP_PORTS` (75 by default), while
OS detection is best-effort and stores its confidence separately. Running the
backend from an elevated terminal improves raw-packet and OS-detection results.
Slow hosts are fingerprinted in bounded parallel jobs (`NMAP_PARALLEL_HOSTS`)
so their timeouts do not accumulate across the inventory.

Automatic mode recalculates the active IPv4 network for every new scan, so
changing Wi-Fi or Ethernet networks does not require editing `.env`. Only a
directly connected private network can be selected automatically; arbitrary
remote or public targets remain rejected.

## Layer 3 exposure checks

The default exposure profile is an explicit allowlist: `smb-protocols`,
`ftp-anon`, `ssl-cert`, and `rdp-enum-encryption`. A check runs only when its
matching service is observed. Telnet, HTTP-without-HTTPS, and newly observed
administrative ports are evaluated from stored service/history evidence.
`ssl-enum-ciphers` is intentionally excluded from the customer default because
it is intrusive/noisy. Raw check output is stored for evidence and findings
never assert a CVE that was not established by a later intelligence layer.

## Layer 4 NVD enrichment

CPE-bearing services are enriched asynchronously through the NVD CVE API 2.0.
Responses are cached locally for `NVD_CACHE_HOURS`, so dashboard requests never
call NVD. Configure `NVD_API_KEY` for higher authorized throughput. Exact
versioned CPEs are presented as likely/high-confidence candidates; partial CPEs
are potential matches requiring version validation. Generic unversioned platform
CPEs are not queried automatically because they would produce misleadingly broad
results. CVSS is selected consistently in the order v4.0, v3.1, v3.0, then v2,
while the selected version and vector are retained alongside the score.

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

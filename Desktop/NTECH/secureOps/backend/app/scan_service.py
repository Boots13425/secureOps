import threading
from typing import Dict, Any, List, Optional

from . import repository
from .scanner import ScanStopped, discover_hosts, fingerprint_hosts, run_exposure_checks
from .nvd import coordinator as nvd_coordinator


def generate_telemetry_diff(
    session_id: str, 
    previous_assets: List[Dict[str, Any]], 
    current_hosts: list
) -> List[Dict[str, Any]]:
    """
    Layer 7: Compares current observed hosts with previous scan baseline
    and outputs structured change_events.
    """
    change_events = []

    # Map previous assets by MAC (fallback to IP if MAC not present)
    prev_map = {}
    for a in previous_assets:
        key = a.get("mac_address") or a.get("ip_address")
        if key:
            prev_map[key] = a

    # Map current scan hosts
    curr_map = {}
    for h in current_hosts:
        key = getattr(h, "mac_address", None) or getattr(h, "ip_address", None)
        if key:
            curr_map[key] = h

    # 1. NEW_ASSET detection
    for key, host in curr_map.items():
        if key not in prev_map:
            change_events.append({
                "scan_id": session_id,
                "asset_key": key,
                "event_type": "NEW_ASSET",
                "old_value": None,
                "new_value": getattr(host, "ip_address", key)
            })

    # 2. ASSET_MISSING detection
    for key, prev_asset in prev_map.items():
        if key not in curr_map:
            change_events.append({
                "scan_id": session_id,
                "asset_key": key,
                "event_type": "ASSET_MISSING",
                "old_value": prev_asset.get("hostname") or prev_asset.get("ip_address", key),
                "new_value": "Offline"
            })

    # 3. NEW_PORT & PORT_CLOSED on persisting devices
    for key in set(prev_map.keys()).intersection(curr_map.keys()):
        prev_ports = set(prev_map[key].get("open_ports") or [])
        
        curr_host = curr_map[key]
        curr_ports = set()
        if hasattr(curr_host, "services"):
            curr_ports = {s.port for s in curr_host.services if getattr(s, "port", None)}

        for port in (curr_ports - prev_ports):
            change_events.append({
                "scan_id": session_id,
                "asset_key": key,
                "event_type": "NEW_PORT",
                "old_value": None,
                "new_value": str(port)
            })

        for port in (prev_ports - curr_ports):
            change_events.append({
                "scan_id": session_id,
                "asset_key": key,
                "event_type": "PORT_CLOSED",
                "old_value": str(port),
                "new_value": None
            })

    return change_events


class ScanCoordinator:
    def __init__(self, publish):
        self.publish = publish
        self.stops: dict[str, threading.Event] = {}
        self.lock = threading.Lock()

    def start(self, session):
        session_id = session["id"]
        stop = threading.Event()
        with self.lock:
            self.stops[session_id] = stop
        thread = threading.Thread(
            target=self._run, 
            args=(session, stop), 
            daemon=True, 
            name=f"scan-{session_id}"
        )
        thread.start()

    def stop(self, session_id):
        with self.lock:
            event = self.stops.get(session_id)
        if event:
            event.set()
        session = repository.get_session(session_id)
        if not session:
            return None
        if session["status"] != "RUNNING":
            return session
        result = repository.finish_session(session_id, "STOPPED", session["devices_found"])
        self.publish("SESSION_STOPPED", result)
        return result

    def _run(self, session, stop):
        session_id = session["id"]
        try:
            # Retrieve baseline snapshot before persisting new scan data
            previous_assets = repository.get_previous_scan_assets(session["subnet"]) or []

            # Layer 1: Discover
            hosts = discover_hosts(session["subnet"], stop)
            if stop.is_set():
                return
            repository.store_scan_results(session_id, session["subnet"], hosts)
            self.publish("SESSION_TICK", {"id": session_id, "phase": "discovered", "devices_found": len(hosts)})

            # Layer 2: Fingerprint
            fingerprint_hosts(hosts, stop)
            if stop.is_set():
                return
            repository.store_scan_results(session_id, session["subnet"], hosts, record_activity=False)
            self.publish("SESSION_TICK", {"id": session_id, "phase": "fingerprinted", "devices_found": len(hosts)})

            # Layer 3: Safe Exposure Checks
            try:
                run_exposure_checks(hosts, stop)
                if stop.is_set():
                    return
                created = repository.store_exposure_results(session_id, hosts)
                self.publish("SESSION_TICK", {"id": session_id, "phase": "exposure_checked", "findings_created": created})
            except ScanStopped:
                raise
            except Exception as exc:
                repository.add_activity(
                    session_id, 
                    "EXPOSURE_CHECKS_FAILED", 
                    "Exposure checks could not complete", 
                    str(exc)[:1000]
                )

            # Layer 7: Baseline Delta Telemetry
            try:
                diff_events = generate_telemetry_diff(session_id, previous_assets, hosts)
                if diff_events:
                    repository.store_change_events(session_id, diff_events)
                    self.publish("SESSION_TICK", {"id": session_id, "phase": "telemetry_diffed", "changes": len(diff_events)})
            except Exception as exc:
                repository.add_activity(
                    session_id,
                    "TELEMETRY_DIFF_FAILED",
                    "Change telemetry calculation encountered an issue",
                    str(exc)[:1000]
                )

            # Complete Scan Session
            result = repository.finish_session(session_id, "COMPLETED", len(hosts))

            # Layers 4-6: Queue Vulnerability Enrichment
            service_ids = [
                service.service_id 
                for host in hosts 
                for service in host.services 
                if getattr(service, "service_id", None) and getattr(service, "cpe", None)
            ]
            enrichment_job = nvd_coordinator.schedule(session_id, "scan", service_ids)
            repository.add_activity(
                session_id, 
                "NVD_ENRICHMENT_QUEUED", 
                "NVD enrichment queued", 
                f"Job {enrichment_job} · {len(service_ids)} CPE-bearing service(s)"
            )
            self.publish("SESSION_COMPLETED", result)

        except ScanStopped:
            if repository.get_session(session_id)["status"] == "RUNNING":
                result = repository.finish_session(session_id, "STOPPED")
                self.publish("SESSION_STOPPED", result)
        except Exception as exc:
            result = repository.finish_session(session_id, "FAILED", error=str(exc)[:1000])
            self.publish("SESSION_FAILED", result)
        finally:
            with self.lock:
                self.stops.pop(session_id, None)
import threading

from . import repository
from .scanner import ScanStopped, discover_hosts, fingerprint_hosts, run_exposure_checks
from .nvd import coordinator as nvd_coordinator


class ScanCoordinator:
    def __init__(self, publish):
        self.publish = publish
        self.stops: dict[str, threading.Event] = {}
        self.lock = threading.Lock()

    def start(self, session):
        session_id = session["id"]
        stop = threading.Event()
        with self.lock: self.stops[session_id] = stop
        thread = threading.Thread(target=self._run, args=(session, stop), daemon=True, name=f"scan-{session_id}")
        thread.start()

    def stop(self, session_id):
        with self.lock: event = self.stops.get(session_id)
        if event: event.set()
        session = repository.get_session(session_id)
        if not session: return None
        if session["status"] != "RUNNING": return session
        result = repository.finish_session(session_id, "STOPPED", session["devices_found"])
        self.publish("SESSION_STOPPED", result)
        return result

    def _run(self, session, stop):
        session_id = session["id"]
        try:
            hosts = discover_hosts(session["subnet"], stop)
            if stop.is_set(): return
            repository.store_scan_results(session_id, session["subnet"], hosts)
            self.publish("SESSION_TICK", {"id": session_id, "phase": "discovered", "devices_found": len(hosts)})
            fingerprint_hosts(hosts, stop)
            if stop.is_set(): return
            repository.store_scan_results(session_id, session["subnet"], hosts, record_activity=False)
            self.publish("SESSION_TICK", {"id": session_id, "phase": "fingerprinted", "devices_found": len(hosts)})
            try:
                run_exposure_checks(hosts, stop)
                if stop.is_set(): return
                created = repository.store_exposure_results(session_id, hosts)
                self.publish("SESSION_TICK", {"id": session_id, "phase": "exposure_checked", "findings_created": created})
            except ScanStopped:
                raise
            except Exception as exc:
                repository.add_activity(session_id, "EXPOSURE_CHECKS_FAILED", "Exposure checks could not complete", str(exc)[:1000])
            result = repository.finish_session(session_id, "COMPLETED", len(hosts))
            service_ids = [service.service_id for host in hosts for service in host.services if service.service_id and service.cpe]
            enrichment_job = nvd_coordinator.schedule(session_id, "scan", service_ids)
            repository.add_activity(session_id, "NVD_ENRICHMENT_QUEUED", "NVD enrichment queued", f"Job {enrichment_job} · {len(service_ids)} CPE-bearing service(s)")
            self.publish("SESSION_COMPLETED", result)
        except ScanStopped:
            if repository.get_session(session_id)["status"] == "RUNNING":
                result = repository.finish_session(session_id, "STOPPED")
                self.publish("SESSION_STOPPED", result)
        except Exception as exc:
            result = repository.finish_session(session_id, "FAILED", error=str(exc)[:1000])
            self.publish("SESSION_FAILED", result)
        finally:
            with self.lock: self.stops.pop(session_id, None)
